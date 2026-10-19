//! SQLite implementation of `Fail2BanDb` (`fail2ban/server/database.py`).

use rusqlite::{Connection, params};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use crate::schema::{apply_pragmas, migrate_db};
use f2b_types::{BanTicket, FailTicket, IPAddr, Ticket};

fn get_string_or_blob(row: &rusqlite::Row<'_>, idx: usize) -> rusqlite::Result<Option<String>> {
    match row.get_ref(idx)? {
        rusqlite::types::ValueRef::Text(s) => Ok(Some(String::from_utf8_lossy(s).into_owned())),
        rusqlite::types::ValueRef::Blob(b) => Ok(Some(String::from_utf8_lossy(b).into_owned())),
        _ => Ok(None),
    }
}

#[derive(Debug)]
pub struct Fail2BanDb {
    conn: Mutex<Connection>,
    filename: PathBuf,
    purge_age: AtomicI64,
    pub outdated_factor: i64,
    max_matches: AtomicUsize,
}

impl Fail2BanDb {
    /// Connect to or create a database, applying PRAGMAs and running migrations.
    pub fn open(filename: impl AsRef<Path>, purge_age: i64) -> rusqlite::Result<Self> {
        let path = filename.as_ref().to_path_buf();
        let mut conn = Connection::open(&path)?;
        apply_pragmas(&conn)?;
        migrate_db(&mut conn)?;

        Ok(Self {
            conn: Mutex::new(conn),
            filename: path,
            purge_age: AtomicI64::new(purge_age),
            outdated_factor: 3,
            max_matches: AtomicUsize::new(10),
        })
    }

    pub fn open_in_memory() -> rusqlite::Result<Self> {
        let mut conn = Connection::open_in_memory()?;
        apply_pragmas(&conn)?;
        migrate_db(&mut conn)?;

        Ok(Self {
            conn: Mutex::new(conn),
            filename: PathBuf::from(":memory:"),
            purge_age: AtomicI64::new(86400),
            outdated_factor: 3,
            max_matches: AtomicUsize::new(10),
        })
    }

    pub fn filename(&self) -> &Path {
        &self.filename
    }

    /// `purgeage` in seconds.
    pub fn purge_age(&self) -> i64 {
        self.purge_age.load(Ordering::Relaxed)
    }

    pub fn set_purge_age(&self, seconds: i64) {
        self.purge_age.store(seconds, Ordering::Relaxed);
    }

    /// `maxMatches`: matches stored per ban.
    pub fn max_matches(&self) -> usize {
        self.max_matches.load(Ordering::Relaxed)
    }

    pub fn set_max_matches(&self, value: usize) {
        self.max_matches.store(value, Ordering::Relaxed);
    }

    pub fn add_jail(&self, name: &str) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO jails(name, enabled) VALUES(?1, 1)",
            [name],
        )?;
        conn.execute(
            "UPDATE jails SET enabled = 1 WHERE name = ?1 AND enabled != 1",
            [name],
        )?;
        Ok(())
    }

    pub fn del_jail(&self, name: &str) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("UPDATE jails SET enabled=0 WHERE name=?1", [name])?;
        Ok(())
    }

    pub fn del_all_jails(&self) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("UPDATE jails SET enabled=0", [])?;
        Ok(())
    }

    pub fn get_jail_names(&self, enabled: Option<bool>) -> rusqlite::Result<HashSet<String>> {
        let conn = self.conn.lock().unwrap();
        let mut set = HashSet::new();
        match enabled {
            None => {
                let mut stmt = conn.prepare("SELECT name FROM jails")?;
                let mut rows = stmt.query([])?;
                while let Some(row) = rows.next()? {
                    set.insert(row.get(0)?);
                }
            }
            Some(en) => {
                let mut stmt = conn.prepare("SELECT name FROM jails WHERE enabled = ?1")?;
                let mut rows = stmt.query([if en { 1 } else { 0 }])?;
                while let Some(row) = rows.next()? {
                    set.insert(row.get(0)?);
                }
            }
        }
        Ok(set)
    }

    pub fn add_log(
        &self,
        jail: &str,
        path: &str,
        pos: u64,
        md5: Option<&str>,
    ) -> rusqlite::Result<Option<u64>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT firstlinemd5, lastfilepos FROM logs WHERE jail=?1 AND path=?2")?;
        let mut rows = stmt.query(params![jail, path])?;

        let first_line_md5: Option<String>;
        let mut last_line_pos: Option<u64> = None;

        if let Some(row) = rows.next()? {
            first_line_md5 = row.get(0)?;
            let raw_pos: Option<i64> = row.get(1)?;
            last_line_pos = raw_pos.map(|p| p.max(0) as u64);
        } else {
            first_line_md5 = None;
        }

        if first_line_md5.is_none() && (pos > 0 || md5.is_some()) {
            conn.execute(
                "INSERT OR REPLACE INTO logs(jail, path, firstlinemd5, lastfilepos) VALUES(?1, ?2, ?3, ?4)",
                params![jail, path, md5, pos as i64],
            )?;
        }

        if md5.is_some() && md5 != first_line_md5.as_deref() {
            last_line_pos = None;
        }

        Ok(last_line_pos)
    }

    pub fn update_log(
        &self,
        jail: &str,
        path: &str,
        pos: u64,
        md5: Option<&str>,
    ) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        let count = conn.execute(
            "UPDATE logs SET firstlinemd5=?1, lastfilepos=?2 WHERE jail=?3 AND path=?4",
            params![md5, pos as i64, jail, path],
        )?;
        if count == 0 {
            conn.execute(
                "INSERT OR REPLACE INTO logs(jail, path, firstlinemd5, lastfilepos) VALUES(?1, ?2, ?3, ?4)",
                params![jail, path, md5, pos as i64],
            )?;
        }
        Ok(())
    }

    /// `getJournalPos`: the stored journal position (epoch seconds) of `jail`.
    pub fn get_journal_pos(&self, jail: &str, name: &str) -> rusqlite::Result<Option<i64>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT lastfilepos FROM logs WHERE jail=?1 AND path=?2")?;
        let mut rows = stmt.query(params![jail, name])?;
        match rows.next()? {
            Some(row) => row.get(0),
            None => Ok(None),
        }
    }

    pub fn get_log_paths(&self, jail: Option<&str>) -> rusqlite::Result<HashSet<String>> {
        let conn = self.conn.lock().unwrap();
        let mut set = HashSet::new();
        if let Some(j) = jail {
            let mut stmt = conn.prepare("SELECT path FROM logs WHERE jail=?1")?;
            let mut rows = stmt.query([j])?;
            while let Some(row) = rows.next()? {
                set.insert(row.get(0)?);
            }
        } else {
            let mut stmt = conn.prepare("SELECT path FROM logs")?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                set.insert(row.get(0)?);
            }
        }
        Ok(set)
    }

    pub fn add_ban(&self, jail: &str, ticket: &BanTicket, default_bt: i64) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        let ip_str = ticket.id().ntoa().to_string();
        let time_of_ban = ticket.time().round() as i64;
        let ban_time = ticket.ticket().ban_time(default_bt);
        let ban_count = ticket.ticket().ban_count();

        let mut data_map = serde_json::Map::new();
        let matches = ticket.ticket().matches();
        let max_matches = self.max_matches();
        if max_matches > 0 && !matches.is_empty() {
            let start = matches.len().saturating_sub(max_matches);
            data_map.insert("matches".into(), serde_json::json!(&matches[start..]));
        }
        data_map.insert(
            "failures".into(),
            serde_json::json!(ticket.ticket().failures()),
        );
        let data_json = serde_json::Value::Object(data_map).to_string();

        conn.execute(
            "INSERT INTO bans(jail, ip, timeofban, bantime, bancount, data) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            params![jail, ip_str, time_of_ban, ban_time, ban_count, data_json],
        )?;

        conn.execute(
            "INSERT OR REPLACE INTO bips(ip, jail, timeofban, bantime, bancount, data) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            params![ip_str, jail, time_of_ban, ban_time, ban_count, data_json],
        )?;

        Ok(())
    }

    pub fn del_ban(&self, jail: &str, ips: &[&str]) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        if ips.is_empty() {
            conn.execute("DELETE FROM bips WHERE jail = ?1", [jail])?;
            conn.execute("DELETE FROM bans WHERE jail = ?1", [jail])?;
        } else {
            for ip in ips {
                conn.execute(
                    "DELETE FROM bips WHERE jail = ?1 AND ip = ?2",
                    params![jail, ip],
                )?;
                conn.execute(
                    "DELETE FROM bans WHERE jail = ?1 AND ip = ?2",
                    params![jail, ip],
                )?;
            }
        }
        Ok(())
    }

    /// Read active bans to restore them on startup (`getCurrentBans`).
    pub fn get_current_bans(
        &self,
        jail: Option<&str>,
        ip: Option<&str>,
        from_time: Option<f64>,
        correct_ban_time: Option<i64>,
        max_matches: Option<usize>,
    ) -> rusqlite::Result<Vec<FailTicket>> {
        let conn = self.conn.lock().unwrap();
        let from_t = from_time.unwrap_or(0.0);

        let mut query =
            "SELECT ip, timeofban, bantime, bancount, data FROM bips WHERE 1".to_owned();
        let mut params_vec: Vec<rusqlite::types::Value> = Vec::new();

        if let Some(j) = jail {
            query.push_str(" AND jail = ?");
            params_vec.push(j.to_owned().into());
        }
        if let Some(i) = ip {
            query.push_str(" AND ip = ?");
            params_vec.push(i.to_owned().into());
        }

        let mut stmt = conn.prepare(&query)?;
        let mut rows = stmt.query(rusqlite::params_from_iter(params_vec))?;
        let mut tickets = Vec::new();

        while let Some(row) = rows.next()? {
            let ban_ip: String = row.get(0)?;
            let time_of_ban: f64 = row.get(1)?;
            let mut ban_time: i64 = row.get(2)?;
            let ban_count: i64 = row.get(3)?;
            let data_str = get_string_or_blob(row, 4)?;

            if ban_time == -2 {
                ban_time = correct_ban_time.unwrap_or(600);
            } else if let Some(cbt) = correct_ban_time {
                if cbt >= 0 && (ban_time == -1 || ban_time > cbt) {
                    ban_time = cbt;
                }
            }

            if ban_time != -1 && (time_of_ban + ban_time as f64) <= from_t {
                continue;
            }

            let Ok(ip_obj) = IPAddr::new(&ban_ip) else {
                continue;
            };

            let mut ticket = Ticket::new(ip_obj, time_of_ban);
            ticket.set_ban_time(ban_time);
            ticket.set_ban_count(ban_count, true);
            ticket.set_restored(true);

            if let Some(s) = data_str {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&s) {
                    if let Some(m) = val.get("matches").and_then(|m| m.as_array()) {
                        let matches_limit = max_matches.unwrap_or_else(|| self.max_matches());
                        let mut m_vec: Vec<String> = m
                            .iter()
                            .filter_map(|x| x.as_str().map(str::to_owned))
                            .collect();
                        if matches_limit > 0 && m_vec.len() > matches_limit {
                            let start = m_vec.len() - matches_limit;
                            m_vec = m_vec[start..].to_vec();
                        }
                        ticket.set_matches(m_vec);
                    }
                    if let Some(failures) = val.get("failures").and_then(|f| f.as_i64()) {
                        ticket.set_failures(failures);
                    }
                }
            }

            tickets.push(FailTicket::from_ticket(ticket));
        }

        Ok(tickets)
    }

    /// Read ban info from `bips` table (`getBan`).
    /// Returns `(bancount, timeofban, bantime)` if found.
    pub fn get_ban(
        &self,
        ip: &str,
        jail: Option<&str>,
        overall_jails: bool,
        for_ban_time: Option<f64>,
        from_time: Option<f64>,
        now: f64,
    ) -> rusqlite::Result<Option<(i64, f64, i64)>> {
        let conn = self.conn.lock().unwrap();
        let mut query = if overall_jails {
            "SELECT sum(bancount), max(timeofban), sum(bantime) FROM bips WHERE ip = ?".to_owned()
        } else {
            "SELECT bancount, timeofban, bantime FROM bips WHERE ip = ?".to_owned()
        };
        let mut params_vec: Vec<rusqlite::types::Value> = vec![ip.to_owned().into()];

        if !overall_jails {
            if let Some(j) = jail {
                query.push_str(" AND jail = ?");
                params_vec.push(j.to_owned().into());
            }
        }

        if let Some(fbt) = for_ban_time {
            query.push_str(" AND timeofban > ?");
            params_vec.push(((now - fbt) as i64).into());
        }

        if let Some(ft) = from_time {
            query.push_str(" AND timeofban > ?");
            params_vec.push((ft as i64).into());
        }

        if overall_jails || jail.is_none() {
            query.push_str(" GROUP BY ip ORDER BY timeofban DESC LIMIT 1");
        } else {
            query.push_str(" ORDER BY timeofban DESC LIMIT 1");
        }

        let mut stmt = conn.prepare(&query)?;
        let mut rows = stmt.query(rusqlite::params_from_iter(params_vec))?;

        if let Some(row) = rows.next()? {
            let bancount: Option<i64> = row.get(0)?;
            let timeofban: Option<f64> = row.get(1)?;
            let bantime: Option<i64> = row.get(2)?;
            if let (Some(bc), Some(tob), Some(bt)) = (bancount, timeofban, bantime) {
                return Ok(Some((bc, tob, bt)));
            }
        }
        Ok(None)
    }

    /// Read historical bans from `bans` table (`getBans`).
    pub fn get_bans(
        &self,
        jail: Option<&str>,
        ip: Option<&str>,
        bantime: Option<i64>,
        now: f64,
    ) -> rusqlite::Result<Vec<FailTicket>> {
        let conn = self.conn.lock().unwrap();
        let mut query = "SELECT ip, timeofban, data FROM bans WHERE 1".to_owned();
        let mut params_vec: Vec<rusqlite::types::Value> = Vec::new();

        if let Some(j) = jail {
            query.push_str(" AND jail = ?");
            params_vec.push(j.to_owned().into());
        }
        if let Some(bt) = bantime {
            if bt >= 0 {
                query.push_str(" AND timeofban > ?");
                params_vec.push(((now - bt as f64) as i64).into());
            }
        }
        if let Some(i) = ip {
            query.push_str(" AND ip = ?");
            params_vec.push(i.to_owned().into());
        }
        query.push_str(" ORDER BY ip, timeofban desc");

        let mut stmt = conn.prepare(&query)?;
        let mut rows = stmt.query(rusqlite::params_from_iter(params_vec))?;
        let mut tickets = Vec::new();

        while let Some(row) = rows.next()? {
            let ban_ip: String = row.get(0)?;
            let time_of_ban: f64 = row.get(1)?;
            let data_str = get_string_or_blob(row, 2)?;

            let Ok(ip_obj) = IPAddr::new(&ban_ip) else {
                continue;
            };
            let mut ticket = Ticket::new(ip_obj, time_of_ban);

            if let Some(s) = data_str {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&s) {
                    if let Some(m) = val.get("matches").and_then(|m| m.as_array()) {
                        let m_vec: Vec<String> = m
                            .iter()
                            .filter_map(|x| x.as_str().map(str::to_owned))
                            .collect();
                        ticket.set_matches(m_vec);
                    }
                    if let Some(failures) = val.get("failures").and_then(|f| f.as_i64()) {
                        ticket.set_failures(failures);
                    }
                }
            }
            tickets.push(FailTicket::from_ticket(ticket));
        }

        Ok(tickets)
    }

    /// Purges expired bips and unused disabled jails.
    pub fn purge(&self, now: f64) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        let cutoff = (now as i64) - self.purge_age();

        // Purge bips
        conn.execute(
            "DELETE FROM bips WHERE timeofban < ?1 AND bantime != -1 AND (timeofban + (bantime * ?2)) < ?1",
            params![cutoff, self.outdated_factor],
        )?;

        // Clean jails
        conn.execute(
            "DELETE FROM jails WHERE enabled = 0 \
             AND NOT EXISTS(SELECT 1 FROM bans WHERE jail = jails.name) \
             AND NOT EXISTS(SELECT 1 FROM bips WHERE jail = jails.name)",
            [],
        )?;

        Ok(())
    }
}
