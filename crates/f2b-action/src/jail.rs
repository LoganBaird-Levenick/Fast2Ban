//! In-process Jail coordinating filter, failmanager, actions, and backends.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use f2b_backend::Backend;
use f2b_backend::journal::FormattedEntry;
use f2b_db::Fail2BanDb;
use f2b_filter::{FailEntry, Filter};
use f2b_regex::TupleLine;
use f2b_types::{BanTicket, FailManager, FailTicket, IPAddr, IPAddrSet, SharedClock};

use crate::actions::Actions;
use crate::ban_extra::BanExtra;
use crate::exec::execute_cmd;
use crate::observer::Observer;

/// Name of the journal position in the database `logs` table.
const JOURNAL_DB_NAME: &str = "systemd-journal";
/// `MyTime.time2str`: `%Y-%m-%d %H:%M:%S` in the given local zone.
pub fn time2str(zone: &f2b_date::LocalZone, t: f64) -> String {
    let f = zone.local_fields(t);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        f.year, f.month, f.day, f.hour, f.minute, f.second
    )
}
/// An active jail instance managing the complete monitoring and ban lifecycle.
#[derive(Debug)]
pub struct Jail {
    pub name: String,
    pub filter: Filter,
    pub fail_manager: FailManager,
    pub actions: Actions,
    pub backend: Backend,
    pub ignore_ip: IPAddrSet,
    /// `ignoreip` entries as configured (`getIgnoreIP`), in insertion order.
    pub ignore_list: Vec<String>,
    pub ignore_self: bool,
    pub ignore_command: Option<String>,
    pub ignore_cache_spec: Option<String>,
    ignore_cache: std::sync::Mutex<Option<f2b_types::TtlCache<String, bool>>>,
    pub clock: SharedClock,
    pub ban_extra: BanExtra,
    pub database: Option<Arc<Fail2BanDb>>,
    /// `idle on|off`: an idle jail neither reads logs nor unbans.
    pub idle: bool,
    /// Set between `start` and `stop`.
    pub active: bool,
    /// Backend name the jail was added with (`auto`, `polling`, `systemd`, ...).
    pub backend_name: String,
    /// Local time zone for the times in the ban list.
    pub zone: f2b_date::LocalZone,
    log_encoding: String,
    reload_logs: Option<Vec<String>>,
    reload_actions: Option<Vec<String>>,
    /// Last position written to the database per log file.
    db_pos: std::collections::HashMap<String, u64>,
    /// Last journal time (epoch seconds) written to the database.
    db_journal_secs: Option<i64>,
}

impl Jail {
    pub fn new(name: &str, filter: Filter, backend: Backend, clock: SharedClock) -> Self {
        Self {
            name: name.to_owned(),
            filter,
            fail_manager: FailManager::new(),
            actions: Actions::new(name),
            backend,
            ignore_ip: IPAddrSet::new(),
            ignore_list: Vec::new(),
            ignore_self: true,
            ignore_command: None,
            ignore_cache_spec: None,
            ignore_cache: std::sync::Mutex::new(None),
            clock,
            ban_extra: BanExtra::new(),
            database: None,
            idle: false,
            active: false,
            backend_name: "auto".to_owned(),
            zone: f2b_date::LocalZone::system(),
            log_encoding: "auto".to_owned(),
            reload_logs: None,
            reload_actions: None,
            db_pos: std::collections::HashMap::new(),
            db_journal_secs: None,
        }
    }

    /// `addIgnoreIP`: an address, network or host name (resolved now).
    pub fn add_ignore_ip(&mut self, ip_str: &str) -> Result<(), f2b_types::ipaddr::IPAddrError> {
        match IPAddr::new(ip_str) {
            Ok(ip) => self.ignore_ip.add(ip),
            Err(e) => {
                let resolved = crate::selfips::resolve_host(ip_str);
                if resolved.is_empty() {
                    return Err(e);
                }
                for ip in resolved {
                    self.ignore_ip.add(ip);
                }
            }
        }
        if !self.ignore_list.iter().any(|s| s == ip_str) {
            self.ignore_list.push(ip_str.to_owned());
        }
        Ok(())
    }

    /// `delIgnoreIP`: drop an entry (and the addresses it expanded to).
    pub fn del_ignore_ip(&mut self, ip_str: &str) {
        self.ignore_list.retain(|s| s != ip_str);
        let mut set = IPAddrSet::new();
        for entry in &self.ignore_list {
            if let Ok(ip) = IPAddr::new(entry) {
                set.add(ip);
            } else {
                for ip in crate::selfips::resolve_host(entry) {
                    set.add(ip);
                }
            }
        }
        self.ignore_ip = set;
    }
    pub fn set_ignore_cache(&mut self, spec: Option<String>) {
        self.ignore_cache_spec = spec.clone();
        if let Ok(mut guard) = self.ignore_cache.lock() {
            if let Some(s) = spec {
                let parts: Vec<&str> = s.split_whitespace().collect();
                let max_count = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(100);
                let max_time = parts
                    .get(2)
                    .and_then(|p| f2b_expr::str2seconds(p).ok())
                    .map(|n| n.as_f64())
                    .unwrap_or(300.0);
                *guard = Some(f2b_types::TtlCache::new(
                    max_count,
                    max_time,
                    self.clock.clone(),
                ));
            } else {
                *guard = None;
            }
        }
    }

    /// `setLogEncoding` (`auto` follows the UTF-8 locale of the process).
    pub fn set_log_encoding(&mut self, encoding: &str) {
        encoding.clone_into(&mut self.log_encoding);
        self.backend.set_encoding(encoding);
    }

    pub fn log_encoding(&self) -> &str {
        &self.log_encoding
    }

    /// `setFindTime`: filter and failure manager use the same window.
    pub fn set_find_time(&mut self, seconds: f64) {
        self.filter.set_find_time(seconds);
        self.fail_manager.set_max_time(seconds);
    }

    /// `addLogPath`.
    pub fn add_log_path(&mut self, path: &str, tail: bool) -> std::io::Result<()> {
        // during a reload a known path keeps its container (and file position)
        if let Some(pending) = self.reload_logs.as_mut() {
            if let Some(pos) = pending.iter().position(|p| p == path) {
                pending.remove(pos);
                return Ok(());
            }
        }
        self.backend.add_log_path(path, tail)?;
        // resume behind the position stored for this file (unless it rotated)
        if let (Some(db), Some(containers)) = (&self.database, self.backend.containers_mut()) {
            if let Some(c) = containers.get_mut(Path::new(path)) {
                match db.add_log(&self.name, path, c.pos(), Some(c.hash())) {
                    Ok(Some(last)) if !tail => c.set_pos(last),
                    Ok(_) => {}
                    Err(e) => log::error!("[{}] Unable to read the log position: {e}", self.name),
                }
                self.db_pos.insert(path.to_owned(), c.pos());
            }
        }
        Ok(())
    }

    /// `delLogPath`: false when the path was not monitored.
    pub fn del_log_path(&mut self, path: &str) -> bool {
        self.backend.del_log_path(Path::new(path)).is_some()
    }

    pub fn log_paths(&self) -> Vec<String> {
        self.backend
            .log_paths()
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect()
    }

    pub fn set_ignore_self(&mut self, val: bool) {
        self.ignore_self = val;
    }

    pub fn set_ignore_command(&mut self, cmd: Option<String>) {
        self.ignore_command = cmd;
    }

    pub fn set_database(&mut self, db: Option<Arc<Fail2BanDb>>) {
        self.database = db;
    }

    pub fn set_ban_time_extra(&mut self, opt: &str, val: Option<&str>) -> Result<(), String> {
        self.ban_extra.set_opt(opt, val)
    }

    pub fn get_ban_time_extra(&self, opt: &str) -> Option<String> {
        self.ban_extra.get_opt(opt)
    }

    pub fn max_ban_time(&self) -> i64 {
        self.ban_extra
            .max_ban_time(self.actions.ban_manager.ban_time())
    }

    pub fn calc_ban_time(&self, ban_time: f64, ban_count: i64) -> Result<f2b_expr::Num, String> {
        Observer::calc_ban_time(&self.ban_extra, ban_time, ban_count)
    }

    pub fn failure_found(&mut self, ticket: &mut FailTicket, now: f64) {
        Observer::failure_found(
            &self.name,
            &self.ban_extra,
            self.database.as_deref(),
            &mut self.fail_manager,
            &mut self.actions,
            ticket,
            now,
        );
    }

    pub fn ban_found(&mut self, ticket: &mut BanTicket, base_ban_time: i64, now: f64) -> bool {
        Observer::ban_found(
            &self.name,
            &self.ban_extra,
            self.database.as_deref(),
            ticket,
            base_ban_time,
            now,
        )
    }

    pub fn incr_ban_time(&self, ticket: &mut BanTicket, base_ban_time: i64, now: f64) -> i64 {
        Observer::incr_ban_time(
            &self.name,
            &self.ban_extra,
            self.database.as_deref(),
            base_ban_time,
            ticket,
            now,
        )
    }

    pub fn restore_current_bans(
        &mut self,
        correct_ban_time: bool,
        now: f64,
    ) -> Result<usize, String> {
        let Some(db) = &self.database else {
            return Ok(0);
        };
        let cbt = if correct_ban_time {
            Some(self.max_ban_time())
        } else {
            None
        };
        let restored = db
            .get_current_bans(Some(&self.name), None, Some(now), cbt, None)
            .map_err(|e| e.to_string())?;

        let mut count = 0;
        for t in restored {
            let mut ban_ticket = BanTicket::from_fail_ticket(t);
            ban_ticket.ticket_mut().set_restored(true);
            match self.actions.ban(&mut ban_ticket, now) {
                Ok(true) => count += 1,
                Ok(false) => {}
                Err(e) => log::error!("[{}] Failed to restore ban: {e}", self.name),
            }
        }
        Ok(count)
    }

    /// Check if an IP address should be ignored according to `ignoreself`,
    /// `ignoreip` or `ignorecommand` (`Filter._inIgnoreIPList`).
    pub fn is_ignored(&self, ip: &IPAddr) -> bool {
        let ip_str = ip.ntoa();
        if let Ok(mut guard) = self.ignore_cache.lock() {
            if let Some(c) = guard.as_mut() {
                if let Some(&cached) = c.get(&ip_str.to_string()) {
                    return cached;
                }
            }
        }

        let ignored = self.is_ignored_uncached(ip);

        if let Ok(mut guard) = self.ignore_cache.lock() {
            if let Some(c) = guard.as_mut() {
                c.set(ip_str.to_string(), ignored);
            }
        }

        ignored
    }

    fn is_ignored_uncached(&self, ip: &IPAddr) -> bool {
        if self.ignore_self && crate::selfips::self_ips().contains(ip) {
            log::debug!("[{}] Ignore {} by ignoreself rule", self.name, ip.ntoa());
            return true;
        }
        if self.ignore_ip.contains(ip) {
            log::debug!("[{}] Ignore {} by ip", self.name, ip.ntoa());
            return true;
        }

        // Check external ignore command if configured
        if let Some(cmd_template) = &self.ignore_command {
            let cmd = cmd_template.replace("<ip>", &ip.ntoa());
            if let Ok(res) = execute_cmd(&cmd, Duration::from_secs(5), &[]) {
                if res.success {
                    log::debug!("[{}] Ignore {} by command", self.name, ip.ntoa());
                    return true;
                }
            }
        }

        false
    }

    pub fn start(&mut self) -> Result<(), String> {
        log::info!("[{}] Jail started", self.name);
        if self.backend.is_journal() {
            self.start_journal()?;
        }
        self.active = true;
        self.actions.start()
    }

    /// Read the journal from `max(stored position, now - findtime)`.
    fn start_journal(&mut self) -> Result<(), String> {
        let now = self.clock.time();
        let stored = self
            .database
            .as_ref()
            .and_then(|db| {
                db.get_journal_pos(&self.name, JOURNAL_DB_NAME)
                    .ok()
                    .flatten()
            })
            .unwrap_or(0);
        let since = (stored as f64).max(now - self.filter.find_time().trunc());
        let name = self.name.clone();
        let Some(journal) = self.backend.journal_mut() else {
            return Ok(());
        };
        if journal.matches().is_empty() {
            log::info!(
                "[{name}] Jail started without 'journalmatch' set. Jail regexs will be checked against all journal entries, which is not advised for performance reasons."
            );
        }
        journal
            .start(since)
            .map_err(|e| format!("[{name}] Unable to start the journal reader: {e}"))
    }

    pub fn stop(&mut self) -> Result<(), String> {
        log::info!("[{}] Jail stopped", self.name);
        self.active = false;
        if let Some(journal) = self.backend.journal_mut() {
            journal.stop();
        }
        self.actions.stop()
    }

    /// `addJournalMatch`; matches only exist for the systemd backend, other
    /// backends ignore them like upstream's non-journal filters do.
    pub fn add_journal_match(&mut self, m: &[String]) -> Result<(), String> {
        match self.backend.journal_mut() {
            Some(j) => j.add_match(m).map_err(|e| e.to_string()),
            None => Ok(()),
        }
    }

    /// `delJournalMatch`.
    pub fn del_journal_match(&mut self, m: &[String]) -> Result<(), String> {
        match self.backend.journal_mut() {
            Some(j) => j
                .del_match(if m.is_empty() { None } else { Some(m) })
                .map_err(|e| e.to_string()),
            None => Ok(()),
        }
    }

    /// `getJournalMatch`: the groups of matches (empty for file backends).
    pub fn journal_matches(&self) -> Vec<Vec<String>> {
        self.backend
            .journal()
            .map(|j| j.matches().get().to_vec())
            .unwrap_or_default()
    }

    /// Process a single log line directly, updating failures and executing bans if threshold reached.
    pub fn process_line(&mut self, line: &str, now: f64) -> Result<usize, String> {
        let entries = self.filter.process_line(line).map_err(|e| e.to_string())?;
        Ok(self.handle_failures(entries, now))
    }

    /// A journal entry (date and time are known, no date detection).
    fn process_journal_entry(&mut self, e: FormattedEntry, now: f64) -> usize {
        let line = TupleLine::new(e.pre, e.date, e.post);
        match self.filter.process_line_with_date(line, e.time) {
            Ok(entries) => self.handle_failures(entries, now),
            Err(err) => {
                log::error!("[{}] Failed to process journal entry: {err}", self.name);
                0
            }
        }
    }

    /// `Filter.processLineAndAdd` after the failures were found: ignore
    /// rules, failure counting, observer and ban. Returns the new bans.
    fn handle_failures(&mut self, entries: Vec<FailEntry>, now: f64) -> usize {
        let mut bans = 0;

        for entry in entries {
            let Some(fid) = entry.fid else {
                continue;
            };

            if self.is_ignored(&fid) {
                log::debug!("[{}] Ignored failure from {}", self.name, fid.ntoa());
                continue;
            }

            let found_time = entry.date.unwrap_or(now);
            log::info!(
                target: "f2b_filter::filter",
                "[{}] Found {} - {}",
                self.name,
                fid.ntoa(),
                time2str(&self.zone, found_time)
            );
            let mut ticket = FailTicket::new(fid.clone(), found_time);
            let mut matches = Vec::new();
            if let Some(f2b_filter::FailVal::Lines(l)) = entry.fail.get("matches") {
                for t in l {
                    matches.push(format!("{}{}{}", t.pre, t.date, t.post));
                }
            }
            ticket.ticket_mut().set_matches(matches);

            let attempts = self.fail_manager.add_failure(ticket.clone(), 1);
            Observer::failure_found(
                &self.name,
                &self.ban_extra,
                self.database.as_deref(),
                &mut self.fail_manager,
                &mut self.actions,
                &mut ticket,
                now,
            );

            if attempts >= self.fail_manager.max_retry() && self.perform_ban(&fid, now) {
                bans += 1;
            }
        }

        bans
    }

    /// One scheduling round: read new log lines (or journal entries), process
    /// them, unban expired tickets and save the read position.
    pub fn step(&mut self, now: f64) -> Result<usize, String> {
        if self.idle || !self.active {
            return Ok(0);
        }
        let mut bans = 0;
        if self.backend.is_journal() {
            let mut entries = Vec::new();
            if let Some(j) = self.backend.journal_mut() {
                j.poll(|e| entries.push(e));
            }
            for e in entries {
                bans += self.process_journal_entry(e, now);
            }
            self.save_journal_pos();
        } else {
            let mut lines = Vec::new();
            if let Err(e) = self.backend.poll_once(|_path: &Path, line: &str| {
                lines.push(line.to_owned());
            }) {
                log::error!("[{}] Error reading logs: {e}", self.name);
            }
            for line in lines {
                match self.process_line(&line, now) {
                    Ok(n) => bans += n,
                    Err(e) => log::error!("[{}] Failed to process line: {e}", self.name),
                }
            }
            self.save_log_positions();
        }

        if let Err(e) = self.actions.check_unban(now, None) {
            log::error!("[{}] Failed to unban: {e}", self.name);
        }
        self.fail_manager.cleanup(now);

        Ok(bans)
    }

    /// `_updateDBPending` for log files: store positions that changed.
    fn save_log_positions(&mut self) {
        let (Some(db), Some(containers)) = (&self.database, self.backend.containers_mut()) else {
            return;
        };
        for (path, c) in containers.iter() {
            let key = path.to_string_lossy().into_owned();
            if self.db_pos.get(&key) == Some(&c.pos()) {
                continue;
            }
            match db.update_log(&self.name, &key, c.pos(), Some(c.hash())) {
                Ok(()) => {
                    self.db_pos.insert(key, c.pos());
                }
                Err(e) => log::error!("[{}] Unable to store the log position: {e}", self.name),
            }
        }
    }

    /// `_updateDBPending` for the journal: store time and ISO text of the last entry.
    fn save_journal_pos(&mut self) {
        let Some(db) = &self.database else {
            return;
        };
        let Some((time, iso)) = self.backend.journal().and_then(|j| j.last_entry()) else {
            return;
        };
        let secs = time.floor() as i64;
        if self.db_journal_secs == Some(secs) {
            return;
        }
        match db.update_log(
            &self.name,
            JOURNAL_DB_NAME,
            u64::try_from(secs).unwrap_or(0),
            Some(iso),
        ) {
            Ok(()) => self.db_journal_secs = Some(secs),
            Err(e) => log::error!("[{}] Unable to store the journal position: {e}", self.name),
        }
    }

    /// `performBan`: move the failure of `fid` to the ban manager and run the
    /// actions. Errors are logged (upstream logs and carries on); returns
    /// whether a new ban was added.
    fn perform_ban(&mut self, fid: &IPAddr, now: f64) -> bool {
        let Ok(to_ban) = self.fail_manager.to_ban(Some(fid)) else {
            return false;
        };
        let mut ban_ticket = BanTicket::from_fail_ticket(to_ban);
        match Observer::ban(
            &self.name,
            &self.ban_extra,
            self.database.as_deref(),
            &mut self.actions,
            &mut ban_ticket,
            now,
        ) {
            Ok(added) => added,
            Err(e) => {
                log::error!(
                    "[{}] Failed to execute ban of {}: {e}",
                    self.name,
                    fid.ntoa()
                );
                false
            }
        }
    }

    /// `Filter.addAttempt` (`set <jail> attempt <ip> [<match>...]`): 0 when the
    /// address is ignored, else 1.
    pub fn add_attempt(&mut self, ip: &str, matches: Vec<String>, now: f64) -> Result<i64, String> {
        let ip = IPAddr::new(ip).map_err(|e| e.to_string())?;
        let mut ticket = FailTicket::new(ip.clone(), now);
        let count = i64::try_from(matches.len()).unwrap_or(i64::MAX).max(1);
        ticket.ticket_mut().set_matches(matches);
        if self.is_ignored(&ip) {
            return Ok(0);
        }
        log::info!(
            target: "f2b_filter::filter",
            "[{}] Attempt {} - {}",
            self.name,
            ip.ntoa(),
            time2str(&self.zone, now)
        );
        let attempts = self.fail_manager.add_failure(ticket.clone(), count);
        if attempts >= self.fail_manager.max_retry() {
            self.perform_ban(&ip, now);
        }
        Observer::failure_found(
            &self.name,
            &self.ban_extra,
            self.database.as_deref(),
            &mut self.fail_manager,
            &mut self.actions,
            &mut ticket,
            now,
        );
        Ok(1)
    }

    /// `Actions.addBannedIP` (`set <jail> banip <ip>...`): ban without failures.
    pub fn ban_ips(&mut self, ips: &[&str], now: f64) -> Result<usize, String> {
        let mut count = 0;
        for ip in ips {
            let ip = IPAddr::new(ip).map_err(|e| e.to_string())?;
            let mut ticket = BanTicket::new(ip, now);
            if Observer::ban(
                &self.name,
                &self.ban_extra,
                self.database.as_deref(),
                &mut self.actions,
                &mut ticket,
                now,
            )? {
                count += 1;
            }
        }
        Ok(count)
    }

    /// `Actions.removeBannedIP`: unban single addresses, subnets or (with
    /// `None`) everything. Bans are removed from the database also.
    ///
    /// # Errors
    /// `not banned` for addresses that are not banned unless `if_exists`.
    pub fn unban_ips(&mut self, ips: Option<&[&str]>, if_exists: bool) -> Result<usize, String> {
        let Some(ips) = ips else {
            if let Some(db) = &self.database {
                let _ = db.del_ban(&self.name, &[]);
            }
            return self.actions.flush_ban(false);
        };
        let mut count = 0;
        let mut missed: Vec<String> = Vec::new();
        for text in ips {
            let parsed = IPAddr::new(text);
            if let Some(db) = &self.database {
                let _ = db.del_ban(&self.name, &[text]);
            }
            let ticket = parsed
                .as_ref()
                .ok()
                .and_then(|ip| self.actions.ban_manager.get_ticket_by_id(ip));
            if let Some(ticket) = ticket {
                self.actions.unban(&ticket)?;
                count += 1;
                continue;
            }
            // a subnet covers every banned address inside of it
            let covered: Vec<IPAddr> = match &parsed {
                Ok(net) => self
                    .actions
                    .ban_manager
                    .get_ban_list()
                    .into_iter()
                    .filter(|ip| net.contains(ip))
                    .collect(),
                Err(_) => Vec::new(),
            };
            if covered.is_empty() {
                if !if_exists {
                    missed.push((*text).to_owned());
                }
                continue;
            }
            for ip in covered {
                if let Some(ticket) = self.actions.ban_manager.get_ticket_by_id(&ip) {
                    self.actions.unban(&ticket)?;
                    count += 1;
                }
            }
        }
        if missed.is_empty() {
            Ok(count)
        } else {
            Err(format!("not banned: {missed:?}"))
        }
    }

    /// `Actions.getBanList`: addresses ordered by end of ban, optionally with
    /// `ip \t<time> + <bantime> = <end>` details.
    pub fn ban_list(&self, with_time: bool) -> Vec<String> {
        let zone = &self.zone;
        let default_bt = self.actions.ban_manager.ban_time();
        let mut list: Vec<(&BanTicket, f64)> = self
            .actions
            .ban_manager
            .tickets()
            .map(|t| (t, t.ticket().get_end_of_ban_time(default_bt)))
            .collect();
        list.sort_by(|a, b| a.1.total_cmp(&b.1));
        list.into_iter()
            .map(|(t, eob)| {
                if with_time {
                    format!(
                        "{} \t{} + {} = {}",
                        t.id().ntoa(),
                        time2str(zone, t.time()),
                        t.ticket().ban_time(default_bt),
                        time2str(zone, eob)
                    )
                } else {
                    t.id().ntoa().into_owned()
                }
            })
            .collect()
    }

    /// `Actions.getBanned` for the given addresses: all banned addresses when
    /// `ids` is empty, a single flag for one id, else a flag per id.
    pub fn is_banned(&self, ip: &str) -> bool {
        IPAddr::new(ip).is_ok_and(|ip| self.actions.ban_manager.in_ban_list(&ip))
    }

    /// `Jail.status(flavor)` pieces: `(currently failed, total failed)`.
    pub fn filter_counts(&self) -> (usize, usize) {
        (self.fail_manager.size(), self.fail_manager.fail_total())
    }

    /// `(currently banned, total banned)`.
    pub fn action_counts(&self) -> (usize, usize) {
        (
            self.actions.ban_manager.size(),
            self.actions.ban_manager.ban_total(),
        )
    }

    /// `Jail.status` begin of reload (`filter.reload(begin=True)` +
    /// `actions.reload(begin=True)`): parameters are re-sent by the stream.
    pub fn reload_begin(&mut self) {
        self.idle = true;
        self.filter.clear_fail_regex();
        self.filter.clear_ignore_regex();
        let _ = self.filter.set_pref_regex(None);
        self.ignore_list.clear();
        self.ignore_ip = IPAddrSet::new();
        self.reload_logs = Some(self.log_paths());
        self.reload_actions = Some(Vec::new());
    }

    /// End of reload: drop log files and actions that the new configuration
    /// does not mention, run `actionreload` of the kept actions.
    pub fn reload_end(&mut self) {
        for path in self.reload_logs.take().unwrap_or_default() {
            self.del_log_path(&path);
        }
        let Some(kept) = self.reload_actions.take() else {
            return;
        };
        let obsolete: Vec<String> = self
            .actions
            .names()
            .into_iter()
            .filter(|n| !kept.contains(n))
            .collect();
        if !obsolete.is_empty() {
            if let Err(e) = self.actions.remove_actions(&obsolete) {
                log::error!("[{}] Failed to remove actions {obsolete:?}: {e}", self.name);
            }
        }
        for name in &kept {
            if let Some(action) = self.actions.get_action_mut(name) {
                if let Err(e) = action.reload() {
                    log::error!("[{}] Failed to reload action {name}: {e}", self.name);
                }
            }
        }
    }

    /// `Actions.addAction` semantics: during a reload an action that already
    /// exists keeps its state and is only marked as still configured.
    pub fn add_action(&mut self, name: &str) {
        if let Some(kept) = self.reload_actions.as_mut() {
            if !kept.iter().any(|n| n == name) {
                kept.push(name.to_owned());
            }
        }
        if self.actions.get_action(name).is_none() {
            self.actions
                .add_action(crate::CommandAction::new(&self.name, name));
        }
    }
}
