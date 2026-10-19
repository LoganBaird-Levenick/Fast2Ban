//! Server state managing active jails, logging, and database.

use indexmap::IndexMap;
use std::sync::Arc;

use f2b_action::Jail;
use f2b_backend::Backend;
use f2b_date::LocalZone;
use f2b_db::Fail2BanDb;
use f2b_filter::Filter;
use f2b_proto::Value;
use f2b_types::{DnsUtils, IPAddr, SharedClock, system_clock};

#[derive(Debug)]
pub struct Server {
    pub jails: IndexMap<String, Jail>,
    pub db: Option<Arc<Fail2BanDb>>,
    pub log_level: String,
    pub log_target: String,
    pub syslog_socket: String,
    pub allow_ipv6: String,
    pub clock: SharedClock,
    pub running: bool,
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

impl Server {
    pub fn new() -> Self {
        Self {
            jails: IndexMap::new(),
            db: None,
            log_level: "INFO".to_owned(),
            log_target: "STDERR".to_owned(),
            syslog_socket: "auto".to_owned(),
            allow_ipv6: "auto".to_owned(),
            clock: system_clock(),
            running: true,
        }
    }

    pub fn add_jail(&mut self, name: &str, backend_type: &str) -> Result<(), String> {
        if self.jails.contains_key(name) {
            return Ok(());
        }

        let dns = Arc::new(DnsUtils::system(self.clock.clone()));
        let zone = LocalZone::system();
        let filter = Filter::new(self.clock.clone(), dns, zone);
        let backend = Backend::create(backend_type);

        let jail = Jail::new(name, filter, backend, self.clock.clone());

        // Associate database if present
        if let Some(db) = &self.db {
            let _ = db.add_jail(name);
        }

        self.jails.insert(name.to_owned(), jail);
        Ok(())
    }

    pub fn start_jail(&mut self, name: &str) -> Result<(), String> {
        let jail = self
            .jails
            .get_mut(name)
            .ok_or_else(|| format!("Jail {name} not found"))?;
        jail.start()?;

        // Re-instate bans from database if database is configured
        if let Some(db) = &self.db {
            let now = jail.clock.time();
            if let Ok(bans) = db.get_current_bans(
                Some(name),
                None,
                Some(now),
                Some(jail.actions.ban_manager.ban_time()),
                None,
            ) {
                for t in bans {
                    let mut bt = f2b_types::BanTicket::from_fail_ticket(t);
                    let _ = jail.actions.ban(&mut bt, now);
                }
            }
        }

        Ok(())
    }

    pub fn stop_jail(&mut self, name: &str) -> Result<(), String> {
        let jail = self
            .jails
            .get_mut(name)
            .ok_or_else(|| format!("Jail {name} not found"))?;
        jail.stop()
    }

    pub fn stop_all_jails(&mut self) -> Result<(), String> {
        for jail in self.jails.values_mut() {
            let _ = jail.stop();
        }
        Ok(())
    }

    pub fn quit(&mut self) {
        let _ = self.stop_all_jails();
        self.running = false;
    }

    pub fn set_database(&mut self, path: &str) -> Result<(), String> {
        if path == "None" || path.is_empty() {
            self.db = None;
            return Ok(());
        }

        let db =
            Fail2BanDb::open(path, 86400).map_err(|e| format!("cannot open db {path}: {e}"))?;
        let db_arc = Arc::new(db);
        for name in self.jails.keys() {
            let _ = db_arc.add_jail(name);
        }
        self.db = Some(db_arc);
        Ok(())
    }

    pub fn unban_ip(&mut self, jail_name: Option<&str>, ips: &[&str]) -> Result<usize, String> {
        let mut unbanned = 0;
        let _now = self.clock.time();

        for (name, jail) in &mut self.jails {
            if let Some(target) = jail_name {
                if name != target {
                    continue;
                }
            }

            if ips.is_empty() || (ips.len() == 1 && ips[0] == "--all") {
                unbanned += jail.actions.flush_ban(false)?;
            } else {
                for &ip_str in ips {
                    if let Ok(ip) = IPAddr::new(ip_str) {
                        if let Some(ticket) = jail.actions.ban_manager.get_ticket_by_id(&ip) {
                            jail.actions.unban(&ticket)?;
                            unbanned += 1;
                        }
                    }
                }
            }

            if let Some(db) = &self.db {
                let _ = db.del_ban(name, ips);
            }
        }

        Ok(unbanned)
    }

    pub fn status(&self, jail_name: Option<&str>) -> Result<Value, String> {
        if let Some(name) = jail_name {
            let jail = self
                .jails
                .get(name)
                .ok_or_else(|| format!("Jail {name} not found"))?;

            let filter_stat = Value::List(vec![
                Value::Tuple(vec![
                    Value::Str("Currently failed".into()),
                    Value::Int(jail.fail_manager.size() as i64),
                ]),
                Value::Tuple(vec![
                    Value::Str("Total failed".into()),
                    Value::Int(jail.fail_manager.fail_total() as i64),
                ]),
                Value::Tuple(vec![
                    Value::Str("File list".into()),
                    Value::List(
                        jail.filter
                            .line_buffer()
                            .iter()
                            .map(|l| Value::Str(l.post.clone()))
                            .collect(),
                    ),
                ]),
            ]);

            let banned_ips: Vec<Value> = jail
                .actions
                .ban_manager
                .get_ban_list()
                .into_iter()
                .map(|ip| Value::Str(ip.ntoa().to_string()))
                .collect();

            let actions_stat = Value::List(vec![
                Value::Tuple(vec![
                    Value::Str("Currently banned".into()),
                    Value::Int(jail.actions.ban_manager.size() as i64),
                ]),
                Value::Tuple(vec![
                    Value::Str("Total banned".into()),
                    Value::Int(jail.actions.ban_manager.ban_total() as i64),
                ]),
                Value::Tuple(vec![
                    Value::Str("Banned IP list".into()),
                    Value::List(banned_ips),
                ]),
            ]);

            Ok(Value::List(vec![
                Value::Tuple(vec![Value::Str("Filter".into()), filter_stat]),
                Value::Tuple(vec![Value::Str("Actions".into()), actions_stat]),
            ]))
        } else {
            let mut jail_names: Vec<String> = self.jails.keys().cloned().collect();
            jail_names.sort();

            Ok(Value::List(vec![
                Value::Tuple(vec![
                    Value::Str("Number of jail".into()),
                    Value::Int(jail_names.len() as i64),
                ]),
                Value::Tuple(vec![
                    Value::Str("Jail list".into()),
                    Value::Str(jail_names.join(", ")),
                ]),
            ]))
        }
    }
}
