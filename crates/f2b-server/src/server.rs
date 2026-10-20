//! Server state: the jail registry, database, reload bookkeeping and the
//! periodic work (`Server` in `fail2ban/server/server.py`).
//!
//! Every jail sits behind its own mutex. The server mutex is only held to look
//! a jail up, so a slow action command of one jail cannot block commands for
//! the others (or the `status` of the server).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use indexmap::IndexMap;

use f2b_action::Jail;
use f2b_backend::Backend;
use f2b_date::LocalZone;
use f2b_db::Fail2BanDb;
use f2b_filter::Filter;
use f2b_types::{DnsUtils, SharedClock, system_clock};

/// A jail shared between the command handlers and the runner.
pub type JailHandle = Arc<Mutex<Jail>>;

/// Lock a jail, continuing with the state a panicking holder left behind.
pub fn lock_jail(jail: &JailHandle) -> MutexGuard<'_, Jail> {
    jail.lock().unwrap_or_else(|e| e.into_inner())
}

#[derive(Debug)]
pub struct Server {
    jails: IndexMap<String, JailHandle>,
    pub db: Option<Arc<Fail2BanDb>>,
    pub log_level: String,
    pub log_target: String,
    pub syslog_socket: String,
    pub allow_ipv6: String,
    pub thread_options: String,
    pub clock: SharedClock,
    pub zone: LocalZone,
    pub running: bool,
    /// Jails still to be confirmed by the configuration stream of a running
    /// reload (`true`: not seen yet, `false`: added, waiting for `start`).
    reload_state: HashMap<String, bool>,
    db_purge_next: f64,
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

/// How often the database is purged (`ObserverThread.__db_purge_interval`).
const DB_PURGE_INTERVAL: f64 = 60.0 * 60.0;

impl Server {
    pub fn new() -> Self {
        let clock = system_clock();
        let now = clock.time();
        Self {
            jails: IndexMap::new(),
            db: None,
            log_level: "INFO".to_owned(),
            log_target: "STDOUT".to_owned(),
            syslog_socket: "auto".to_owned(),
            allow_ipv6: "auto".to_owned(),
            thread_options: String::new(),
            clock,
            zone: LocalZone::system(),
            running: true,
            reload_state: HashMap::new(),
            db_purge_next: now + DB_PURGE_INTERVAL,
        }
    }

    // ----------------------------------------------------------- registry

    /// The jail named `name`.
    ///
    /// # Errors
    /// `Unknown jail` when there is none.
    pub fn jail(&self, name: &str) -> Result<JailHandle, String> {
        self.jails
            .get(name)
            .cloned()
            .ok_or_else(|| format!("Jail {name} not found"))
    }

    /// All jails sorted by name (`sorted(self.__jails.items())`).
    pub fn jails_sorted(&self) -> Vec<(String, JailHandle)> {
        let mut v: Vec<(String, JailHandle)> = self
            .jails
            .iter()
            .map(|(n, j)| (n.clone(), j.clone()))
            .collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }

    pub fn jail_count(&self) -> usize {
        self.jails.len()
    }

    /// `addJail`. During a reload an existing jail with the same backend is
    /// kept (its bans and failures survive); a changed backend restarts it.
    pub fn add_jail(&mut self, name: &str, backend_name: &str) -> Result<(), String> {
        if self.reload_state.get(name) == Some(&true) {
            if let Some(handle) = self.jails.get(name).cloned() {
                let same_backend = lock_jail(&handle).backend_name == backend_name;
                if same_backend {
                    log::info!("Reload jail {name:?}");
                    self.reload_state.insert(name.to_owned(), false);
                    self.register_in_db(name);
                    return Ok(());
                }
                log::info!("Restart jail {name:?} (reason: backend changed to {backend_name:?})");
                self.del_jail(name);
                self.reload_state.remove(name);
            }
        }
        if self.jails.contains_key(name) {
            return Err(format!("Jail {name:?} already exists"));
        }

        let dns = Arc::new(DnsUtils::system(self.clock.clone()));
        let filter = Filter::new(self.clock.clone(), dns, self.zone.clone());
        let backend = Backend::from_spec(backend_name)
            .map_err(|e| format!("Unable to use backend {backend_name:?}: {e}"))?;
        let mut jail = Jail::new(name, filter, backend, self.clock.clone());
        jail.backend_name = backend_name.to_owned();
        jail.set_database(self.db.clone());
        self.jails
            .insert(name.to_owned(), Arc::new(Mutex::new(jail)));
        self.register_in_db(name);
        Ok(())
    }

    fn register_in_db(&self, name: &str) {
        if let Some(db) = &self.db {
            if let Err(e) = db.add_jail(name) {
                log::error!("Unable to register jail {name:?} in the database: {e}");
            }
        }
    }

    /// `delJail`: stop and forget a jail.
    pub fn del_jail(&mut self, name: &str) {
        if let Some(handle) = self.jails.shift_remove(name) {
            let mut jail = lock_jail(&handle);
            if let Err(e) = jail.stop() {
                log::error!("[{name}] Failed to stop jail: {e}");
            }
            if let Some(db) = &self.db {
                let _ = db.del_jail(name);
            }
        }
    }

    // ---------------------------------------------------------- lifecycle

    /// `startJail`: start (or, during a reload, confirm) a jail and restore
    /// its bans from the database.
    pub fn start_jail(&mut self, name: &str) -> Result<(), String> {
        let handle = self.jail(name)?;
        let mut jail = lock_jail(&handle);
        if jail.active {
            if self.reload_state.remove(name).is_some() {
                log::info!("Jail {name:?} reloaded");
            }
        } else {
            self.reload_state.remove(name);
            jail.start()?;
            let now = jail.clock.time();
            if let Err(e) = jail.restore_current_bans(true, now) {
                log::error!("[{name}] Unable to restore bans: {e}");
            }
        }
        jail.idle = false;
        Ok(())
    }

    pub fn stop_jail(&mut self, name: &str) -> Result<(), String> {
        let handle = self.jail(name)?;
        let mut jail = lock_jail(&handle);
        jail.stop()
    }

    pub fn stop_all_jails(&mut self) {
        for (name, handle) in self.jails_sorted() {
            if let Err(e) = lock_jail(&handle).stop() {
                log::error!("[{name}] Failed to stop jail: {e}");
            }
        }
    }

    /// `quit`: stop everything; the listener ends once `running` is false.
    pub fn quit(&mut self) {
        log::info!("Stopping all jails");
        self.stop_all_jails();
        log::info!("Exiting Fail2ban");
        self.running = false;
    }

    // -------------------------------------------------------------- reload

    /// `reloadJails(name, opts, begin)`.
    ///
    /// # Errors
    /// Unknown jail (without `--if-exists`) or a reload already running.
    pub fn reload_jails(&mut self, name: &str, opts: &[&str], begin: bool) -> Result<(), String> {
        let all = name == "--all";
        if begin {
            if !self.reload_state.is_empty() && (all || self.reload_state.contains_key(name)) {
                return Err("Reload already in progress".to_owned());
            }
            log::info!(
                "Reload {}",
                if all {
                    "all jails".to_owned()
                } else {
                    format!("jail {name}")
                }
            );
            let targets: Vec<(String, JailHandle)> = if all {
                self.jails_sorted()
            } else {
                match self.jails.get(name) {
                    Some(h) => vec![(name.to_owned(), h.clone())],
                    None if opts.contains(&"--if-exists") => Vec::new(),
                    None => return Err(format!("Jail {name} not found")),
                }
            };
            for (jn, handle) in targets {
                let mut jail = lock_jail(&handle);
                if opts.contains(&"--unban") {
                    if let Err(e) = jail.unban_ips(None, true) {
                        log::error!("[{jn}] Failed to unban: {e}");
                    }
                }
                if opts.contains(&"--restart") {
                    if let Err(e) = jail.stop() {
                        log::error!("[{jn}] Failed to stop jail: {e}");
                    }
                }
                jail.reload_begin();
                self.reload_state.insert(jn, true);
            }
        } else {
            let leftover: Vec<String> = self.reload_state.keys().cloned().collect();
            for jn in &leftover {
                // not mentioned by the new configuration: remove it
                self.del_jail(jn);
            }
            for (jn, handle) in self.jails_sorted() {
                if !leftover.contains(&jn) {
                    lock_jail(&handle).reload_end();
                }
            }
            self.reload_state.clear();
            log::info!("Reload finished.");
        }
        Ok(())
    }

    // ------------------------------------------------------------ database

    /// `setDatabase`: `None` (or empty) disables persistence.
    pub fn set_database(&mut self, path: &str) -> Result<(), String> {
        let purge_age = self.db.as_ref().map_or(86400, |d| d.purge_age());
        let max_matches = self.db.as_ref().map(|d| d.max_matches());
        if path == "None" || path.is_empty() {
            self.db = None;
        } else {
            if let Some(cur) = &self.db {
                if cur.filename().to_string_lossy() == path {
                    return Ok(());
                }
            }
            let db = Fail2BanDb::open(path, purge_age)
                .map_err(|e| format!("Unable to open the database {path}: {e}"))?;
            if let Some(m) = max_matches {
                db.set_max_matches(m);
            }
            self.db = Some(Arc::new(db));
        }
        for (name, handle) in self.jails_sorted() {
            lock_jail(&handle).set_database(self.db.clone());
            self.register_in_db(&name);
        }
        Ok(())
    }

    // -------------------------------------------------------------- runner

    /// One scheduling round: every active jail reads its logs, bans and
    /// unbans (`FilterPoll.run` + `Actions.run`), and the database is purged
    /// periodically. Locks are taken per jail, never across jails.
    pub fn tick(server: &Mutex<Server>) -> bool {
        let (jails, db, now, purge_due) = {
            let mut s = server.lock().unwrap_or_else(|e| e.into_inner());
            if !s.running {
                return false;
            }
            let now = s.clock.time();
            let purge_due = s.db.is_some() && now >= s.db_purge_next;
            if purge_due {
                s.db_purge_next = now + DB_PURGE_INTERVAL;
            }
            (s.jails_sorted(), s.db.clone(), now, purge_due)
        };
        for (name, handle) in jails {
            match handle.try_lock() {
                Ok(mut jail) => {
                    let jail_now = jail.clock.time();
                    if let Err(e) = jail.step(jail_now) {
                        log::error!("[{name}] {e}");
                    }
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    log::trace!("[{name}] step is still in progress, skipping tick");
                }
                Err(std::sync::TryLockError::Poisoned(p)) => {
                    let mut jail = p.into_inner();
                    let jail_now = jail.clock.time();
                    let _ = jail.step(jail_now);
                }
            }
        }
        if let (true, Some(db)) = (purge_due, db) {
            log::debug!("Purge database event occurred");
            if let Err(e) = db.purge(now) {
                log::error!("Database purge failed: {e}");
            }
        }
        true
    }
}
