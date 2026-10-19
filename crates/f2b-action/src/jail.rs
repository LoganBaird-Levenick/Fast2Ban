//! In-process Jail coordinating filter, failmanager, actions, and backends.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use f2b_backend::Backend;
use f2b_db::Fail2BanDb;
use f2b_filter::Filter;
use f2b_types::{BanTicket, FailManager, FailTicket, IPAddr, IPAddrSet, SharedClock};

use crate::actions::Actions;
use crate::ban_extra::BanExtra;
use crate::exec::execute_cmd;
use crate::observer::Observer;
/// An active jail instance managing the complete monitoring and ban lifecycle.
#[derive(Debug)]
pub struct Jail {
    pub name: String,
    pub filter: Filter,
    pub fail_manager: FailManager,
    pub actions: Actions,
    pub backend: Backend,
    pub ignore_ip: IPAddrSet,
    pub ignore_self: bool,
    pub ignore_command: Option<String>,
    pub clock: SharedClock,
    pub ban_extra: BanExtra,
    pub database: Option<Arc<Fail2BanDb>>,
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
            ignore_self: true,
            ignore_command: None,
            clock,
            ban_extra: BanExtra::new(),
            database: None,
        }
    }

    pub fn add_ignore_ip(&mut self, ip_str: &str) -> Result<(), f2b_types::ipaddr::IPAddrError> {
        let ip = IPAddr::new(ip_str)?;
        self.ignore_ip.add(ip);
        Ok(())
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
            let (added, _) = self.actions.ban_manager.add_ban_ticket(ban_ticket, now);
            if added {
                count += 1;
            }
        }
        Ok(count)
    }

    /// Check if an IP address should be ignored according to `ignoreip`, `ignoreself`, or `ignorecommand`.
    pub fn is_ignored(&self, ip: &IPAddr) -> bool {
        if self.ignore_ip.contains(ip) {
            return true;
        }

        // Check external ignore command if configured
        if let Some(cmd_template) = &self.ignore_command {
            let cmd = cmd_template.replace("<ip>", &ip.ntoa());
            if let Ok(res) = execute_cmd(&cmd, Duration::from_secs(5), &[]) {
                if res.success {
                    log::info!("[{}] Ignore {} by ignorecommand", self.name, ip.ntoa());
                    return true;
                }
            }
        }

        false
    }

    pub fn start(&mut self) -> Result<(), String> {
        log::info!("[{}] Jail started", self.name);
        self.actions.start()
    }

    pub fn stop(&mut self) -> Result<(), String> {
        log::info!("[{}] Jail stopped", self.name);
        self.actions.stop()
    }

    /// Process a single log line directly, updating failures and executing bans if threshold reached.
    pub fn process_line(&mut self, line: &str, now: f64) -> Result<usize, String> {
        let entries = self.filter.process_line(line).map_err(|e| e.to_string())?;
        let mut bans = 0;

        for entry in entries {
            let Some(fid) = entry.fid else {
                continue;
            };

            if self.is_ignored(&fid) {
                log::debug!("[{}] Ignored failure from {}", self.name, fid.ntoa());
                continue;
            }

            let mut ticket = FailTicket::new(fid.clone(), entry.date.unwrap_or(now));
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

            if attempts >= self.fail_manager.max_retry() {
                if let Ok(to_ban) = self.fail_manager.to_ban(Some(&fid)) {
                    let mut ban_ticket = BanTicket::from_fail_ticket(to_ban);
                    let base_bt = self.actions.ban_manager.ban_time();
                    Observer::ban_found(
                        &self.name,
                        &self.ban_extra,
                        self.database.as_deref(),
                        &mut ban_ticket,
                        base_bt,
                        now,
                    );
                    if self.actions.ban(&mut ban_ticket, now)? {
                        bans += 1;
                    }
                }
            }
        }

        Ok(bans)
    }

    /// Run a polling step: reads new lines from backend, processes them, and unbans expired tickets.
    pub fn step(&mut self, now: f64) -> Result<usize, String> {
        let mut lines = Vec::new();
        let _ = self.backend.poll_once(|_path: &Path, line: &str| {
            lines.push(line.to_owned());
        });

        let mut bans = 0;
        for line in lines {
            bans += self.process_line(&line, now)?;
        }

        self.actions.check_unban(now, None)?;
        self.fail_manager.cleanup(now);

        Ok(bans)
    }
}
