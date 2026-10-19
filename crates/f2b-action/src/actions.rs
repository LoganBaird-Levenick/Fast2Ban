//! Implementation of `Actions` (`fail2ban/server/actions.py`).

use f2b_types::banmanager::{BanManager, BanReason};
use f2b_types::ticket::BanTicket;
use indexmap::IndexMap;

use crate::action::CommandAction;
use crate::tags::ActionInfo;

/// Container and coordinator for all actions of a jail.
#[derive(Debug, Clone)]
pub struct Actions {
    pub jail_name: String,
    pub actions: IndexMap<String, CommandAction>,
    pub ban_manager: BanManager,
    pub ban_epoch: u64,
}

impl Actions {
    pub fn new(jail_name: &str) -> Self {
        Self {
            jail_name: jail_name.to_owned(),
            actions: IndexMap::new(),
            ban_manager: BanManager::new(),
            ban_epoch: 0,
        }
    }

    pub fn add_action(&mut self, action: CommandAction) {
        self.actions.insert(action.name.clone(), action);
    }

    pub fn get_action(&self, name: &str) -> Option<&CommandAction> {
        self.actions.get(name)
    }

    pub fn get_action_mut(&mut self, name: &str) -> Option<&mut CommandAction> {
        self.actions.get_mut(name)
    }

    pub fn start(&mut self) -> Result<(), String> {
        for action in self.actions.values_mut() {
            if !action.actionstart_on_demand {
                action.start(Some("inet4"))?;
            }
        }
        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), String> {
        self.flush_ban(true)?;
        for action in self.actions.values_mut() {
            action.stop(Some("inet4"))?;
            action.stop(Some("inet6"))?;
        }
        Ok(())
    }

    /// Ban a host associated with the given `BanTicket`.
    pub fn ban(&mut self, ticket: &mut BanTicket, now: f64) -> Result<bool, String> {
        let default_bt = self.ban_manager.ban_time();
        let (added, reason) = self.ban_manager.add_ban_ticket(ticket.clone(), now);

        if added {
            let ainfo = ActionInfo::from_ticket(ticket, &self.jail_name, default_bt);
            log::info!("[{}] Ban {}", self.jail_name, ainfo.ip);

            for action in self.actions.values_mut() {
                if ticket.ticket().is_restored() && action.norestored {
                    continue;
                }
                action.ban(&ainfo)?;
            }

            ticket.ticket_mut().set_banned(true);
            ticket.ticket_mut().set_ban_epoch(self.ban_epoch);
            Ok(true)
        } else {
            match reason {
                BanReason::Expired => {
                    log::info!(
                        "[{}] Ignore {}, expired bantime",
                        self.jail_name,
                        ticket.id().ntoa()
                    );
                    Ok(false)
                }
                BanReason::AlreadyBanned { prolonged } => {
                    if prolonged {
                        let ainfo = ActionInfo::from_ticket(ticket, &self.jail_name, default_bt);
                        log::info!("[{}] Prolong ban {}", self.jail_name, ainfo.ip);
                        for action in self.actions.values_mut() {
                            action.ban(&ainfo)?;
                        }
                    }
                    Ok(false)
                }
                BanReason::Ok => unreachable!(),
            }
        }
    }

    /// Unban a host.
    pub fn unban(&mut self, ticket: &BanTicket) -> Result<(), String> {
        let default_bt = self.ban_manager.ban_time();
        let ainfo = ActionInfo::from_ticket(ticket, &self.jail_name, default_bt);
        log::info!("[{}] Unban {}", self.jail_name, ainfo.ip);

        for action in self.actions.values_mut() {
            action.unban(&ainfo)?;
        }
        Ok(())
    }

    /// Check and unban expired tickets.
    pub fn check_unban(&mut self, now: f64, max_count: Option<usize>) -> Result<usize, String> {
        let expired = self.ban_manager.unban_list(now, max_count);
        let count = expired.len();
        for t in expired {
            self.unban(&t)?;
        }
        Ok(count)
    }

    /// Flush all active bans.
    pub fn flush_ban(&mut self, stop: bool) -> Result<usize, String> {
        let tickets = self.ban_manager.flush_ban_list();
        let count = tickets.len();

        let default_bt = self.ban_manager.ban_time();
        for action in self.actions.values_mut() {
            if !action.actionflush.is_empty() {
                action.flush()?;
            } else {
                for t in &tickets {
                    let ainfo = ActionInfo::from_ticket(t, &self.jail_name, default_bt);
                    action.unban(&ainfo)?;
                }
            }
        }
        if stop {
            log::info!("[{}] Repeal all bans (count: {count})", self.jail_name);
        }
        Ok(count)
    }
}
