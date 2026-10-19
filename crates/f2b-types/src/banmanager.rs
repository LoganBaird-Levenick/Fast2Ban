//! Port of upstream `BanManager` (`fail2ban/server/banmanager.py`).

use indexmap::IndexMap;

use crate::ipaddr::IPAddr;
use crate::ticket::{BanTicket, MAX_TIME};

/// Reason why a ticket was not added as a new ban.
#[derive(Debug, Clone, PartialEq)]
pub enum BanReason {
    Ok,
    Expired,
    AlreadyBanned { prolonged: bool },
}

/// Manages active bans, expiration times, and unbanning.
#[derive(Debug, Clone)]
pub struct BanManager {
    ban_list: IndexMap<IPAddr, BanTicket>,
    ban_time: i64,
    ban_total: usize,
    next_unban_time: f64,
}

impl Default for BanManager {
    fn default() -> Self {
        Self::new()
    }
}

impl BanManager {
    pub fn new() -> Self {
        Self {
            ban_list: IndexMap::new(),
            ban_time: 600,
            ban_total: 0,
            next_unban_time: MAX_TIME,
        }
    }

    pub fn ban_time(&self) -> i64 {
        self.ban_time
    }

    pub fn set_ban_time(&mut self, value: i64) {
        self.ban_time = value;
    }

    pub fn ban_total(&self) -> usize {
        self.ban_total
    }

    pub fn set_ban_total(&mut self, value: usize) {
        self.ban_total = value;
    }

    pub fn size(&self) -> usize {
        self.ban_list.len()
    }

    pub fn in_ban_list(&self, ip: &IPAddr) -> bool {
        self.ban_list.contains_key(ip)
    }

    pub fn get_ban_list(&self) -> Vec<IPAddr> {
        self.ban_list.keys().cloned().collect()
    }

    /// Add a ban ticket. Returns true if newly added, false if expired or already banned.
    pub fn add_ban_ticket(
        &mut self,
        mut ticket: BanTicket,
        current_time: f64,
    ) -> (bool, BanReason) {
        let eob = ticket.ticket().get_end_of_ban_time(self.ban_time);
        if eob < current_time {
            return (false, BanReason::Expired);
        }

        let fid = ticket.id().clone();
        if let Some(old_ticket) = self.ban_list.get_mut(&fid) {
            let mut prolonged = false;
            if eob > old_ticket.ticket().get_end_of_ban_time(self.ban_time) {
                prolonged = true;
                let mut btm = ticket.ticket().ban_time(self.ban_time);
                if btm != -1 {
                    let diftm = ticket.time() - old_ticket.time();
                    if diftm > 0.0 {
                        btm += diftm as i64;
                    }
                }
                old_ticket.ticket_mut().set_ban_time(btm);
            }
            return (false, BanReason::AlreadyBanned { prolonged });
        }

        ticket.ticket_mut().incr_ban_count(1);
        self.ban_total += 1;
        if self.next_unban_time > eob {
            self.next_unban_time = eob;
        }
        self.ban_list.insert(fid, ticket);
        (true, BanReason::Ok)
    }

    /// Returns tickets whose end of ban time has arrived (`time > eob`).
    pub fn unban_list(&mut self, time: f64, max_count: Option<usize>) -> Vec<BanTicket> {
        if self.next_unban_time > time {
            return Vec::new();
        }

        let max_cnt = max_count.unwrap_or(usize::MAX);
        let mut unbanned = Vec::new();
        let mut next_time = MAX_TIME;
        let mut expired_keys = Vec::new();

        for (fid, ticket) in &self.ban_list {
            let eob = ticket.ticket().get_end_of_ban_time(self.ban_time);
            if time > eob {
                expired_keys.push(fid.clone());
                if expired_keys.len() >= max_cnt {
                    next_time = self.next_unban_time;
                    break;
                }
            } else if next_time > eob {
                next_time = eob;
            }
        }

        self.next_unban_time = next_time;
        for k in expired_keys {
            if let Some(t) = self.ban_list.shift_remove(&k) {
                unbanned.push(t);
            }
        }

        unbanned
    }

    /// Flush all active bans and return them.
    pub fn flush_ban_list(&mut self) -> Vec<BanTicket> {
        self.next_unban_time = MAX_TIME;
        self.ban_list.drain(..).map(|(_, t)| t).collect()
    }

    pub fn get_ticket(&self, fid: &IPAddr) -> Option<&BanTicket> {
        self.ban_list.get(fid)
    }

    pub fn get_ticket_mut(&mut self, fid: &IPAddr) -> Option<&mut BanTicket> {
        self.ban_list.get_mut(fid)
    }

    pub fn get_ticket_by_id(&mut self, fid: &IPAddr) -> Option<BanTicket> {
        self.ban_list.shift_remove(fid)
    }
}
