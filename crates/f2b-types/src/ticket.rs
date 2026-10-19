//! Port of upstream `Ticket`, `FailTicket`, and `BanTicket`
//! (`fail2ban/server/ticket.py`).

use indexmap::IndexMap;
use std::fmt;

use crate::ipaddr::IPAddr;

/// Upstream's `MAX_TIME = 0x7FFFFFFFFFFF` (~4461763-th year).
pub const MAX_TIME: f64 = 140737488355327.0;

/// Ticket flags.
pub const FLAG_RESTORED: u8 = 0x01;
pub const FLAG_BANNED: u8 = 0x08;

/// Base ticket object (`fail2ban.server.ticket.Ticket`).
#[derive(Clone, Debug, PartialEq)]
pub struct Ticket {
    id: IPAddr,
    flags: u8,
    ban_count: i64,
    ban_time: Option<i64>,
    time: f64,
    failures: i64,
    matches: Vec<String>,
    data: IndexMap<String, String>,
    ban_epoch: u64,
}

impl Ticket {
    pub fn new(ip: IPAddr, time: f64) -> Self {
        Self {
            id: ip,
            flags: 0,
            ban_count: 0,
            ban_time: None,
            time,
            failures: 0,
            matches: Vec::new(),
            data: IndexMap::new(),
            ban_epoch: 0,
        }
    }

    pub fn id(&self) -> &IPAddr {
        &self.id
    }

    pub fn set_id(&mut self, ip: IPAddr) {
        self.id = ip;
    }

    pub fn ip(&self) -> &IPAddr {
        &self.id
    }

    pub fn time(&self) -> f64 {
        self.time
    }

    pub fn set_time(&mut self, time: f64) {
        self.time = time;
    }

    pub fn ban_time(&self, default_bt: i64) -> i64 {
        self.ban_time.unwrap_or(default_bt)
    }

    pub fn raw_ban_time(&self) -> Option<i64> {
        self.ban_time
    }

    pub fn set_ban_time(&mut self, ban_time: i64) {
        self.ban_time = Some(ban_time);
    }

    pub fn ban_count(&self) -> i64 {
        self.ban_count
    }

    pub fn set_ban_count(&mut self, value: i64, always: bool) {
        if always || value > self.ban_count {
            self.ban_count = value;
        }
    }

    pub fn incr_ban_count(&mut self, value: i64) {
        self.ban_count += value;
    }

    pub fn failures(&self) -> i64 {
        self.failures
    }

    pub fn set_failures(&mut self, failures: i64) {
        self.failures = failures;
    }

    pub fn matches(&self) -> &[String] {
        &self.matches
    }

    pub fn set_matches(&mut self, matches: Vec<String>) {
        self.matches = matches;
    }

    pub fn is_restored(&self) -> bool {
        (self.flags & FLAG_RESTORED) != 0
    }

    pub fn set_restored(&mut self, restored: bool) {
        if restored {
            self.flags |= FLAG_RESTORED;
        } else {
            self.flags &= !FLAG_RESTORED;
        }
    }

    pub fn is_banned(&self) -> bool {
        (self.flags & FLAG_BANNED) != 0
    }

    pub fn set_banned(&mut self, banned: bool) {
        if banned {
            self.flags |= FLAG_BANNED;
        } else {
            self.flags &= !FLAG_BANNED;
        }
    }

    pub fn ban_epoch(&self) -> u64 {
        self.ban_epoch
    }

    pub fn set_ban_epoch(&mut self, epoch: u64) {
        self.ban_epoch = epoch;
    }

    pub fn data(&self) -> &IndexMap<String, String> {
        &self.data
    }

    pub fn data_mut(&mut self) -> &mut IndexMap<String, String> {
        &mut self.data
    }

    pub fn get_end_of_ban_time(&self, default_bt: i64) -> f64 {
        let bt = self.ban_time.unwrap_or(default_bt);
        if bt == -1 {
            MAX_TIME
        } else {
            self.time + bt as f64
        }
    }

    pub fn is_timed_out(&self, time: f64, default_bt: i64) -> bool {
        let bt = self.ban_time.unwrap_or(default_bt);
        if bt == -1 {
            false
        } else {
            time > self.time + bt as f64
        }
    }
}

impl fmt::Display for Ticket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Ticket: ip={} time={} bantime={:?} bancount={} #attempts={} matches={:?}",
            self.id.ntoa(),
            self.time,
            self.ban_time,
            self.ban_count,
            self.failures,
            self.matches
        )
    }
}

/// FailTicket extends Ticket with attempt tracking across sliding windows.
#[derive(Clone, Debug, PartialEq)]
pub struct FailTicket {
    ticket: Ticket,
    first_time: f64,
    retry: i64,
}

impl FailTicket {
    pub fn new(ip: IPAddr, time: f64) -> Self {
        Self {
            ticket: Ticket::new(ip, time),
            first_time: time,
            retry: 1,
        }
    }

    pub fn from_ticket(ticket: Ticket) -> Self {
        let time = ticket.time();
        let retry = if ticket.failures() > 0 {
            ticket.failures()
        } else {
            1
        };
        Self {
            ticket,
            first_time: time,
            retry,
        }
    }

    pub fn ticket(&self) -> &Ticket {
        &self.ticket
    }

    pub fn ticket_mut(&mut self) -> &mut Ticket {
        &mut self.ticket
    }

    pub fn into_ticket(self) -> Ticket {
        self.ticket
    }

    pub fn id(&self) -> &IPAddr {
        self.ticket.id()
    }

    pub fn time(&self) -> f64 {
        self.ticket.time()
    }

    pub fn retry(&self) -> i64 {
        self.retry
    }

    pub fn set_retry(&mut self, value: i64) {
        self.retry = value;
        if self.ticket.failures == 0 {
            self.ticket.failures = 1;
        }
        if value == 0 {
            self.ticket.failures = 0;
            self.ticket.matches.clear();
        }
    }

    pub fn first_time(&self) -> f64 {
        self.first_time
    }

    /// Upstream `adjustTime`: adjusts retry estimation if interval exceeds max_time.
    pub fn adjust_time(&mut self, time: f64, max_time: f64) {
        if time > self.ticket.time {
            if self.first_time < time - max_time {
                let interval = time - self.first_time;
                if interval > 0.0 {
                    let rate = (self.retry as f64) / interval * max_time;
                    self.retry = rate.round() as i64;
                }
                self.first_time = time - max_time;
            }
            self.ticket.time = time;
        }
    }

    /// Upstream `inc`: increment failure counts and append matches.
    pub fn inc(&mut self, matches: Option<&[String]>, attempt: i64, count: i64) {
        self.retry += count;
        self.ticket.failures += attempt;
        if let Some(m) = matches {
            self.ticket.matches.extend(m.iter().cloned());
        }
    }
}

/// BanTicket represents a ticket for a banned host.
#[derive(Clone, Debug, PartialEq)]
pub struct BanTicket {
    fail_ticket: FailTicket,
}

impl BanTicket {
    pub fn new(ip: IPAddr, time: f64) -> Self {
        Self {
            fail_ticket: FailTicket::new(ip, time),
        }
    }

    pub fn from_fail_ticket(fail_ticket: FailTicket) -> Self {
        Self { fail_ticket }
    }

    pub fn from_ticket(ticket: Ticket) -> Self {
        Self {
            fail_ticket: FailTicket::from_ticket(ticket),
        }
    }

    pub fn fail_ticket(&self) -> &FailTicket {
        &self.fail_ticket
    }

    pub fn fail_ticket_mut(&mut self) -> &mut FailTicket {
        &mut self.fail_ticket
    }

    pub fn ticket(&self) -> &Ticket {
        self.fail_ticket.ticket()
    }

    pub fn ticket_mut(&mut self) -> &mut Ticket {
        self.fail_ticket.ticket_mut()
    }

    pub fn id(&self) -> &IPAddr {
        self.fail_ticket.id()
    }

    pub fn time(&self) -> f64 {
        self.fail_ticket.time()
    }
}
