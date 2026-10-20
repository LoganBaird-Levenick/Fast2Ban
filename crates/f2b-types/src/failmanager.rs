//! Port of upstream `FailManager` (`fail2ban/server/failmanager.py`).

use indexmap::IndexMap;

use crate::ipaddr::IPAddr;
use crate::ticket::FailTicket;

/// Error indicating no failure meets the ban criteria.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailManagerEmpty;

impl std::fmt::Display for FailManagerEmpty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "No failures ready to ban")
    }
}

impl std::error::Error for FailManagerEmpty {}

/// Manages failures detected by the filter before banning.
#[derive(Debug, Clone)]
pub struct FailManager {
    fail_list: IndexMap<IPAddr, FailTicket>,
    max_retry: i64,
    max_time: f64,
    fail_total: usize,
    max_matches: usize,
}

impl Default for FailManager {
    fn default() -> Self {
        Self::new()
    }
}

impl FailManager {
    pub fn new() -> Self {
        Self {
            fail_list: IndexMap::new(),
            max_retry: 3,
            max_time: 600.0,
            fail_total: 0,
            max_matches: 5,
        }
    }

    pub fn max_retry(&self) -> i64 {
        self.max_retry
    }

    pub fn set_max_retry(&mut self, value: i64) {
        self.max_retry = value;
    }

    pub fn max_time(&self) -> f64 {
        self.max_time
    }

    pub fn set_max_time(&mut self, value: f64) {
        self.max_time = value;
    }

    pub fn max_matches(&self) -> usize {
        self.max_matches
    }

    pub fn set_max_matches(&mut self, value: usize) {
        self.max_matches = value;
    }

    pub fn fail_total(&self) -> usize {
        self.fail_total
    }

    pub fn set_fail_total(&mut self, value: usize) {
        self.fail_total = value;
    }

    pub fn size(&self) -> usize {
        self.fail_list.len()
    }

    pub fn get_fail_count(&self) -> (usize, i64) {
        let total_retry: i64 = self.fail_list.values().map(|f| f.retry()).sum();
        (self.fail_list.len(), total_retry)
    }

    /// Add a failure ticket. Returns the current retry / attempt count for that IP.
    pub fn add_failure(&mut self, mut ticket: FailTicket, count: i64) -> i64 {
        let fid = ticket.id().clone();
        let attempts: i64;

        if let Some(existing) = self.fail_list.get_mut(&fid) {
            let attempt = if ticket.ticket().failures() <= 0 {
                1
            } else {
                ticket.ticket().failures()
            };
            let matches = if self.max_matches > 0 {
                Some(ticket.ticket().matches())
            } else {
                None
            };
            let unix_time = ticket.time();
            existing.adjust_time(unix_time, self.max_time);
            existing.inc(matches, attempt, count);
            existing
                .ticket_mut()
                .set_ban_count(ticket.ticket().ban_count(), false);

            if self.max_matches > 0 {
                let m = existing.ticket().matches();
                if m.len() > self.max_matches {
                    let truncated: Vec<String> = m[m.len() - self.max_matches..].to_vec();
                    existing.ticket_mut().set_matches(truncated);
                }
            } else {
                existing.ticket_mut().set_matches(Vec::new());
            }
            attempts = existing.retry();
        } else {
            if count > ticket.ticket().failures() {
                ticket.set_retry(count);
            }
            if self.max_matches > 0 {
                let m = ticket.ticket().matches();
                if m.len() > self.max_matches {
                    let truncated: Vec<String> = m[m.len() - self.max_matches..].to_vec();
                    ticket.ticket_mut().set_matches(truncated);
                }
            } else {
                ticket.ticket_mut().set_matches(Vec::new());
            }
            attempts = ticket.retry();
            const MAX_FAILURES_CAPACITY: usize = 50_000;
            if self.fail_list.len() >= MAX_FAILURES_CAPACITY {
                self.fail_list.shift_remove_index(0);
            }
            self.fail_list.insert(fid, ticket);
        }

        self.fail_total += 1;
        attempts
    }

    /// Cleans up failure entries older than `time - max_time`.
    pub fn cleanup(&mut self, time: f64) {
        let cutoff = time - self.max_time;
        self.fail_list.retain(|_, item| item.time() > cutoff);
    }

    pub fn del_failure(&mut self, fid: &IPAddr) -> Option<FailTicket> {
        self.fail_list.shift_remove(fid)
    }

    /// Finds and removes an entry ready to ban (`retry >= max_retry`).
    pub fn to_ban(&mut self, fid: Option<&IPAddr>) -> Result<FailTicket, FailManagerEmpty> {
        if let Some(target) = fid {
            if let Some(pos) = self.fail_list.get_index_of(target) {
                if self.fail_list[pos].retry() >= self.max_retry {
                    let (_, ticket) = self.fail_list.shift_remove_index(pos).unwrap();
                    return Ok(ticket);
                }
            }
        } else {
            for (i, (_, ticket)) in self.fail_list.iter().enumerate() {
                if ticket.retry() >= self.max_retry {
                    let (_, ticket) = self.fail_list.shift_remove_index(i).unwrap();
                    return Ok(ticket);
                }
            }
        }
        Err(FailManagerEmpty)
    }
}
