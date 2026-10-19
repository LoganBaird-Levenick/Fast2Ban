//! Observer handling dynamic ban time increment, failure counts, and database interactions.

use f2b_db::Fail2BanDb;
use f2b_types::{BanTicket, FailManager, FailTicket};

use crate::actions::Actions;
use crate::ban_extra::{BanExtra, rand_float};

/// Observer handling failure increment, ban time calculations, and persistence.
#[derive(Debug)]
pub struct Observer;

impl Observer {
    /// Notify observer a failure for an IP was found.
    /// Observer checks if IP was previously known (bad) and increases retry count accordingly.
    pub fn failure_found(
        jail_name: &str,
        ban_extra: &BanExtra,
        database: Option<&Fail2BanDb>,
        fail_manager: &mut FailManager,
        actions: &mut Actions,
        ticket: &mut FailTicket,
        now: f64,
    ) {
        if !ban_extra.increment {
            return;
        }
        let Some(db) = database else {
            return;
        };
        let ip = ticket.id().clone();
        let ip_str = ip.ntoa();
        let max_retry = fail_manager.max_retry();
        if let Ok(Some((ban_count, time_of_ban, _last_ban_time))) = db.get_ban(
            &ip_str,
            Some(jail_name),
            ban_extra.overalljails,
            None,
            None,
            now,
        ) {
            let effective_ban_count = ban_count.max(ticket.ticket().ban_count());
            let count_shift = if effective_ban_count < 20 {
                effective_ban_count
            } else {
                20
            };
            let mut retry_count = (1i64 << count_shift) / 2 + 1;
            retry_count = retry_count.min(max_retry);

            if ticket.time() <= time_of_ban {
                log::debug!(
                    "[{}] Ignore failure {} before last ban {} <= {}, restored",
                    jail_name,
                    ip_str,
                    ticket.time(),
                    time_of_ban
                );
                return;
            }

            if retry_count <= 1 {
                return;
            }

            log::info!(
                "[{}] Found {}, bad - {}, {} # -> {}{}",
                jail_name,
                ip_str,
                ticket.time(),
                effective_ban_count,
                retry_count,
                if retry_count >= max_retry {
                    ", Ban"
                } else {
                    ""
                }
            );

            ticket.ticket_mut().set_ban_count(effective_ban_count, true);
            // retry_count - 1 because ticket was already once incremented by filter itself
            let attempts = fail_manager.add_failure(ticket.clone(), retry_count - 1);
            if attempts >= max_retry {
                if let Ok(to_ban) = fail_manager.to_ban(Some(ticket.id())) {
                    let mut ban_ticket = BanTicket::from_fail_ticket(to_ban);
                    let base_bt = actions.ban_manager.ban_time();
                    if actions.ban(&mut ban_ticket, now).unwrap_or(false) {
                        Self::ban_found(
                            jail_name,
                            ban_extra,
                            database,
                            &mut ban_ticket,
                            base_bt,
                            now,
                        );
                        if let Some(t) = actions.ban_manager.get_ticket_mut(ban_ticket.id()) {
                            if let Some(bt) = ban_ticket.ticket().raw_ban_time() {
                                t.ticket_mut().set_ban_time(bt);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Check for IP address to increment ban time (if was already banned).
    pub fn incr_ban_time(
        jail_name: &str,
        ban_extra: &BanExtra,
        database: Option<&Fail2BanDb>,
        base_ban_time: i64,
        ticket: &mut BanTicket,
        now: f64,
    ) -> i64 {
        if base_ban_time <= 0 || !ban_extra.increment {
            return base_ban_time;
        }
        let Some(db) = database else {
            return base_ban_time;
        };
        let ip = ticket.id().clone();
        let ip_str = ip.ntoa();
        let mut ban_time = base_ban_time;
        if let Ok(Some((ban_count, time_of_ban, _last_ban_time))) = db.get_ban(
            &ip_str,
            Some(jail_name),
            ban_extra.overalljails,
            None,
            None,
            now,
        ) {
            if ban_count >= ticket.ticket().ban_count() {
                ticket.ticket_mut().set_ban_count(ban_count + 1, true);
            }
            if ban_count > 0 {
                if let Ok(res) =
                    ban_extra.calc_ban_time(base_ban_time as f64, ban_count, rand_float)
                {
                    ban_time = res.as_i64().unwrap_or(base_ban_time);
                }
            }
            ticket.ticket_mut().set_ban_time(ban_time);

            if ticket.time() > time_of_ban {
                log::info!(
                    "[{}] IP {} is bad: {} # last {} - incr {} to {}",
                    jail_name,
                    ip_str,
                    ban_count,
                    time_of_ban,
                    base_ban_time,
                    ban_time
                );
            } else {
                ticket.ticket_mut().set_restored(true);
            }
        }

        ban_time
    }

    /// Notify observer a ban occurred for an IP.
    /// Increases/prolongs ban time if applicable and persists to database.
    pub fn ban_found(
        jail_name: &str,
        ban_extra: &BanExtra,
        database: Option<&Fail2BanDb>,
        ticket: &mut BanTicket,
        base_ban_time: i64,
        now: f64,
    ) -> bool {
        if ticket.ticket().is_restored() {
            return false;
        }
        let old_btime = base_ban_time;
        let mut btime = base_ban_time;

        if btime != -1 && ticket.ticket().raw_ban_time().is_none() {
            btime = Self::incr_ban_time(jail_name, ban_extra, database, btime, ticket, now);
            if btime == -1 || btime > old_btime {
                ticket.ticket_mut().set_ban_time(btime);
            }
        }

        if btime != -1 {
            let bendtime = ticket.time() + btime as f64;
            if bendtime < now {
                log::debug!("Ignore old bantime {}", bendtime);
                return false;
            }
        }

        if btime != old_btime {
            log::info!(
                "[{}] Increase Ban {} ({} # {} -> {})",
                jail_name,
                ticket.id().ntoa(),
                ticket.ticket().ban_count(),
                old_btime,
                btime
            );
        }

        if let Some(db) = database {
            if !ticket.ticket().is_restored() {
                let _ = db.add_ban(jail_name, ticket, btime);
            }
        }

        true
    }

    /// Calculate ban time directly for testing and transmitter queries.
    pub fn calc_ban_time(
        ban_extra: &BanExtra,
        ban_time: f64,
        ban_count: i64,
    ) -> Result<f2b_expr::Num, String> {
        ban_extra.calc_ban_time(ban_time, ban_count, rand_float)
    }
}
