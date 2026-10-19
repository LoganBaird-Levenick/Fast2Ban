//! The process-local time zone, made injectable.
//!
//! Upstream converts naive local times with `time.mktime` and builds "now"
//! with `datetime.fromtimestamp`, both of which read the process time zone
//! (`TZ`). The crate never reads `TZ` implicitly: every detector carries a
//! [`LocalZone`] chosen by the caller.

use std::fmt;

use jiff::Timestamp;
use jiff::civil::DateTime;
use jiff::tz::{AmbiguousOffset, TimeZone};

use crate::civil::{Naive, split_timestamp};

/// A time zone that stands for "the process local time zone".
#[derive(Clone)]
pub struct LocalZone {
    tz: TimeZone,
    /// Offset (seconds) of the zone's standard time: the offset glibc's
    /// `mktime` starts its search from (see [`LocalZone::mktime`]).
    std_offset: i64,
    /// glibc quirk for POSIX TZ *rules* (no tz database file): the DST rule is
    /// not applied before 1970-01-01T00:00Z; such instants use this offset
    /// (standard time for northern, DST for southern-hemisphere rules).
    pre_1970: Option<i64>,
}

impl fmt::Debug for LocalZone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalZone")
            .field("iana_name", &self.tz.iana_name())
            .field("std_offset", &self.std_offset)
            .field("pre_1970", &self.pre_1970)
            .finish()
    }
}

impl LocalZone {
    fn new(tz: TimeZone, posix_rule: bool) -> Self {
        // standard-time offset: the offset of the first of 2000-01-15 and
        // 2000-07-15 (noon UTC) that is not DST, else the January one
        let at = |secs: i64| {
            Timestamp::from_second(secs).ok().map(|ts| {
                let info = tz.to_offset_info(ts);
                (i64::from(info.offset().seconds()), info.dst().is_dst())
            })
        };
        let std_offset = [947_937_600, 963_662_400]
            .into_iter()
            .filter_map(at)
            .find(|&(_, dst)| !dst)
            .or_else(|| at(947_937_600))
            .map_or(0, |(o, _)| o);
        let pre_1970 = posix_rule.then(|| {
            // January 15th in DST means a southern-hemisphere rule
            match at(947_937_600) {
                Some((off, true)) => off,
                _ => std_offset,
            }
        });
        Self {
            tz,
            std_offset,
            pre_1970,
        }
    }

    /// UTC.
    pub fn utc() -> Self {
        Self::new(TimeZone::UTC, false)
    }

    /// A POSIX TZ rule such as `CET-01CEST-02,M3.5.0,M10.5.0` (the rule is
    /// applied to every year, like glibc does for rule strings).
    pub fn posix(rule: &str) -> Result<Self, String> {
        TimeZone::posix(rule)
            .map(|tz| Self::new(tz, true))
            .map_err(|e| format!("invalid POSIX TZ rule {rule:?}: {e}"))
    }

    /// An IANA zone name (`Europe/Paris`), looked up in the system tz database.
    pub fn named(name: &str) -> Result<Self, String> {
        TimeZone::get(name)
            .map(|tz| Self::new(tz, false))
            .map_err(|e| format!("unknown time zone {name:?}: {e}"))
    }

    /// Interpret the text of a `TZ` environment variable: empty means UTC,
    /// a leading `:` or an IANA name selects a database zone, anything else
    /// is tried as a POSIX rule.
    pub fn from_tz_value(tz: &str) -> Result<Self, String> {
        let tz = tz.strip_prefix(':').unwrap_or(tz);
        if tz.is_empty() || tz == "UTC" {
            return Ok(Self::utc());
        }
        Self::posix(tz).or_else(|_| Self::named(tz))
    }

    /// The system's current zone (reads `TZ` / `/etc/localtime` once, now).
    /// Only call this at start-up, never per line.
    pub fn system() -> Self {
        Self::new(TimeZone::system(), false)
    }

    /// UTC offset in seconds in effect at Unix time `secs`.
    fn offset_at(&self, secs: i64) -> i64 {
        if let Some(off) = self.pre_1970
            && secs < 0
        {
            return off;
        }
        let ts = Timestamp::from_second(secs).unwrap_or(if secs < 0 {
            Timestamp::MIN
        } else {
            Timestamp::MAX
        });
        i64::from(self.tz.to_offset(ts).seconds())
    }

    /// `datetime.fromtimestamp(t)`: the local civil time of Unix time `t`.
    pub(crate) fn local_civil(&self, t: f64) -> Naive {
        let (secs, us) = split_timestamp(t);
        Naive {
            secs: secs + self.offset_at(secs),
            us,
        }
    }

    /// `time.mktime(naive.timetuple())` (`tm_isdst = -1`), in whole seconds.
    ///
    /// glibc's `mktime` starts from the offset of its previous call and
    /// accepts the first consistent instant, so an ambiguous (repeated) local
    /// time resolves to whichever instance matches that history, which is
    /// process-global state. This port is a pure function instead: it behaves
    /// like glibc whose previous call had the zone's *standard* offset
    /// (`o0`): the search starts at `naive - o0`, and a repeated time resolves
    /// to the instance with the offset in effect there. A skipped time (spring
    /// forward) is interpreted with the offset before the gap, as glibc does.
    pub(crate) fn mktime(&self, n: &Naive) -> i64 {
        if let Some(off) = self.pre_1970
            && n.secs - off < 0
        {
            return n.secs - off;
        }
        let f = n.fields();
        if let Ok(dt) = DateTime::new(
            f.year as i16,
            f.month as i8,
            f.day as i8,
            f.hour as i8,
            f.minute as i8,
            f.second as i8,
            0,
        ) {
            let amb = self.tz.to_ambiguous_timestamp(dt);
            if let AmbiguousOffset::Fold { before, after } = amb.offset() {
                let o1 = self.offset_at(n.secs - self.std_offset);
                for off in [before, after] {
                    if i64::from(off.seconds()) == o1 {
                        return n.secs - o1;
                    }
                }
            }
            if let Ok(ts) = amb.later() {
                return ts.as_second();
            }
        }
        // outside the range jiff represents (last day of year 9999): use the
        // offset at the edge of the range
        n.secs - self.offset_at(if n.secs < 0 { i64::MIN } else { i64::MAX })
    }
}
