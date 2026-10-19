//! Date detection for Fast2Ban: a port of upstream Fail2Ban's
//! `server/datedetector.py`, `datetemplate.py` and `strptime.py`.
//!
//! # Usage
//!
//! ```
//! use f2b_date::{DateDetector, DateEnv, LocalZone};
//! use f2b_types::fixed_clock;
//!
//! // "now" 2005-08-14 10:00:00 UTC, local zone CET/CEST (POSIX rule)
//! let zone = LocalZone::posix("CET-01CEST-02,M3.5.0,M10.5.0").unwrap();
//! let env = DateEnv::new(fixed_clock(1_124_013_600.0), zone);
//! let mut dd = DateDetector::with_default_templates(env).unwrap();
//!
//! let line = "Aug 14 11:22:33 host sshd[1]: Failed password";
//! let tm = dd.match_time(line);
//! let (s, e) = tm.span().unwrap();
//! assert_eq!(&line[s..e], "Aug 14 11:22:33");
//! assert_eq!(dd.get_time(&line[s..e], &tm), Some(1_124_011_353.0));
//! ```
//!
//! # Differences from upstream
//!
//! * **No global state.** Upstream shares template objects (and their `hits`
//!   counters), a pattern cache and the default-template list between all
//!   detectors of the process. Here every [`DateDetector`] owns its templates;
//!   a detector behaves like upstream's first detector in a fresh process. The
//!   upstream pattern cache is keyed by the *upper-cased* pattern (when it has
//!   no `%`), so e.g. `\d+` and `\D+` alias each other there; that is not
//!   replicated.
//! * **Environment is explicit** ([`DateEnv`]): the clock (`MyTime.time()` and
//!   `now()`), the process-local time zone ([`LocalZone`], the oracle uses
//!   the POSIX rule `CET-01CEST-02,M3.5.0,M10.5.0`; `TZ` is never read except
//!   by [`LocalZone::system`]), the import-time wall-clock year of upstream's
//!   `%ExY` year window and `MyTime.alternateNowTime`.
//! * **Templates compile eagerly.** Upstream compiles a template's regex at
//!   its first use, so a broken `datepattern` fails on the first log line;
//!   here [`DateDetector::append_template`] reports it immediately.
//! * `lastUsed` uses the injected clock instead of `time.time()`.
//! * Python exceptions other than `ValueError` that escape upstream's
//!   `getTime` (`KeyError`, `TypeError`, `OverflowError`, ...) are returned by
//!   [`DateDetector::try_get_time`]; [`DateDetector::get_time`] maps them to
//!   `None`.
//! * A template regex that matches the empty string at the very end of a line
//!   would raise `IndexError` in upstream's `matchTime`; here it is treated as
//!   having no neighbouring character.
//! * Unsupported Python-regex corners are rejected with an error: verbose
//!   mode `(?x)`, `(?a)`, `(?L)`, `\N{..}`, and an unkeyed `%s`/`%.2s`
//!   conversion in a date pattern (upstream would splice the `repr` of its
//!   whole `timeRE` dict, whose order depends on the hash seed); see `pyre.rs`.
//! * `mktime`: glibc resolves a repeated local time (DST fall-back) from the
//!   state of its previous call; this crate is a pure function and behaves
//!   like glibc primed with the zone's standard offset. glibc applies a POSIX
//!   TZ *rule* only from 1970-01-01 on (earlier instants use standard time,
//!   DST for southern rules); [`LocalZone::posix`] reproduces that.
//! * `%ExY` year window: [`DateEnv::with_year_window_now`] is upstream's
//!   `MyTime.alternateNowTime` (as set by `fail2ban-regex`), independent of
//!   the injected clock; [`DateEnv::with_wall_clock_year`] is the year the
//!   upstream module saw at import time.
//! * The names of `%Exk`/`%Exl` depend on Python's hash seed upstream; this
//!   crate uses `%Exk`/`%Exl` (hash seed 0).

mod civil;
mod detector;
mod error;
mod pyint;
mod pyre;
mod strptime;
mod template;
mod time_re_table;
mod zone;

pub use detector::{
    DateDetector, DateEnv, DatePatternInfo, TemplateFilter, TemplateInfo, TimeMatch,
};
pub use error::{DateError, TimeError};
pub use zone::LocalZone;

/// `validateTimeZone`: minutes east of UTC for a `logtimezone` value such as
/// `UTC`, `CET`, `+0200` or `UTC+02:00`.
pub fn validate_time_zone(tz: &str) -> Result<i64, DateError> {
    strptime::validate_time_zone(tz).map_err(|_| DateError::TimeZone(tz.to_string()))
}
