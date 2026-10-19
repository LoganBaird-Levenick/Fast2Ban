//! Naive (time-zone-less) date arithmetic mirroring Python's `datetime`
//! (proleptic Gregorian calendar, years 1..=9999).

/// Failure of a Python `datetime` operation, by exception class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PyExc {
    Value,
    Type,
    Key,
    Index,
    Overflow,
    Attribute,
}

pub(crate) type PyResult<T> = Result<T, PyExc>;

pub(crate) fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

pub(crate) fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            if is_leap(y) {
                29
            } else {
                28
            }
        }
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (month 1..=12).
pub(crate) fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Inverse of [`days_from_civil`].
pub(crate) fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Monday = 0 (Python `date.weekday()`), from days since 1970-01-01.
pub(crate) fn weekday(days: i64) -> i64 {
    (days + 3).rem_euclid(7)
}

const MIN_SECS: i64 = -62_135_596_800; // 0001-01-01T00:00:00
const MAX_SECS: i64 = 253_402_300_799; // 9999-12-31T23:59:59

/// A naive `datetime` with microsecond resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Naive {
    /// seconds since 1970-01-01T00:00:00 (as if UTC)
    pub secs: i64,
    pub us: u32,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Fields {
    pub year: i64,
    pub month: i64,
    pub day: i64,
    pub hour: i64,
    pub minute: i64,
    pub second: i64,
}

impl Naive {
    /// `datetime.datetime(year, month, day, hour, minute, second)`; errors are
    /// `ValueError` (fields out of range) like upstream.
    pub(crate) fn new(
        year: i64,
        month: i64,
        day: i64,
        hour: i64,
        minute: i64,
        second: i64,
    ) -> PyResult<Self> {
        if !(1..=9999).contains(&year)
            || !(1..=12).contains(&month)
            || !(1..=days_in_month(year, month)).contains(&day)
            || !(0..24).contains(&hour)
            || !(0..60).contains(&minute)
            || !(0..60).contains(&second)
        {
            return Err(PyExc::Value);
        }
        Ok(Self {
            secs: days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second,
            us: 0,
        })
    }

    pub(crate) fn fields(&self) -> Fields {
        let days = self.secs.div_euclid(86_400);
        let rem = self.secs.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days);
        Fields {
            year,
            month,
            day,
            hour: rem / 3600,
            minute: rem % 3600 / 60,
            second: rem % 60,
        }
    }

    /// `self + timedelta(seconds=delta)`; `OverflowError` outside year 1..=9999.
    pub(crate) fn add_secs(self, delta: i64) -> PyResult<Self> {
        let secs = self.secs.checked_add(delta).ok_or(PyExc::Overflow)?;
        if !(MIN_SECS..=MAX_SECS).contains(&secs) {
            return Err(PyExc::Overflow);
        }
        Ok(Self { secs, us: self.us })
    }

    /// `self.replace(year=y, month=m, day=d)`.
    pub(crate) fn replace_date(self, y: i64, m: i64, d: i64) -> PyResult<Self> {
        let f = self.fields();
        let mut n = Self::new(y, m, d, f.hour, f.minute, f.second)?;
        n.us = self.us;
        Ok(n)
    }
}

/// `datetime.fromtimestamp(t)` microsecond rounding (`ROUND_HALF_EVEN`):
/// returns whole seconds and microseconds.
pub(crate) fn split_timestamp(t: f64) -> (i64, u32) {
    let int = t.trunc();
    let mut frac = ((t - int) * 1e6).round_ties_even();
    let mut int = int;
    if frac >= 1e6 {
        frac -= 1e6;
        int += 1.0;
    } else if frac < 0.0 {
        frac += 1e6;
        int -= 1.0;
    }
    (int as i64, frac as u32)
}
