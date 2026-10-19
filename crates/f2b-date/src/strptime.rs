//! Port of upstream `server/strptime.py`: the `timeRE` token table, the
//! `%`-pattern expansion, time zone validation and `reGroupDictStrptime`.

use std::collections::HashMap;
use std::sync::LazyLock;

use f2b_helpers::pychar;

use crate::civil::{Naive, PyExc, PyResult, civil_from_days, days_from_civil, weekday};
use crate::pyint::py_int;
use crate::pyre::{PyRegex, compile_py_regex};
use crate::time_re_table::{TIME_NAMES, TIME_RE, TZ_STR};
use crate::zone::LocalZone;

/// Upstream `MyTime.alternateNowTime or 978393600` default of the year window.
const DEFAULT_ALTERNATE_NOW: f64 = 978_393_600.0;

// ---------------------------------------------------------------------------
// Year window (`_updateTimeRE`)
// ---------------------------------------------------------------------------

/// Port of the nested `grp()` of `_getYearCentRE`.
fn grp(exprset: &[String]) -> String {
    let mut c: Option<String> = None;
    if exprset.len() > 1 {
        for i in exprset {
            let pre = &i[..i.len().saturating_sub(1)];
            if c.is_none() || c.as_deref() == Some(pre) {
                c = Some(pre.to_string());
            } else {
                c = None;
                break;
            }
        }
        if c.as_deref().is_none_or(str::is_empty) {
            for i in exprset {
                let first = &i[..1];
                if c.is_none() || c.as_deref() == Some(first) {
                    c = Some(first.to_string());
                } else {
                    c = None;
                    break;
                }
            }
        }
        if let Some(c) = c.filter(|c| !c.is_empty()) {
            let rest: Vec<String> = exprset.iter().map(|i| i[c.len()..].to_string()).collect();
            return format!("{c}{}", grp(&rest));
        }
    }
    if exprset.len() > 1 {
        if exprset[0].len() > 1 {
            format!("(?:{})", exprset.join("|"))
        } else {
            format!("[{}]", exprset.concat())
        }
    } else {
        exprset.concat()
    }
}

/// The `%ExY` expression for a window: years from the alternate "now"
/// (2001 by default, earlier if a smaller `year_window_now` was set) up to
/// three years after the wall-clock year.
pub(crate) fn ex_year_regex(
    wall_year: i64,
    year_window_now: Option<f64>,
    zone: &LocalZone,
) -> String {
    let alt = match year_window_now {
        // `MyTime.alternateNowTime or 978393600`: 0 is falsy
        Some(t) if t != 0.0 => t.min(DEFAULT_ALTERNATE_NOW),
        _ => DEFAULT_ALTERNATE_NOW,
    };
    let alt_year = zone.local_civil(alt).fields().year;
    let cent = |y: i64| -> String { y.to_string().chars().take(3).collect() };
    let mut set: Vec<String> = vec![cent(wall_year - 1), cent(wall_year + 3)];
    let mut i = -1;
    while i < wall_year - alt_year + 1 {
        set.push(cent(alt_year + i));
        i += 3;
    }
    set.sort();
    set.dedup();
    format!(r"(?P<Y>{}\d)", grp(&set))
}

// ---------------------------------------------------------------------------
// Pattern expansion
// ---------------------------------------------------------------------------

/// The `timeRE` dictionary of a detector (only `ExY` varies).
#[derive(Debug, Clone)]
pub(crate) struct TimeRe {
    ex_y: String,
}

impl TimeRe {
    pub(crate) fn new(ex_y: String) -> Self {
        Self { ex_y }
    }

    fn regex(&self, key: &str) -> Option<&str> {
        if key == "ExY" {
            return Some(&self.ex_y);
        }
        TIME_RE.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
    }
}

fn name_of(key: &str) -> Option<&'static str> {
    TIME_NAMES.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
}

/// Longest `timeRE` key that `rest` (text after a `%`) starts with, per the
/// alternation `%(%|<multi-char keys>|[<single-char keys>])` of
/// `getTimePatternRE`.
fn match_key(rest: &str) -> Option<&'static str> {
    if rest.starts_with('%') {
        return Some("%");
    }
    TIME_RE
        .iter()
        .map(|(k, _)| *k)
        .filter(|k| k.len() > 1)
        .find(|k| rest.starts_with(k))
        .or_else(|| {
            let c = rest.chars().next()?;
            TIME_RE
                .iter()
                .map(|(k, _)| *k)
                .find(|k| k.len() == 1 && k.starts_with(c))
        })
}

/// `_patternRE.sub(r'%(\1)s', pattern)`.
fn to_format(pattern: &str) -> String {
    let mut fmt = String::with_capacity(pattern.len() + 8);
    let mut rest = pattern;
    while let Some(pos) = rest.find('%') {
        fmt.push_str(&rest[..pos]);
        let after = &rest[pos + 1..];
        if let Some(key) = match_key(after) {
            fmt.push_str("%(");
            fmt.push_str(key);
            fmt.push_str(")s");
            rest = &after[key.len()..];
        } else {
            fmt.push('%');
            rest = after;
        }
    }
    fmt.push_str(rest);
    fmt
}

/// Python `fmt % mapping` for a mapping of `str` values. Unsupported
/// (rare) forms are reported as errors: unkeyed `%s`/`%r`/`%a` (Python would
/// insert the repr of the whole dict), `%a`.
fn percent_format(fmt: &str, lookup: &dyn Fn(&str) -> Option<String>) -> Result<String, String> {
    let chars: Vec<char> = fmt.chars().collect();
    let mut out = String::with_capacity(fmt.len() * 4);
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        i += 1;
        if c != '%' {
            out.push(c);
            continue;
        }
        let mut key: Option<String> = None;
        if chars.get(i) == Some(&'(') {
            i += 1;
            let start = i;
            let mut depth = 1;
            while i < chars.len() && depth > 0 {
                match chars[i] {
                    ')' => depth -= 1,
                    '(' => depth += 1,
                    _ => {}
                }
                i += 1;
            }
            if depth > 0 {
                return Err("incomplete format key".into());
            }
            key = Some(chars[start..i - 1].iter().collect());
        }
        let mut left = false;
        while let Some(&f) = chars.get(i) {
            match f {
                '-' => left = true,
                '+' | ' ' | '#' | '0' => {}
                _ => break,
            }
            i += 1;
        }
        let mut width = 0usize;
        if chars.get(i) == Some(&'*') {
            return Err("* wants int".into());
        }
        while let Some(d) = chars.get(i).and_then(|c| c.to_digit(10)) {
            width = width.saturating_mul(10).saturating_add(d as usize);
            i += 1;
        }
        let mut prec: Option<usize> = None;
        if chars.get(i) == Some(&'.') {
            i += 1;
            if chars.get(i) == Some(&'*') {
                return Err("* wants int".into());
            }
            let mut p = 0usize;
            while let Some(d) = chars.get(i).and_then(|c| c.to_digit(10)) {
                p = p.saturating_mul(10).saturating_add(d as usize);
                i += 1;
            }
            prec = Some(p);
        }
        while matches!(chars.get(i), Some('h' | 'l' | 'L')) {
            i += 1;
        }
        let Some(&conv) = chars.get(i) else {
            return Err("incomplete format".into());
        };
        i += 1;
        let text = match conv {
            '%' => {
                out.push('%');
                continue;
            }
            's' | 'r' | 'c' => {
                let Some(k) = &key else {
                    return Err(format!("unsupported unkeyed %{conv} conversion"));
                };
                let Some(v) = lookup(k) else {
                    return Err(format!("KeyError: {k:?}"));
                };
                match conv {
                    's' => v,
                    'r' => pychar::repr_str(&v),
                    _ => {
                        if v.chars().count() != 1 {
                            return Err("%c requires int or char".into());
                        }
                        v
                    }
                }
            }
            'a' => return Err("unsupported %a conversion".into()),
            'd' | 'i' | 'u' | 'o' | 'x' | 'X' | 'e' | 'E' | 'f' | 'F' | 'g' | 'G' => {
                return Err(format!("%{conv} format: a real number is required"));
            }
            c => return Err(format!("unsupported format character {c:?}")),
        };
        let text: String = match prec {
            Some(p) => text.chars().take(p).collect(),
            None => text,
        };
        let n = text.chars().count();
        if left {
            out.push_str(&text);
            out.extend(std::iter::repeat_n(' ', width.saturating_sub(n)));
        } else {
            out.extend(std::iter::repeat_n(' ', width.saturating_sub(n)));
            out.push_str(&text);
        }
    }
    Ok(out)
}

/// `(name, regex)` of a date pattern: `fmt % names`, `fmt % timeRE`.
pub(crate) fn expand_pattern(pattern: &str, tre: &TimeRe) -> Result<(String, String), String> {
    let fmt = to_format(pattern);
    let name = percent_format(&fmt, &|k| name_of(k).map(str::to_string))?;
    let regex = percent_format(&fmt, &|k| tre.regex(k).map(str::to_string))?;
    Ok((name, regex))
}

// ---------------------------------------------------------------------------
// Time zones
// ---------------------------------------------------------------------------

static FIXED_OFFSET_TZ_RE: LazyLock<PyRegex> = LazyLock::new(|| {
    compile_py_regex(r"\A([A-Z](?:[A-Z]{2,4})?)?([+-][01]\d(?::?\d{2})?)?$")
        .unwrap_or_else(|e| unreachable!("static pattern: {e}"))
});

/// Upstream `TZ_ABBR_OFFS` (abbreviation -> minutes east of UTC).
static TZ_ABBR_OFFS: LazyLock<HashMap<&'static str, i64>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    for line in TZ_STR.lines() {
        let mut it = line.split_whitespace();
        let Some(off) = it.next().and_then(|o| o.parse::<f64>().ok()) else {
            continue;
        };
        let minutes = (off * 60.0).trunc() as i64;
        for tz in it {
            m.insert(tz, minutes);
        }
    }
    m
});

fn abbr_offset(tz: Option<&str>) -> PyResult<i64> {
    match tz {
        None | Some("") => Ok(0),
        Some(t) => TZ_ABBR_OFFS.get(t).copied().ok_or(PyExc::Key),
    }
}

/// `validateTimeZone(tz)`: minutes east of UTC. `ValueError` for text that is
/// not `[ABBR][+-hh[:mm]]`, `KeyError` for an unknown abbreviation.
pub(crate) fn validate_time_zone(tz: &str) -> PyResult<i64> {
    let Some(c) = FIXED_OFFSET_TZ_RE.search(tz, 0) else {
        return Err(PyExc::Value);
    };
    let g = |i: usize| c[i].map(|(s, e)| &tz[s..e]);
    zone2offset(g(1), g(2))
}

fn zone2offset(abbr: Option<&str>, tzo: Option<&str>) -> PyResult<i64> {
    let tzo = match tzo {
        None | Some("") => return abbr_offset(abbr),
        Some(t) => t,
    };
    let t: Vec<char> = tzo.chars().collect();
    let base = abbr_offset(abbr)?;
    let int = |s: &[char]| -> PyResult<i64> {
        let s: String = s.iter().collect();
        py_int(&s)
            .and_then(|v| i64::try_from(v).ok())
            .ok_or(PyExc::Value)
    };
    if t.len() <= 3 {
        return Ok(base + int(&t)? * 60);
    }
    let sign = if t[0] == '-' { -1 } else { 1 };
    let (mm_from, mm_to) = if t[3] == ':' { (4, 6) } else { (3, 5) };
    let hh = int(&t[1..3])?;
    let mm = int(t.get(mm_from..mm_to.min(t.len())).unwrap_or(&[]))?;
    Ok(base + sign * (hh * 60 + mm))
}

// ---------------------------------------------------------------------------
// reGroupDictStrptime
// ---------------------------------------------------------------------------

const A_MONTH: [&str; 13] = [
    "", "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
];
const F_MONTH: [&str; 13] = [
    "",
    "january",
    "february",
    "march",
    "april",
    "may",
    "june",
    "july",
    "august",
    "september",
    "october",
    "november",
    "december",
];
const A_WEEKDAY: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
const F_WEEKDAY: [&str; 7] = [
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
];

fn index_of(list: &[&str], val: &str) -> PyResult<i128> {
    let low = val.to_lowercase();
    list.iter()
        .position(|x| *x == low)
        .map(|i| i as i128)
        .ok_or(PyExc::Value)
}

fn int(val: &str) -> PyResult<i128> {
    py_int(val).ok_or(PyExc::Value)
}

/// Python `datetime` C-int argument conversion.
fn c_int(v: i128) -> PyResult<i64> {
    i32::try_from(v).map(i64::from).map_err(|_| PyExc::Overflow)
}

/// `date(year, 1, 1).toordinal()` (days since 0001-01-01, plus one).
fn toordinal_jan1(year: i128) -> PyResult<i64> {
    let y = c_int(year)?;
    if !(1..=9999).contains(&y) {
        return Err(PyExc::Value);
    }
    Ok(days_from_civil(y, 1, 1) + 719_163)
}

/// `_strptime._calc_julian_from_U_or_W`.
fn calc_julian(
    year: i128,
    week_of_year: i128,
    day_of_week: i128,
    week_starts_mon: bool,
) -> PyResult<i128> {
    let y = c_int(year)?;
    if !(1..=9999).contains(&y) {
        return Err(PyExc::Value);
    }
    let mut first_weekday = i128::from(weekday(days_from_civil(y, 1, 1)));
    let mut dow = day_of_week;
    if !week_starts_mon {
        first_weekday = (first_weekday + 1) % 7;
        dow = (dow + 1).rem_euclid(7);
    }
    let week_0_length = (7 - first_weekday).rem_euclid(7);
    if week_of_year == 0 {
        Ok(1 + dow - first_weekday)
    } else {
        let days_to_week = week_0_length
            .checked_add(
                week_of_year
                    .checked_sub(1)
                    .and_then(|w| w.checked_mul(7))
                    .ok_or(PyExc::Overflow)?,
            )
            .ok_or(PyExc::Overflow)?;
        Ok(1 + days_to_week + dow)
    }
}

/// Inputs of [`group_dict_to_time`] that come from the detector.
pub(crate) struct TimeCtx<'a> {
    pub zone: &'a LocalZone,
    /// "now" (`MyTime.now()`), evaluated lazily
    pub now: &'a dyn Fn() -> Naive,
    /// the detector's `default_tz` (minutes), if set
    pub default_tz: Option<i64>,
}

/// `reGroupDictStrptime(found_dict, msec=False, default_tz)`: Unix time of the
/// named groups (`(name, value)` in group definition order, `None` value =
/// group did not participate).
pub(crate) fn group_dict_to_time(
    found: &[(&str, Option<&str>)],
    ctx: &TimeCtx<'_>,
) -> PyResult<f64> {
    let mut now: Option<Naive> = None;
    let get_now = |now: &mut Option<Naive>| -> Naive { *now.get_or_insert_with(|| (ctx.now)()) };

    let (mut year, mut month, mut day): (Option<i128>, Option<i128>, Option<i128>) =
        (None, None, None);
    let mut tzoffset: Option<i64> = None;
    let (mut weekday_v, mut julian, mut week_of_year): (Option<i128>, Option<i128>, Option<i128>) =
        (None, None, None);
    let mut week_of_year_start = 0;
    let (mut hour, mut minute, mut second): (i128, i128, i128) = (0, 0, 0);

    for &(key, val) in found {
        let Some(val) = val else { continue };
        match key {
            "y" => {
                let mut y = int(val)?;
                // Fail2ban year should be always in the current century (>= 2000)
                if y <= 2000 {
                    y += 2000;
                }
                year = Some(y);
            }
            "Y" => year = Some(int(val)?),
            "m" => month = Some(int(val)?),
            "B" => month = Some(index_of(&F_MONTH, val)?),
            "b" => month = Some(index_of(&A_MONTH, val)?),
            "d" => day = Some(int(val)?),
            "H" => hour = int(val)?,
            "I" => {
                hour = int(val)?;
                // `found_dict.get('p', '').lower()`: a present but unmatched
                // group is None -> AttributeError
                let ampm = match found.iter().find(|(k, _)| *k == "p") {
                    None => String::new(),
                    Some((_, None)) => return Err(PyExc::Attribute),
                    Some((_, Some(p))) => p.to_lowercase(),
                };
                if ampm.is_empty() || ampm == "am" {
                    if hour == 12 {
                        hour = 0;
                    }
                } else if ampm == "pm" && hour != 12 {
                    hour += 12;
                }
            }
            "M" => minute = int(val)?,
            "S" => second = int(val)?,
            "f" => {}
            "A" => weekday_v = Some(index_of(&F_WEEKDAY, val)?),
            "a" => weekday_v = Some(index_of(&A_WEEKDAY, val)?),
            "w" => {
                let mut w = int(val)? - 1;
                if w < 0 {
                    w = 6;
                }
                weekday_v = Some(w);
            }
            "j" => julian = Some(int(val)?),
            "U" | "W" => {
                week_of_year = Some(int(val)?);
                week_of_year_start = if key == "U" { 6 } else { 0 };
            }
            "z" | "Z" => {
                tzoffset = Some(if matches!(val, "Z" | "UTC" | "GMT") {
                    0
                } else {
                    validate_time_zone(val)?
                });
            }
            _ => {}
        }
    }

    // Fail2Ban will assume it's this year
    let mut assume_year = false;
    if year.is_none() {
        year = Some(i128::from(get_now(&mut now).fields().year));
        assume_year = true;
    }
    let mut yr = year.unwrap_or(0);
    if month.is_none() || day.is_none() {
        if julian.is_none()
            && let (Some(w), Some(wd)) = (week_of_year, weekday_v)
        {
            julian = Some(calc_julian(yr, w, wd, week_of_year_start == 0)?);
        }
        if let Some(j) = julian {
            let ord = i128::from(toordinal_jan1(yr)?) + j - 1;
            let ord = c_int(ord)?;
            if !(1..=3_652_059).contains(&ord) {
                return Err(PyExc::Value);
            }
            let (y, m, d) = civil_from_days(ord - 719_163);
            yr = i128::from(y);
            month = Some(i128::from(m));
            day = Some(i128::from(d));
        }
    }

    // Fail2Ban assume today
    let mut assume_today = false;
    if month.is_none() && day.is_none() {
        let f = get_now(&mut now).fields();
        month = Some(i128::from(f.month));
        day = Some(i128::from(f.day));
        assume_today = true;
    }

    // datetime.datetime(year, month, day, hour, minute, second, 0)
    let args = [Some(yr), month, day, Some(hour), Some(minute), Some(second)];
    let mut conv = [0i64; 6];
    for (slot, a) in conv.iter_mut().zip(args) {
        *slot = c_int(a.ok_or(PyExc::Type)?)?;
    }
    let mut date_result = Naive::new(conv[0], conv[1], conv[2], conv[3], conv[4], conv[5])?;

    // Correct timezone if not supplied in the log line
    if tzoffset.is_none() {
        tzoffset = ctx.default_tz;
    }
    if let Some(off) = tzoffset {
        date_result = date_result.add_secs(-off * 60)?;
    }

    if assume_today {
        let n = get_now(&mut now);
        if date_result > n {
            // Rollover at midnight, could mean it's yesterday...
            date_result = date_result.add_secs(-86_400)?;
        }
    }
    if assume_year {
        let n = get_now(&mut now);
        if date_result > n.add_secs(86_400)? {
            // assume last year - also reset month and day as it's not yesterday...
            date_result = date_result.replace_date(conv[0] - 1, conv[1], conv[2])?;
        }
    }

    let tm = if tzoffset.is_some() {
        date_result.secs
    } else {
        ctx.zone.mktime(&date_result)
    };
    Ok(tm as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn year_window_default() {
        let z = LocalZone::utc();
        assert_eq!(ex_year_regex(2026, None, &z), r"(?P<Y>20[012]\d)");
    }

    #[test]
    fn tz_validation() {
        assert_eq!(validate_time_zone("UTC"), Ok(0));
        assert_eq!(validate_time_zone("+0530"), Ok(330));
        assert_eq!(validate_time_zone("CET+01:00"), Ok(120));
        assert_eq!(validate_time_zone(""), Ok(0));
        assert_eq!(validate_time_zone("ABCD"), Err(PyExc::Key));
        assert_eq!(validate_time_zone("UTC+2"), Err(PyExc::Value));
    }
}
