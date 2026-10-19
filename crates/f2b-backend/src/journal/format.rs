//! `FilterSystemd.formatJournalEntry` + `getJrnEntTime`: journal entry -> syslog-style line.

use std::fmt::{self, Write as _};

use f2b_date::LocalZone;
use f2b_helpers::pychar::repr_str;

use super::entry::{JournalEntry, JournalValue};
use super::pyint::{Magnitude, parse_int};

/// How python-systemd turns a journal timestamp into a `datetime`, which decides the text of
/// `date.isoformat()`.
#[derive(Debug, Clone, Copy)]
pub enum TimestampStyle<'a> {
    /// python-systemd <= 234: `datetime.fromtimestamp(t)`, a naive datetime in the process zone;
    /// `isoformat()` has no UTC offset (`2024-05-17T12:30:45.123456`).
    NaiveLocal(&'a LocalZone),
    /// python-systemd 235 (current): `datetime.fromtimestamp(t, tz)` where `tz` is the
    /// **fixed** UTC offset (seconds) the process zone had when python-systemd was imported;
    /// `isoformat()` ends in the offset (`2024-05-17T12:30:45.123456+02:00`). The offset is *not*
    /// re-evaluated per entry, so entries from the other half of the DST year carry the offset
    /// of the import time.
    FixedOffset(i32),
}

/// Result of formatting one entry: the `(pre, date, post)` line tuple and the Posix time that
/// upstream hands to `processLineAndAdd`.
#[derive(Debug, Clone, PartialEq)]
pub struct FormattedEntry {
    /// `logline[:0]`: always empty.
    pub pre: String,
    /// `date.isoformat() + ' '`.
    pub date: String,
    /// The log line, newlines escaped as `\n`.
    pub post: String,
    /// `date.timestamp()`.
    ///
    /// For naive local datetimes this is the true epoch time of the entry
    /// (`secs + micro / 1e6`). Python's `datetime.timestamp()` of a naive datetime gives the
    /// same value on the interpreters checked (fold-aware), including for the repeated hour at
    /// a DST fall-back.
    pub time: f64,
}

/// Why an entry cannot be formatted: the conditions under which upstream's
/// `formatJournalEntry` raises (and the filter loop logs "Caught unhandled exception").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatError {
    /// The log encoding is not one of the supported codecs.
    UnknownEncoding(String),
    /// A field has a type upstream cannot handle (e.g. a repeated `_HOSTNAME`, a
    /// `_SOURCE_MONOTONIC_TIMESTAMP` that is not a timedelta, a timestamp that is not a datetime,
    /// or no timestamp at all).
    BadField(&'static str),
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownEncoding(e) => write!(f, "unsupported log encoding {e:?}"),
            Self::BadField(name) => write!(f, "journal field {name} has an unusable type"),
        }
    }
}

impl std::error::Error for FormatError {}

/// Text codecs for `uni_decode(bytes, enc)`: the encodings a journal log line can sensibly use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogEncoding {
    Utf8,
    Ascii,
    Latin1,
}

impl LogEncoding {
    /// Look a Python codec name up (`utf-8`, `utf8`, `ascii`, `latin-1`, `iso-8859-1`, ... in any
    /// case, `-`/`_`/space interchangeable). `auto` means the locale's preferred encoding, taken
    /// as UTF-8. Other codecs are unsupported.
    pub fn from_name(name: &str) -> Option<Self> {
        let norm: String = name
            .trim()
            .chars()
            .map(|c| match c {
                '-' | ' ' => '_',
                c => c.to_ascii_lowercase(),
            })
            .collect();
        match norm.as_str() {
            "utf_8" | "utf8" | "u8" | "utf" | "utf8_ucs2" | "utf8_ucs4" | "cp65001" | "auto" => {
                Some(Self::Utf8)
            }
            "ascii" | "us_ascii" | "646" | "ansi_x3.4_1968" | "ansi_x3_4_1968" | "iso646_us"
            | "iso_646.irv_1991" | "iso_ir_6" | "cp367" | "ibm367" | "us" => Some(Self::Ascii),
            "latin_1" | "latin1" | "latin" | "l1" | "iso_8859_1" | "iso8859_1" | "8859"
            | "cp819" | "ibm819" | "iso_ir_100" | "iso8859" => Some(Self::Latin1),
            _ => None,
        }
    }

    /// `bytes.decode(enc, 'strict')`, falling back to `'replace'` for the whole value like
    /// `helpers.uni_decode`.
    pub fn decode(self, bytes: &[u8]) -> String {
        match self {
            Self::Utf8 => String::from_utf8_lossy(bytes).into_owned(),
            Self::Ascii => bytes
                .iter()
                .map(|&b| if b < 0x80 { char::from(b) } else { '\u{fffd}' })
                .collect(),
            Self::Latin1 => bytes.iter().map(|&b| char::from(b)).collect(),
        }
    }
}

/// Python `repr()` of `bytes`.
fn repr_bytes(b: &[u8]) -> String {
    let quote = if b.contains(&b'\'') && !b.contains(&b'"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(b.len() + 3);
    out.push('b');
    out.push(quote);
    for &c in b {
        match c {
            b'\\' => out.push_str("\\\\"),
            b'\t' => out.push_str("\\t"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            c if char::from(c) == quote => {
                out.push('\\');
                out.push(quote);
            }
            0x20..=0x7e => out.push(char::from(c)),
            c => {
                let _ = write!(out, "\\x{c:02x}");
            }
        }
    }
    out.push(quote);
    out
}

/// Python `repr()` of the values a pid field can hold (`int`, `bytes`, `str`, lists thereof).
/// Other variants cannot occur in `SYSLOG_PID`/`_PID` (their converters yield int or bytes) and
/// are rendered in a Python-like but not exact way.
fn repr_value(v: &JournalValue) -> String {
    match v {
        JournalValue::Text(s) => repr_str(s),
        JournalValue::Bytes(b) => repr_bytes(b),
        JournalValue::Int(i) => i.to_string(),
        JournalValue::BigInt(s) => s.clone(),
        JournalValue::List(l) => {
            let items: Vec<String> = l.iter().map(repr_value).collect();
            format!("[{}]", items.join(", "))
        }
        JournalValue::Uuid(u) => format!("UUID('{u:032x}')"),
        JournalValue::Timestamp(us) => format!("datetime.datetime(<{us}us>)"),
        JournalValue::Duration(us) => format!("datetime.timedelta(microseconds={us})"),
        JournalValue::Monotonic { micros, .. } => format!("({micros}us, UUID)"),
    }
}

/// `"%s" % v`.
fn str_value(v: &JournalValue) -> String {
    match v {
        JournalValue::Text(s) => s.clone(),
        other => repr_value(other),
    }
}

/// `uni_decode(v, enc)` for a field that must end up a string (later `" ".join(...)`).
fn decode_str(
    v: &JournalValue,
    enc: LogEncoding,
    field: &'static str,
) -> Result<String, FormatError> {
    match v {
        JournalValue::Text(s) => Ok(s.clone()),
        JournalValue::Bytes(b) => Ok(enc.decode(b)),
        _ => Err(FormatError::BadField(field)),
    }
}

/// `"[%i]" % v`, then `"[%i]" % int(v, 0)`, then `"[%s]" % v`.
fn format_pid(v: &JournalValue) -> String {
    match v {
        JournalValue::Int(i) => return format!("[{i}]"),
        JournalValue::BigInt(s) => return format!("[{s}]"),
        JournalValue::Bytes(b) => {
            if let Some(n) = parse_int(b, 0) {
                return format!("[{}]", py_int_text(&n));
            }
        }
        JournalValue::Text(s) => {
            if s.is_ascii()
                && let Some(n) = parse_int(s.as_bytes(), 0)
            {
                return format!("[{}]", py_int_text(&n));
            }
        }
        _ => {}
    }
    format!("[{}]", str_value(v))
}

fn py_int_text(p: &super::pyint::ParsedInt) -> String {
    let digits = match &p.magnitude {
        Magnitude::Fits(m) => m.to_string(),
        Magnitude::Huge(d) => d.clone(),
    };
    if p.negative && digits != "0" {
        format!("-{digits}")
    } else {
        digits
    }
}

/// `datetime.fromtimestamp(us / 1e6[, tz])` as Python computes it: float division, then the
/// fractional part is rounded half-even to microseconds.
fn split_python_timestamp(us: i64) -> (i64, i64) {
    let t = us as f64 / 1e6;
    let int_part = t.trunc();
    let mut frac = ((t - int_part) * 1e6).round_ties_even();
    let mut secs = int_part;
    if frac >= 1e6 {
        frac -= 1e6;
        secs += 1.0;
    } else if frac < 0.0 {
        frac += 1e6;
        secs -= 1.0;
    }
    (secs as i64, frac as i64)
}

/// `(isoformat(), timestamp())` of a datetime built from `micros`.
fn date_parts(micros: i64, style: TimestampStyle<'_>) -> (String, f64) {
    let (secs, micro) = split_python_timestamp(micros);
    let (f, offset) = match style {
        TimestampStyle::NaiveLocal(zone) => {
            let f = zone.local_fields(secs as f64);
            ((f.year, f.month, f.day, f.hour, f.minute, f.second), None)
        }
        TimestampStyle::FixedOffset(off) => (civil_from_unix(secs + i64::from(off)), Some(off)),
    };
    let mut iso = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        f.0, f.1, f.2, f.3, f.4, f.5
    );
    if micro != 0 {
        let _ = write!(iso, ".{micro:06}");
    }
    let time = match offset {
        None => secs as f64 + micro as f64 / 1e6,
        // aware datetime: (dt - epoch).total_seconds() = exact microseconds / 1e6
        Some(_) => (secs * 1_000_000 + micro) as f64 / 1e6,
    };
    if let Some(off) = offset {
        let sign = if off < 0 { '-' } else { '+' };
        let a = off.unsigned_abs();
        let (h, m, s) = (a / 3600, a % 3600 / 60, a % 60);
        let _ = write!(iso, "{sign}{h:02}:{m:02}");
        if s != 0 {
            let _ = write!(iso, ":{s:02}");
        }
    }
    (iso, time)
}

/// Proleptic Gregorian civil date/time of a Unix time (no zone).
fn civil_from_unix(secs: i64) -> (i64, i64, i64, i64, i64, i64) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Howard Hinnant's civil_from_days
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, rem / 3600, rem % 3600 / 60, rem % 60)
}

/// `getJrnEntTime`: `_SOURCE_REALTIME_TIMESTAMP`, else `__REALTIME_TIMESTAMP`.
fn entry_time(
    entry: &JournalEntry,
    style: TimestampStyle<'_>,
) -> Result<(String, f64), FormatError> {
    let (name, v) = match entry.get("_SOURCE_REALTIME_TIMESTAMP") {
        Some(v) => ("_SOURCE_REALTIME_TIMESTAMP", v),
        None => match entry.get("__REALTIME_TIMESTAMP") {
            Some(v) => ("__REALTIME_TIMESTAMP", v),
            None => return Err(FormatError::BadField("__REALTIME_TIMESTAMP")),
        },
    };
    match v {
        JournalValue::Timestamp(us) => Ok(date_parts(*us, style)),
        _ => Err(FormatError::BadField(name)),
    }
}

/// Format an entry like upstream, with python-systemd <= 234 style naive local timestamps in
/// `zone`. See [`format_journal_entry_with`] for the python-systemd 235 style.
pub fn format_journal_entry(
    entry: &JournalEntry,
    log_encoding: &str,
    zone: &LocalZone,
) -> Result<FormattedEntry, FormatError> {
    format_journal_entry_with(entry, log_encoding, TimestampStyle::NaiveLocal(zone))
}

/// `FilterSystemd.formatJournalEntry` + `getJrnEntTime`.
///
/// Errors where upstream raises an exception (see [`FormatError`]).
pub fn format_journal_entry_with(
    entry: &JournalEntry,
    log_encoding: &str,
    style: TimestampStyle<'_>,
) -> Result<FormattedEntry, FormatError> {
    let enc = LogEncoding::from_name(log_encoding)
        .ok_or_else(|| FormatError::UnknownEncoding(log_encoding.to_owned()))?;
    let mut elements: Vec<String> = Vec::new();
    if let Some(v) = entry.get("_HOSTNAME").filter(|v| v.is_truthy()) {
        elements.push(decode_str(v, enc, "_HOSTNAME")?);
    }
    let ident = entry
        .get("SYSLOG_IDENTIFIER")
        .filter(|v| v.is_truthy())
        .map(|v| ("SYSLOG_IDENTIFIER", v))
        .or_else(|| entry.get("_COMM").map(|v| ("_COMM", v)));
    if let Some((name, v)) = ident.filter(|(_, v)| v.is_truthy()) {
        let mut text = decode_str(v, enc, name)?;
        let pid = entry
            .get("SYSLOG_PID")
            .filter(|v| v.is_truthy())
            .or_else(|| entry.get("_PID"));
        if let Some(pid) = pid.filter(|v| v.is_truthy()) {
            text.push_str(&format_pid(pid));
        }
        text.push(':');
        let kernel = text == "kernel:";
        elements.push(text);
        if kernel {
            let micros = match entry.get("_SOURCE_MONOTONIC_TIMESTAMP") {
                Some(JournalValue::Duration(us)) => *us,
                Some(_) => return Err(FormatError::BadField("_SOURCE_MONOTONIC_TIMESTAMP")),
                None => match entry.get("__MONOTONIC_TIMESTAMP") {
                    Some(JournalValue::Monotonic { micros, .. }) => *micros,
                    _ => return Err(FormatError::BadField("__MONOTONIC_TIMESTAMP")),
                },
            };
            elements.push(format!("[{:12.6}]", micros as f64 / 1e6));
        }
    }
    match entry.get("MESSAGE") {
        None => elements.push(String::new()),
        Some(JournalValue::List(items)) => {
            let parts = items
                .iter()
                .map(|v| decode_str(v, enc, "MESSAGE"))
                .collect::<Result<Vec<_>, _>>()?;
            elements.push(parts.join(" "));
        }
        Some(v) => elements.push(decode_str(v, enc, "MESSAGE")?),
    }
    let line = elements.join(" ");
    let (iso, time) = entry_time(entry, style)?;
    Ok(FormattedEntry {
        pre: String::new(),
        date: iso + " ",
        post: line.replace('\n', "\\n"),
        time,
    })
}
