//! Typed journal entries, mirroring the Python objects python-systemd's `Reader.get_next()`
//! hands to Fail2Ban (`journal.DEFAULT_CONVERTERS` plus fail2ban's `__CURSOR` override).

use indexmap::IndexMap;

use super::pyint::{Magnitude, ParsedInt, parse_int};

/// Smallest and largest Unix time (seconds) whose `datetime` year is within 1..=9999.
const MIN_DATETIME_SECS: i64 = -62_135_596_800;
const MAX_DATETIME_SECS: i64 = 253_402_300_799;

/// One field value of a journal entry, as python-systemd presents it.
#[derive(Debug, Clone, PartialEq)]
pub enum JournalValue {
    /// `str`: the default conversion (`bytes.decode()`, UTF-8) succeeded.
    Text(String),
    /// `bytes`: the field is not UTF-8 (or a converter raised `ValueError`, which python-systemd
    /// answers by returning the raw bytes), or the field is `COREDUMP`.
    Bytes(Vec<u8>),
    /// `int` (integer converters: `_PID`, `SYSLOG_PID`, `PRIORITY`, ...).
    Int(i128),
    /// `int` beyond `i128`: canonical decimal text with optional leading `-`.
    BigInt(String),
    /// `uuid.UUID` (`MESSAGE_ID`, `_MACHINE_ID`, `_BOOT_ID`): the 128-bit value.
    Uuid(u128),
    /// `datetime.datetime` (`__REALTIME_TIMESTAMP`, `_SOURCE_REALTIME_TIMESTAMP`,
    /// `COREDUMP_TIMESTAMP`): microseconds since the Unix epoch. Python builds a *local* datetime
    /// from it; see [`crate::journal::TimestampStyle`].
    Timestamp(i64),
    /// `datetime.timedelta` (`_SOURCE_MONOTONIC_TIMESTAMP`): microseconds.
    Duration(i64),
    /// `(timedelta, UUID)` (`__MONOTONIC_TIMESTAMP`): microseconds and the boot id of the entry
    /// (`None` if the entry carries no parsable `_BOOT_ID`).
    Monotonic { micros: i64, boot_id: Option<u128> },
    /// A field that occurs more than once (python-systemd returns a `list`).
    List(Vec<JournalValue>),
}

impl JournalValue {
    /// Python truthiness of the converted value.
    pub fn is_truthy(&self) -> bool {
        match self {
            Self::Text(s) => !s.is_empty(),
            Self::Bytes(b) => !b.is_empty(),
            Self::Int(i) => *i != 0,
            Self::Duration(d) => *d != 0,
            Self::List(l) => !l.is_empty(),
            Self::BigInt(_) | Self::Uuid(_) | Self::Timestamp(_) | Self::Monotonic { .. } => true,
        }
    }
}

/// A journal entry: ordered fields; repeated fields are a [`JournalValue::List`].
#[derive(Debug, Clone, Default, PartialEq)]
pub struct JournalEntry {
    fields: IndexMap<String, JournalValue>,
}

impl JournalEntry {
    /// An empty entry.
    pub fn new() -> Self {
        Self::default()
    }

    /// The value of `name`, like `logentry.get(name)`.
    pub fn get(&self, name: &str) -> Option<&JournalValue> {
        self.fields.get(name)
    }

    /// Insert an already converted value (replaces, keeping the position of an existing key).
    pub fn insert(&mut self, name: impl Into<String>, value: JournalValue) {
        self.fields.insert(name.into(), value);
    }

    /// Fields in order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &JournalValue)> {
        self.fields.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Number of distinct field names.
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// `true` if there are no fields.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Build an entry from raw `(name, bytes)` fields in journal order, applying python-systemd's
    /// converters. Repeated names collapse into a [`JournalValue::List`] in order of appearance.
    pub fn from_raw_fields<I>(raw: I) -> Self
    where
        I: IntoIterator<Item = (String, Vec<u8>)>,
    {
        let raw: Vec<(String, Vec<u8>)> = raw.into_iter().collect();
        // the boot id that sd_journal_get_monotonic_usec() reports is the entry's _BOOT_ID
        let boot_id = raw
            .iter()
            .find(|(k, _)| k == "_BOOT_ID")
            .and_then(|(_, v)| match convert_field("_BOOT_ID", v) {
                JournalValue::Uuid(u) => Some(u),
                _ => None,
            });
        let mut grouped: IndexMap<String, Vec<Vec<u8>>> = IndexMap::new();
        for (k, v) in raw {
            grouped.entry(k).or_default().push(v);
        }
        let mut fields = IndexMap::with_capacity(grouped.len());
        for (k, mut values) in grouped {
            let value = if values.len() == 1 {
                convert_field_with_boot(&k, &values.remove(0), boot_id)
            } else {
                JournalValue::List(
                    values
                        .iter()
                        .map(|v| convert_field_with_boot(&k, v, boot_id))
                        .collect(),
                )
            };
            fields.insert(k, value);
        }
        Self { fields }
    }
}

/// python-systemd's `Reader._convert_field` for one raw value.
///
/// `__MONOTONIC_TIMESTAMP` is converted without its boot id here (use
/// [`JournalEntry::from_raw_fields`] for whole entries).
pub fn convert_field(name: &str, raw: &[u8]) -> JournalValue {
    convert_field_with_boot(name, raw, None)
}

fn convert_field_with_boot(name: &str, raw: &[u8], boot_id: Option<u128>) -> JournalValue {
    let bytes = || JournalValue::Bytes(raw.to_vec());
    match name {
        "MESSAGE_ID" | "_MACHINE_ID" | "_BOOT_ID" => {
            parse_uuid(raw).map_or_else(bytes, JournalValue::Uuid)
        }
        "PRIORITY" | "LEADER" | "SESSION_ID" | "USERSPACE_USEC" | "INITRD_USEC" | "KERNEL_USEC"
        | "_UID" | "_GID" | "_PID" | "SYSLOG_FACILITY" | "SYSLOG_PID" | "_AUDIT_SESSION"
        | "_AUDIT_LOGINUID" | "_SYSTEMD_SESSION" | "_SYSTEMD_OWNER_UID" | "CODE_LINE" | "ERRNO"
        | "EXIT_STATUS" | "COREDUMP_PID" | "COREDUMP_UID" | "COREDUMP_GID" | "COREDUMP_SESSION"
        | "COREDUMP_SIGNAL" => parse_int(raw, 10).map_or_else(bytes, py_int_value),
        "_SOURCE_REALTIME_TIMESTAMP" | "COREDUMP_TIMESTAMP" | "__REALTIME_TIMESTAMP" => {
            match small_int(raw) {
                Some(us) if datetime_in_range(us) => JournalValue::Timestamp(us),
                // fromtimestamp() raised ValueError: python-systemd keeps the unconverted value
                // (for `__REALTIME_TIMESTAMP` that is the integer, otherwise the bytes)
                Some(us) if name == "__REALTIME_TIMESTAMP" => JournalValue::Int(i128::from(us)),
                _ => bytes(),
            }
        }
        "_SOURCE_MONOTONIC_TIMESTAMP" => small_int(raw).map_or_else(bytes, JournalValue::Duration),
        "__MONOTONIC_TIMESTAMP" => {
            small_int(raw).map_or_else(bytes, |micros| JournalValue::Monotonic { micros, boot_id })
        }
        "COREDUMP" => bytes(),
        // fail2ban overrides the converter with the identity; the cursor is a `str`
        _ => match std::str::from_utf8(raw) {
            Ok(s) => JournalValue::Text(s.to_owned()),
            Err(_) => bytes(),
        },
    }
}

/// `int(raw)` restricted to `i64` (timestamps; larger values would raise `OverflowError` or
/// `ValueError` in Python and are kept as raw bytes here).
fn small_int(raw: &[u8]) -> Option<i64> {
    match parse_int(raw, 10)? {
        ParsedInt {
            negative,
            magnitude: Magnitude::Fits(m),
        } => {
            if negative {
                i64::try_from(-i128::try_from(m).ok()?).ok()
            } else {
                i64::try_from(m).ok()
            }
        }
        _ => None,
    }
}

fn datetime_in_range(micros: i64) -> bool {
    // float division and rounding cannot move a value across the year 1/9999 limits unless it
    // is within a microsecond of them; the limits are exact for whole seconds
    let secs = micros.div_euclid(1_000_000);
    (MIN_DATETIME_SECS..=MAX_DATETIME_SECS).contains(&secs)
}

fn py_int_value(p: ParsedInt) -> JournalValue {
    match p.magnitude {
        Magnitude::Fits(m) => match i128::try_from(m) {
            Ok(v) => JournalValue::Int(if p.negative { -v } else { v }),
            Err(_) => {
                if p.negative {
                    JournalValue::BigInt(format!("-{m}"))
                } else {
                    JournalValue::BigInt(m.to_string())
                }
            }
        },
        Magnitude::Huge(d) => JournalValue::BigInt(if p.negative { format!("-{d}") } else { d }),
    }
}

/// `uuid.UUID(raw.decode())`.
fn parse_uuid(raw: &[u8]) -> Option<u128> {
    let text = std::str::from_utf8(raw).ok()?;
    let text = text.replace("urn:", "").replace("uuid:", "");
    let text = text.trim_matches(|c| c == '{' || c == '}').replace('-', "");
    if text.chars().count() != 32 {
        return None;
    }
    let p = parse_int(text.as_bytes(), 16)?;
    match p.magnitude {
        Magnitude::Fits(m) if !p.negative || m == 0 => Some(m),
        _ => None,
    }
}
