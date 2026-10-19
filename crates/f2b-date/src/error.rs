use std::fmt;

/// Errors of date pattern / time zone handling and of time evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DateError {
    /// The date pattern is invalid (upstream: `re.error` or the `TypeError`
    /// "Failed to set datepattern ...").
    Pattern { pattern: String, message: String },
    /// A template with the same name is already present (upstream `ValueError`).
    DuplicateTemplate(String),
    /// Invalid log time zone (`validateTimeZone`: `ValueError` "Unknown or
    /// unsupported time zone", or `KeyError` for an unknown abbreviation).
    TimeZone(String),
    /// An exception other than `ValueError` escaped upstream's `getTime`
    /// (`ValueError` means "no date" and is not an error here).
    Time(TimeError),
}

/// Python exception class raised while evaluating a matched date.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeError {
    /// `TypeError` (e.g. only one of month/day matched, `float(None)`)
    Type,
    /// `KeyError` (unknown zone abbreviation such as `%Z` = `ERROR`)
    Key,
    /// `IndexError` (an `{EPOCH}` template without the expected group)
    Index,
    /// `OverflowError` (date arithmetic beyond year 1..9999, huge integers)
    Overflow,
    /// `AttributeError` (`%I` with a non-participating `%p` group)
    Attribute,
}

impl TimeError {
    /// The Python exception class name.
    pub fn python_name(self) -> &'static str {
        match self {
            Self::Type => "TypeError",
            Self::Key => "KeyError",
            Self::Index => "IndexError",
            Self::Overflow => "OverflowError",
            Self::Attribute => "AttributeError",
        }
    }
}

impl fmt::Display for DateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pattern { pattern, message } => {
                write!(f, "invalid date pattern {pattern:?}: {message}")
            }
            Self::DuplicateTemplate(name) => {
                write!(f, "There is already a template with name {name}")
            }
            Self::TimeZone(tz) => write!(f, "Unknown or unsupported time zone: {tz:?}"),
            Self::Time(e) => write!(f, "{} while evaluating a date", e.python_name()),
        }
    }
}

impl std::error::Error for DateError {}
