//! Error types.

use std::error::Error;
use std::fmt;

use f2b_types::IPAddrError;

pub use crate::pyparse::PyReError;

/// Construction failure (`RegexException` of upstream's `failregex.py`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegexError {
    /// `Cannot add empty regex`: the expanded regex is empty or whitespace.
    Empty,
    /// `re.compile` rejected the regex (`Unable to compile regular
    /// expression`). Also covers Python's `OverflowError` for huge repeat
    /// counts, which upstream does not turn into a `RegexException`.
    Compile {
        /// The expanded regex.
        regex: String,
        /// What Python's `re` reports.
        error: PyReError,
    },
    /// A [`crate::FailRegex`] without any `fid`/`ip4`/`ip6`/`dns`/`mlfid`
    /// group (`No failure-id group`).
    NoFailureId {
        /// The expanded regex.
        regex: String,
    },
    /// Python accepts the regex but the Rust engine could not build it
    /// (compiled size limit, nesting limit). Not an upstream condition.
    Engine {
        /// The expanded regex.
        regex: String,
        /// Engine message.
        message: String,
    },
}

impl fmt::Display for RegexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegexError::Empty => f.write_str("Cannot add empty regex"),
            RegexError::Compile { regex, error } => write!(
                f,
                "Unable to compile regular expression '{regex}':\n{error}"
            ),
            RegexError::NoFailureId { regex } => {
                write!(f, "No failure-id group in '{regex}'")
            }
            RegexError::Engine { regex, message } => write!(
                f,
                "Unable to compile regular expression '{regex}':\n{message}"
            ),
        }
    }
}

impl Error for RegexError {}

/// Failure while matching or reading a match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MatchError {
    /// `getFailID` found none of the requested groups set (upstream raises
    /// `RegexException`).
    NoFailId {
        /// The searched buffer.
        buf: String,
        /// `str(compiled pattern)`.
        pattern: String,
    },
    /// The address text is not accepted by `IPAddr`.
    Ip(IPAddrError),
    /// The `cidr` group is not usable as the `int(...)` argument of `IPAddr`
    /// (not an integer, a tuple, or a negative value other than the `CIDR_*`
    /// constants).
    BadCidr,
    /// The backtracking engine exceeded its step limit on this buffer.
    ///
    /// Python's `re` has no such limit (and would run for as long as the
    /// pattern takes). Treat it as "no match for this buffer" and log it: it
    /// means the buffer is adversarial for a pattern that needs backtracking.
    BacktrackLimit,
    /// Any other runtime failure of the backtracking engine, or failure to
    /// build the exact engine for a buffer outside the primary engine's gate.
    Engine(String),
}

impl fmt::Display for MatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MatchError::NoFailId { buf, pattern } => {
                write!(f, "No group found in '{buf}' using '{pattern}'")
            }
            MatchError::Ip(e) => e.fmt(f),
            MatchError::BadCidr => f.write_str("int() argument must be a string or a number"),
            MatchError::BacktrackLimit => f.write_str("regex backtracking limit exceeded"),
            MatchError::Engine(m) => f.write_str(m),
        }
    }
}

impl Error for MatchError {}

impl From<IPAddrError> for MatchError {
    fn from(e: IPAddrError) -> MatchError {
        MatchError::Ip(e)
    }
}
