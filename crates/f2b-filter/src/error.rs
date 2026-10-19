//! Errors of the filter.

use std::fmt;

use f2b_regex::{MatchError, RegexError};
use f2b_types::IPAddrError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterError {
    /// Invalid regex given to the filter (`RegexException` at configuration).
    Regex(RegexError),
    /// A regex matched but its failure id could not be read, or the
    /// backtracking engine failed.
    Match(MatchError),
    /// `IPAddr(...)` rejected a matched address.
    Ip(IPAddrError),
    /// `ValueError` upstream (bad `maxlines`, non-integer `cidr`, ...).
    Value(String),
    /// A line was processed without a date detector and without a given date.
    NoDateDetector,
}

impl fmt::Display for FilterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Regex(e) => e.fmt(f),
            Self::Match(e) => e.fmt(f),
            Self::Ip(e) => e.fmt(f),
            Self::Value(m) => f.write_str(m),
            Self::NoDateDetector => f.write_str("'NoneType' object has no attribute 'matchTime'"),
        }
    }
}

impl std::error::Error for FilterError {}

impl From<RegexError> for FilterError {
    fn from(e: RegexError) -> Self {
        Self::Regex(e)
    }
}

impl From<MatchError> for FilterError {
    fn from(e: MatchError) -> Self {
        Self::Match(e)
    }
}

impl From<IPAddrError> for FilterError {
    fn from(e: IPAddrError) -> Self {
        Self::Ip(e)
    }
}

pub type Result<T> = std::result::Result<T, FilterError>;
