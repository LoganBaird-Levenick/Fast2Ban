//! Fail2Ban-compatible log line filter.
//!
//! Splits the date off a log line, runs `prefregex` / `failregex` /
//! `ignoreregex`, merges multi-line failures by failure id and expands hosts,
//! reproducing upstream's `Filter.processLine` / `findFailure`.

mod error;
mod failval;
mod filter;
mod process;

pub use error::{FilterError, Result};
pub use failval::{FailData, FailVal};
pub use filter::{FailEntry, Filter, IgnoreCallback};
