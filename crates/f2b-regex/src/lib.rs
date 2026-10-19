//! Fail2Ban's failregex layer (`server/failregex.py`) for Fast2Ban.
//!
//! * [`Regex`] / [`FailRegex`]: tag expansion (`<HOST>`, `<F-USER>`, `<SKIPLINES>`...),
//!   compile once, search, upstream-style group dictionaries and multi-line bookkeeping.
//! * [`translate`]: Python `re` pattern -> Rust syntax, with the dual-engine selection
//!   (linear `regex` crate, `fancy-regex` fallback). See its module docs for the rules.

//!
//! # Deviations from Python's `re` (documented, deliberate)
//!
//! * **Backtracking budget**: patterns on `fancy-regex` run with a step limit
//!   ([`DEFAULT_BACKTRACK_LIMIT`]); exceeding it makes `search*` return
//!   [`MatchError::BacktrackLimit`]. Callers treat that as "no match for this
//!   buffer" and log it (ReDoS guard; Python has no limit). Likewise a panic
//!   inside `fancy-regex` is surfaced as [`MatchError::Engine`].
//! * A repeated body that can match the empty string (`(a*)*`-style) may report
//!   different captures for the last empty iteration than Python.
//! * Huge repeat counts (`a{4294967294}`) are accepted by Python but exceed the
//!   engine size limit here ([`RegexError::Engine`]).
//! * Prefix lengths of a `cidr` group beyond `u32` saturate.
//! * `\N{NAME}` uses the `unicode_names2` database (Unicode version may differ).
//!
//! Everything else (construction errors with Python's messages, `getRegex()`
//! text, spans, group dictionaries, multi-line bookkeeping) is checked against
//! upstream by the oracle tests in `tests/`.

mod charset;
mod error;
mod groups;
mod pyast;
mod pyparse;
mod regex;
mod tags;
pub mod translate;

pub use error::{MatchError, PyReError, RegexError};
pub use groups::{GroupValue, Groups, TupleLine, tuple_lines_buf};
pub use regex::{
    DEFAULT_BACKTRACK_LIMIT, FAILURE_ID_GROUPS, FAILURE_ID_PRESENT, FailRegex, Match, Merge, Regex,
    RegexOptions,
};
pub use tags::{UseDns, global_to_local_flags, map_tag_to_option, resolve_host_tag};
pub use translate::{EngineKind, Gate, Translated};
