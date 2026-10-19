//! Ports of the config-parsing helpers of upstream `fail2ban/helpers.py`, plus Python's
//! `shlex.split`.
//!
//! | Rust | Python |
//! |------|--------|
//! | [`as_bool`] | `_as_bool` (string case) |
//! | [`remove_comments`], [`splitwords`] | `removeComments`, `splitwords` |
//! | [`merge_dicts`] | `_merge_dicts` |
//! | [`extract_options`], [`split_with_options`] | `extractOptions`, `splitWithOptions` |
//! | [`substitute_recursive_tags`] | `substituteRecursiveTags` |
//! | [`shlex_split`] | `shlex.split` |
//!
//! Behaviour is verified against the upstream Python functions with fixtures generated
//! by `tools/gen_f2b_helpers_fixtures.py` (`testdata/f2b-helpers/`).
//!
//! # Maps and order
//!
//! Option and tag maps are [`indexmap::IndexMap`]: Python `dict` iteration order decides
//! the order of upstream's command stream, so insertion order is preserved and updating
//! an existing key keeps its position.
//!
//! # Differences from Python (by design)
//!
//! * Values are always Rust `str`; upstream's `uni_string` (bytes decoding) and
//!   `None`-tolerant `splitwords(None)` have no counterpart.
//! * `substituteRecursiveTags` does not support callable `CallingMap` values
//!   (`getRawItem`); see [`substitute_recursive_tags`].
//! * Python `re` classes (`\s`, `\w`) and `repr()` use Python 3.14's Unicode 16.0
//!   tables, embedded in the crate, so results do not depend on the Rust toolchain's
//!   Unicode version.
//! * Python strings may contain lone surrogates; Rust strings cannot.
//! * The regular expressions are executed by hand-written matchers, not by a regex
//!   engine. Pathological inputs that make Python's engine backtrack exponentially
//!   behave the same way here (slow), which cannot happen with sane configuration.

mod options;
pub mod pychar;
mod shlex;
mod tags;
mod words;

pub use options::{OptionError, extract_options, split_with_options};
pub use shlex::{ShlexError, shlex_split};
pub use tags::{AddRepl, MAX_TAG_REPLACE_COUNT, TagError, substitute_recursive_tags};
pub use words::{as_bool, merge_dicts, remove_comments, splitwords};
