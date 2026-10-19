//! systemd journal backend: port of upstream `fail2ban/server/filtersystemd.py`.
//!
//! Upstream reads the journal through python-systemd's `journal.Reader` (libsystemd). No
//! libsystemd binding is used here: [`JournalReader`] runs `journalctl --output=export` and
//! parses the binary-safe export format ([`parse_export`]) into [`JournalEntry`] values that
//! carry the same typed values python-systemd's default converters produce.
//!
//! | Rust | upstream |
//! |------|----------|
//! | [`JournalMatches`] | `addJournalMatch` / `delJournalMatch` / `getJournalMatch` (+ libsystemd `sd_journal_add_match` validation) |
//! | [`format_journal_entry`], [`format_journal_entry_with`] | `formatJournalEntry` + `getJrnEntTime` |
//! | [`JournalOptions::resolve`] | `_getJournalArgs` / `_globJournalFiles` |
//! | [`JournalReader`] | `journal.Reader` + the read loop of `FilterSystemd.run` |
//! | [`parse_export`], [`convert_field`] | `Reader.get_next()` / `DEFAULT_CONVERTERS` |
//!
//! Behaviour is verified against the real upstream `FilterSystemd` driven with a stubbed
//! `systemd` module (`tools/dump_journal_oracle.py`, fixtures in `tests/fixtures/`).
//!
//! # Differences from upstream
//!
//! * `journalctl`, not libsystemd: only options `journalctl` can express are supported
//!   ([`ResolvedJournal::to_journalctl_args`]); the `journalctl` command line itself could not
//!   be exercised against a real journal while developing this module.
//! * `systemd-path` is not executed; [`SystemdPaths::default`] holds the compiled-in values.
//! * `datetime` conversion errors (`OverflowError` for timestamps beyond `time_t`) and Python
//!   integers beyond `i128` in non-decimal notation are not modelled; see [`JournalValue`].
//! * [`LogEncoding`] supports UTF-8, ASCII and Latin-1 codecs only.
//! * python-systemd <= 234 and 235 render timestamps differently; both are supported, see
//!   [`TimestampStyle`].

mod entry;
mod export;
mod format;
mod matches;
mod options;
mod pyint;
mod reader;

pub use entry::{JournalEntry, JournalValue, convert_field};
pub use export::{ExportEntries, parse_export};
pub use format::{
    FormatError, FormattedEntry, LogEncoding, TimestampStyle, format_journal_entry,
    format_journal_entry_with,
};
pub use matches::{JournalMatches, MatchError, is_valid_match, join_match};
pub use options::{
    ALL_NAMESPACES, CURRENT_USER, INCLUDE_DEFAULT_NAMESPACE, JournalError, JournalOptions,
    LOCAL_ONLY, OS_ROOT, RUNTIME_ONLY, ResolvedJournal, SYSTEM_ONLY, SystemdPaths, effective_uid,
    glob_journal_files, parse_flags,
};
pub use reader::{JournalReader, journalctl_args};
