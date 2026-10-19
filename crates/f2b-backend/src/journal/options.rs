//! Journal source selection: `FilterSystemd._getJournalArgs` / `_globJournalFiles` and the
//! translation of the resulting python-systemd `Reader(...)` arguments to `journalctl` options.

use std::collections::BTreeSet;
use std::ffi::{CString, OsString};
use std::fmt;
use std::io;
use std::path::PathBuf;

use f2b_helpers::splitwords;

use super::pyint::{Magnitude, parse_int};

/// `journal.LOCAL_ONLY` (`SD_JOURNAL_LOCAL_ONLY`).
pub const LOCAL_ONLY: i64 = 1;
/// `journal.RUNTIME_ONLY`.
pub const RUNTIME_ONLY: i64 = 2;
/// `journal.SYSTEM` / `journal.SYSTEM_ONLY`.
pub const SYSTEM_ONLY: i64 = 4;
/// `journal.CURRENT_USER`.
pub const CURRENT_USER: i64 = 8;
/// `journal.OS_ROOT`.
pub const OS_ROOT: i64 = 16;
/// `SD_JOURNAL_ALL_NAMESPACES` (not exported by python-systemd, but passed through as a flag).
pub const ALL_NAMESPACES: i64 = 32;
/// `SD_JOURNAL_INCLUDE_DEFAULT_NAMESPACE`.
pub const INCLUDE_DEFAULT_NAMESPACE: i64 = 64;

/// Errors of option resolution and of the translation to `journalctl` arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalError {
    /// `int()` of a flags value failed (`journalflags` or `F2B_SYSTEMD_DEFAULT_FLAGS`).
    InvalidFlags(String),
    /// python-systemd: "path and files cannot be specified simultaneously".
    PathAndFiles,
    /// `journalfiles` matched nothing while `rotated` is set: python-systemd would open an
    /// empty journal (no entries ever); `journalctl` has no equivalent.
    NoFiles,
    /// A combination `journalctl` cannot express.
    Unsupported(String),
}

impl fmt::Display for JournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFlags(s) => write!(f, "invalid literal for int() with base 10: {s:?}"),
            Self::PathAndFiles => f.write_str("path and files cannot be specified simultaneously"),
            Self::NoFiles => f.write_str(
                "journalfiles matched no file (python-systemd would open an empty journal)",
            ),
            Self::Unsupported(s) => write!(f, "unsupported journal option combination: {s}"),
        }
    }
}

impl std::error::Error for JournalError {}

impl From<JournalError> for io::Error {
    fn from(e: JournalError) -> Self {
        io::Error::new(io::ErrorKind::InvalidInput, e)
    }
}

/// `int(text)` for a flags value.
pub fn parse_flags(text: &str) -> Result<i64, JournalError> {
    let err = || JournalError::InvalidFlags(text.to_owned());
    let p = parse_int(text.as_bytes(), 10).ok_or_else(err)?;
    let Magnitude::Fits(m) = p.magnitude else {
        return Err(err());
    };
    let m = i128::try_from(m).map_err(|_| err())?;
    i64::try_from(if p.negative { -m } else { m }).map_err(|_| err())
}

/// The system paths `_getSystemdPath` resolves with `systemd-path`.
///
/// `systemd-path` is **not** executed; the values are the ones systemd compiles in
/// (`system-state-logs` = `/var/log`, `system-runtime-logs` = `/run/log`), which are also
/// upstream's own fallbacks when `systemd-path` is missing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemdPaths {
    pub system_state_logs: String,
    pub system_runtime_logs: String,
}

impl Default for SystemdPaths {
    fn default() -> Self {
        Self {
            system_state_logs: "/var/log".to_owned(),
            system_runtime_logs: "/run/log".to_owned(),
        }
    }
}

/// The journal-related options of a jail (`journalpath`, `journalfiles`, `journalflags`,
/// `namespace`, `rotated`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JournalOptions {
    /// Directory of journal files (`journalpath`).
    pub journalpath: Option<String>,
    /// File patterns (`journalfiles`, already split like `splitwords`; see
    /// [`JournalOptions::set_journalfiles`]); each is glob-expanded by [`JournalOptions::resolve`].
    pub journalfiles: Option<Vec<String>>,
    /// `journalflags` (python-systemd open flags, see the constants of this module).
    pub journalflags: Option<i64>,
    /// `namespace`.
    pub namespace: Option<String>,
    /// `rotated`: also read rotated journal files.
    pub rotated: bool,
    /// Path of the `journalctl` binary; `None` means `$F2B_JOURNALCTL`, else `journalctl`.
    pub journalctl: Option<PathBuf>,
}

/// The arguments upstream's `_getJournalArgs` produces for `journal.Reader(**args)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedJournal {
    /// `flags` (`None`: python-systemd's default, see [`ResolvedJournal::effective_flags`]).
    pub flags: Option<i64>,
    /// `path` (journal directory).
    pub path: Option<String>,
    /// `files` (sorted; upstream's order is arbitrary).
    pub files: Option<Vec<String>>,
    /// `namespace`.
    pub namespace: Option<String>,
}

impl JournalOptions {
    /// Set `journalfiles` from a config string (`splitwords`).
    pub fn set_journalfiles(&mut self, text: &str) {
        self.journalfiles = Some(splitwords(text, false));
    }

    /// `_getJournalArgs(kwargs)` reading `F2B_SYSTEMD_DEFAULT_FLAGS` from the environment and
    /// using the default [`SystemdPaths`].
    pub fn resolve(&self) -> Result<ResolvedJournal, JournalError> {
        let env = std::env::var("F2B_SYSTEMD_DEFAULT_FLAGS").ok();
        self.resolve_with(env.as_deref(), &SystemdPaths::default())
    }

    /// `_getJournalArgs(kwargs)` with explicit `F2B_SYSTEMD_DEFAULT_FLAGS` and system paths.
    ///
    /// Differences: the `files` list is sorted (upstream: arbitrary set order), unreadable files
    /// are always dropped for non-root users like upstream, and `**` in a pattern is
    /// recursive (the `glob` crate; Python's `glob()` without `recursive` treats it as `*`).
    pub fn resolve_with(
        &self,
        default_flags_env: Option<&str>,
        paths: &SystemdPaths,
    ) -> Result<ResolvedJournal, JournalError> {
        let mut path = self.journalpath.clone();
        let mut files: Option<Vec<String>> = self.journalfiles.as_ref().map(|patterns| {
            let set: BTreeSet<String> = patterns.iter().flat_map(|p| glob_paths(p)).collect();
            set.into_iter().collect()
        });
        let path_truthy = path.as_deref().is_some_and(|p| !p.is_empty());
        let mut files_truthy = files.as_ref().is_some_and(|f| !f.is_empty());
        // `flags` key present in upstream's args dict (distinct from "absent" for the
        // `args.get('flags', LOCAL_ONLY)` below)
        let mut flags_key = false;
        let mut flags = None;
        if let Some(f) = self.journalflags {
            flags_key = true;
            flags = Some(f);
        } else if !files_truthy && !path_truthy {
            flags_key = true;
            flags = match default_flags_env {
                Some(env) => Some(parse_flags(env)?),
                None if self.rotated => Some(SYSTEM_ONLY),
                None => None,
            };
        }
        let namespace = self.namespace.clone();
        if !self.rotated && !files_truthy && namespace.as_deref().is_none_or(str::is_empty) {
            let glob_flags = if flags_key { flags } else { Some(LOCAL_ONLY) };
            let globbed =
                glob_journal_files(glob_flags, path.as_deref().filter(|p| !p.is_empty()), paths);
            match globbed {
                Some(list) => {
                    files = Some(list);
                    files_truthy = true;
                    // flags and path cannot be specified simultaneously with files
                    flags = None;
                    path = None;
                }
                None => files = None,
            }
        }
        let _ = files_truthy;
        Ok(ResolvedJournal {
            flags,
            path,
            files,
            namespace,
        })
    }

    /// The `journalctl` binary: the explicit field, else `$F2B_JOURNALCTL`, else `journalctl`.
    pub fn journalctl_program(&self) -> OsString {
        match &self.journalctl {
            Some(p) => p.clone().into_os_string(),
            None => std::env::var_os("F2B_JOURNALCTL")
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| OsString::from("journalctl")),
        }
    }
}

impl ResolvedJournal {
    /// The flags python-systemd's `Reader.__init__` ends up with: `None` means `LOCAL_ONLY`
    /// without path/files, else `0`.
    pub fn effective_flags(&self) -> i64 {
        self.flags
            .unwrap_or(if self.path.is_none() && self.files.is_none() {
                LOCAL_ONLY
            } else {
                0
            })
    }

    /// `journalctl` options selecting the same journal files as `journal.Reader(**self)`.
    ///
    /// The mapping follows `journalctl(1)` and `sd_journal_open(3)`; combinations that
    /// `journalctl` cannot express (or that libsystemd rejects) are errors:
    ///
    /// | python-systemd | journalctl |
    /// |---|---|
    /// | `files=[...]`, flags 0 | `--file=F` for each file |
    /// | `path=P` | `--directory=P` (`--root=P` with `OS_ROOT`) |
    /// | `SYSTEM_ONLY` / `CURRENT_USER` | `--system` / `--user` |
    /// | no `LOCAL_ONLY` (default/namespace mode) | `--merge` |
    /// | `namespace=N` (`+INCLUDE_DEFAULT_NAMESPACE`) | `--namespace=N` (`+N`) |
    /// | `ALL_NAMESPACES` | `--namespace=*` |
    ///
    /// `RUNTIME_ONLY` has no `journalctl` counterpart. As in python-systemd, `namespace` is
    /// ignored when a path or files are given. [INFERENCE] The flag subsets accepted with
    /// path/files mirror libsystemd's `sd_journal_open_directory/_files` argument checks as
    /// remembered; they could not be verified without libsystemd.
    pub fn to_journalctl_args(&self) -> Result<Vec<String>, JournalError> {
        let flags = self.effective_flags();
        let unsupported = |m: String| Err(JournalError::Unsupported(m));
        let mut args = Vec::new();
        if self.path.is_some() && self.files.is_some() {
            return Err(JournalError::PathAndFiles);
        }
        if let Some(files) = &self.files {
            if flags != 0 {
                return unsupported(format!(
                    "journalfiles cannot be combined with journalflags={flags} (libsystemd requires 0)"
                ));
            }
            if files.is_empty() {
                return Err(JournalError::NoFiles);
            }
            args.extend(files.iter().map(|f| format!("--file={f}")));
            return Ok(args);
        }
        let user_bits = flags & (SYSTEM_ONLY | CURRENT_USER);
        if let Some(path) = &self.path {
            let allowed = SYSTEM_ONLY | CURRENT_USER | OS_ROOT;
            if flags & !allowed != 0 {
                return unsupported(format!(
                    "journalpath with journalflags={flags}: only SYSTEM_ONLY, CURRENT_USER and OS_ROOT apply to a directory"
                ));
            }
            args.push(if flags & OS_ROOT != 0 {
                format!("--root={path}")
            } else {
                format!("--directory={path}")
            });
        } else {
            let allowed = LOCAL_ONLY
                | SYSTEM_ONLY
                | CURRENT_USER
                | ALL_NAMESPACES
                | INCLUDE_DEFAULT_NAMESPACE;
            if flags & RUNTIME_ONLY != 0 {
                return unsupported("RUNTIME_ONLY has no journalctl equivalent".to_owned());
            }
            if flags & !allowed != 0 {
                return unsupported(format!("journalflags={flags} is not supported"));
            }
            if flags & LOCAL_ONLY == 0 {
                args.push("--merge".to_owned());
            }
            match self.namespace.as_deref() {
                Some("") => return unsupported("empty namespace".to_owned()),
                Some(ns) => {
                    if flags & ALL_NAMESPACES != 0 {
                        return unsupported(
                            "ALL_NAMESPACES cannot be combined with a namespace".to_owned(),
                        );
                    }
                    args.push(if flags & INCLUDE_DEFAULT_NAMESPACE != 0 {
                        format!("--namespace=+{ns}")
                    } else {
                        format!("--namespace={ns}")
                    });
                }
                None => {
                    if flags & INCLUDE_DEFAULT_NAMESPACE != 0 {
                        return unsupported(
                            "INCLUDE_DEFAULT_NAMESPACE needs a namespace".to_owned(),
                        );
                    }
                    if flags & ALL_NAMESPACES != 0 {
                        args.push("--namespace=*".to_owned());
                    }
                }
            }
        }
        if user_bits & SYSTEM_ONLY != 0 {
            args.push("--system".to_owned());
        }
        if user_bits & CURRENT_USER != 0 {
            args.push("--user".to_owned());
        }
        Ok(args)
    }
}

// --- _globJournalFiles ---------------------------------------------------------------------

/// `os.path.join(a, b)` for a relative `b`.
fn join(a: &str, b: &str) -> String {
    if a.is_empty() || a.ends_with('/') {
        format!("{a}{b}")
    } else {
        format!("{a}/{b}")
    }
}

/// Python's `glob.glob(pattern)`: a wildcard (`*`, `?`, `[`) at the start of a path component
/// never matches a name starting with a dot.
///
/// The `glob` crate's own `require_literal_leading_dot` option is not used: it rejects
/// `.*.journal` for `.d.journal`.
fn glob_paths(pattern: &str) -> Vec<String> {
    let opts = glob::MatchOptions {
        case_sensitive: true,
        require_literal_separator: true,
        require_literal_leading_dot: false,
    };
    let Ok(paths) = glob::glob_with(pattern, opts) else {
        return Vec::new();
    };
    let pat_parts: Vec<&str> = pattern.split('/').collect();
    paths
        .filter_map(Result::ok)
        .map(|p| p.to_string_lossy().into_owned())
        .filter(|p| {
            let parts: Vec<&str> = p.split('/').collect();
            // `**` changes the component count: no per-component check possible then
            parts.len() != pat_parts.len()
                || pat_parts.iter().zip(&parts).all(|(pp, part)| {
                    let wildcard_start = pp.starts_with(['*', '?', '[']);
                    !(wildcard_start && part.starts_with('.'))
                })
        })
        .collect()
}

/// The effective user id (`os.geteuid()`).
pub fn effective_uid() -> u32 {
    // SAFETY: geteuid(2) has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

fn is_readable(path: &str) -> bool {
    CString::new(path)
        // SAFETY: `c` is a valid NUL-terminated string for the duration of the call.
        .is_ok_and(|c| unsafe { libc::access(c.as_ptr(), libc::R_OK) } == 0)
}

/// `_globJournalFiles(flags, path)`: journal files without rotated `*@*.journal` ones;
/// `None` if there are none. `flags: None` is Python's `flags=None`.
pub fn glob_journal_files(
    flags: Option<i64>,
    path: Option<&str>,
    paths: &SystemdPaths,
) -> Option<Vec<String>> {
    let mut set: BTreeSet<String> = BTreeSet::new();
    let mut add = |p: &str| {
        if flags.is_none_or(|f| f & SYSTEM_ONLY != 0) {
            set.extend(glob_paths(&join(p, "system.journal")));
        }
        if flags.is_some_and(|f| f & CURRENT_USER != 0) {
            set.extend(glob_paths(&join(
                p,
                &format!("user-{}.journal", effective_uid()),
            )));
        }
        if flags.is_none_or(|f| f & (SYSTEM_ONLY | CURRENT_USER) == 0) {
            let all: BTreeSet<String> = glob_paths(&join(p, "*.journal")).into_iter().collect();
            let rotated: BTreeSet<String> =
                glob_paths(&join(p, "*@*.journal")).into_iter().collect();
            set.extend(all.difference(&rotated).cloned());
        }
    };
    match path {
        Some(p) => add(p),
        None => {
            if flags.is_none_or(|f| f & RUNTIME_ONLY == 0) {
                add(&join(&paths.system_state_logs, "journal/*"));
            }
            add(&join(&paths.system_runtime_logs, "journal/*"));
        }
    }
    let mut list: Vec<String> = set.into_iter().collect();
    if effective_uid() != 0 {
        list.retain(|f| is_readable(f));
    }
    (!list.is_empty()).then_some(list)
}
