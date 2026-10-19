//! Log monitoring backends for Fast2Ban: log files (polling, inotify) and the
//! systemd journal.

pub mod container;
pub mod inotify;
pub mod journal;
pub mod polling;
pub mod systemd;

pub use container::FileContainer;
pub use inotify::InotifyBackend;
pub use polling::PollingBackend;
pub use systemd::JournalBackend;

use std::path::{Path, PathBuf};

use indexmap::IndexMap;

/// Unified backend enumeration.
#[derive(Debug)]
pub enum Backend {
    Polling(PollingBackend),
    Inotify(InotifyBackend),
    Journal(JournalBackend),
}

impl Backend {
    /// A file backend by name: `polling`, anything else is inotify (which
    /// falls back to polling without kernel support). Use
    /// [`Backend::from_spec`] for `systemd`.
    pub fn create(name: &str) -> Self {
        match name {
            "polling" => Self::Polling(PollingBackend::new()),
            _ => Self::Inotify(InotifyBackend::new()),
        }
    }

    /// The backend of `add <jail> <spec>`: a name with optional options, e.g.
    /// `systemd[journalflags=1]`.
    ///
    /// # Errors
    /// Malformed option syntax or options the backend does not know.
    pub fn from_spec(spec: &str) -> Result<Self, String> {
        let (name, opts) = f2b_helpers::extract_options(spec).map_err(|e| e.to_string())?;
        if name.starts_with("systemd") {
            return Ok(Self::Journal(JournalBackend::from_backend_options(&opts)?));
        }
        if !opts.is_empty() {
            return Err(format!("Backend {name:?} does not take options"));
        }
        Ok(Self::create(&name))
    }

    /// `true` for the systemd journal backend.
    pub fn is_journal(&self) -> bool {
        matches!(self, Self::Journal(_))
    }

    pub fn journal(&self) -> Option<&JournalBackend> {
        match self {
            Self::Journal(j) => Some(j),
            _ => None,
        }
    }

    pub fn journal_mut(&mut self) -> Option<&mut JournalBackend> {
        match self {
            Self::Journal(j) => Some(j),
            _ => None,
        }
    }

    pub fn add_log_path(&mut self, path: impl AsRef<Path>, tail: bool) -> std::io::Result<()> {
        match self {
            Self::Polling(p) => p.add_log_path(path, tail),
            Self::Inotify(i) => i.add_log_path(path, tail),
            Self::Journal(_) => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "log files cannot be monitored by the systemd backend",
            )),
        }
    }

    pub fn del_log_path(&mut self, path: &Path) -> Option<FileContainer> {
        match self {
            Self::Polling(p) => p.del_log_path(path),
            Self::Inotify(i) => i.del_log_path(path),
            Self::Journal(_) => None,
        }
    }

    /// Monitored log file paths in insertion order (`getLogPath`).
    pub fn log_paths(&self) -> Vec<PathBuf> {
        match self {
            Self::Polling(p) => p.log_paths(),
            Self::Inotify(i) => i.log_paths(),
            Self::Journal(_) => Vec::new(),
        }
    }

    /// The file containers (position, rotation hash) of a file backend.
    pub fn containers_mut(&mut self) -> Option<&mut IndexMap<PathBuf, FileContainer>> {
        match self {
            Self::Polling(p) => Some(p.containers_mut()),
            Self::Inotify(i) => Some(i.containers_mut()),
            Self::Journal(_) => None,
        }
    }

    /// Set the decoding for all (present and future) log files (`setLogEncoding`).
    pub fn set_encoding(&mut self, encoding: &str) {
        match self {
            Self::Polling(p) => p.set_encoding(encoding),
            Self::Inotify(i) => i.set_encoding(encoding),
            Self::Journal(j) => j.set_encoding(encoding),
        }
    }

    /// Read new lines of the monitored files. The journal backend yields
    /// nothing here; use [`JournalBackend::poll`] through [`Backend::journal_mut`].
    pub fn poll_once<F: FnMut(&Path, &str)>(&mut self, on_line: F) -> std::io::Result<usize> {
        match self {
            Self::Polling(p) => p.poll_once(on_line),
            Self::Inotify(i) => i.poll_once(on_line),
            Self::Journal(_) => Ok(0),
        }
    }
}
