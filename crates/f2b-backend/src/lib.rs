//! Log file monitoring backends for Fast2Ban.

pub mod container;
pub mod inotify;
pub mod polling;

pub use container::FileContainer;
pub use inotify::InotifyBackend;
pub use polling::PollingBackend;

use std::path::Path;

/// Unified backend enumeration.
#[derive(Debug)]
pub enum Backend {
    Polling(PollingBackend),
    Inotify(InotifyBackend),
}

impl Backend {
    pub fn create(name: &str) -> Self {
        match name {
            "polling" => Self::Polling(PollingBackend::new()),
            _ => Self::Inotify(InotifyBackend::new()),
        }
    }

    pub fn add_log_path(&mut self, path: impl AsRef<Path>, tail: bool) -> std::io::Result<()> {
        match self {
            Self::Polling(p) => p.add_log_path(path, tail),
            Self::Inotify(i) => i.add_log_path(path, tail),
        }
    }

    pub fn del_log_path(&mut self, path: &Path) -> Option<FileContainer> {
        match self {
            Self::Polling(p) => p.del_log_path(path),
            Self::Inotify(i) => i.del_log_path(path),
        }
    }

    pub fn poll_once<F: FnMut(&Path, &str)>(&mut self, on_line: F) -> std::io::Result<usize> {
        match self {
            Self::Polling(p) => p.poll_once(on_line),
            Self::Inotify(i) => i.poll_once(on_line),
        }
    }
}
