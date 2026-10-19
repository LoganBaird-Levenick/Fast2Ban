//! Inotify backend on Linux, with polling fallback (`fail2ban/server/filterpyinotify.py`).

use crate::container::FileContainer;
use crate::polling::PollingBackend;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct InotifyBackend {
    inner: PollingBackend,
    #[cfg(target_os = "linux")]
    inotify: Option<inotify::Inotify>,
    #[cfg(target_os = "linux")]
    watches: std::collections::HashMap<PathBuf, inotify::WatchDescriptor>,
}

impl Default for InotifyBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl InotifyBackend {
    pub fn new() -> Self {
        #[cfg(target_os = "linux")]
        {
            let inotify = inotify::Inotify::init().ok();
            Self {
                inner: PollingBackend::new(),
                inotify,
                watches: std::collections::HashMap::new(),
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            Self {
                inner: PollingBackend::new(),
            }
        }
    }

    pub fn add_log_path(&mut self, path: impl AsRef<Path>, tail: bool) -> std::io::Result<()> {
        let p = path.as_ref().to_path_buf();
        self.inner.add_log_path(&p, tail)?;

        #[cfg(target_os = "linux")]
        if let Some(ino) = self.inotify.as_mut() {
            use inotify::WatchMask;
            let mask = WatchMask::MODIFY
                | WatchMask::MOVE_SELF
                | WatchMask::DELETE_SELF
                | WatchMask::ATTRIB;
            if let Ok(wd) = ino.watches().add(&p, mask) {
                self.watches.insert(p, wd);
            }
        }

        Ok(())
    }

    pub fn del_log_path(&mut self, path: &Path) -> Option<FileContainer> {
        #[cfg(target_os = "linux")]
        if let (Some(ino), Some(wd)) = (self.inotify.as_mut(), self.watches.remove(path)) {
            let _ = ino.watches().remove(wd);
        }

        self.inner.del_log_path(path)
    }

    pub fn poll_once<F: FnMut(&Path, &str)>(&mut self, on_line: F) -> std::io::Result<usize> {
        // Drain any inotify events if present on Linux
        #[cfg(target_os = "linux")]
        if let Some(ino) = self.inotify.as_mut() {
            let mut buf = [0u8; 4096];
            let _ = ino.read_events(&mut buf);
        }

        self.inner.poll_once(on_line)
    }
}
