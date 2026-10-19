//! Polling backend for log monitoring (`fail2ban/server/filterpoll.py`).

use indexmap::IndexMap;
use std::path::{Path, PathBuf};

use crate::container::FileContainer;

#[derive(Debug)]
pub struct PollingBackend {
    containers: IndexMap<PathBuf, FileContainer>,
}

impl Default for PollingBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl PollingBackend {
    pub fn new() -> Self {
        Self {
            containers: IndexMap::new(),
        }
    }

    pub fn add_log_path(&mut self, path: impl AsRef<Path>, tail: bool) -> std::io::Result<()> {
        let p = path.as_ref().to_path_buf();
        if !self.containers.contains_key(&p) {
            let container = FileContainer::new(&p, "utf-8", tail)?;
            self.containers.insert(p, container);
        }
        Ok(())
    }

    pub fn del_log_path(&mut self, path: &Path) -> Option<FileContainer> {
        self.containers.shift_remove(path)
    }

    pub fn has_log_path(&self, path: &Path) -> bool {
        self.containers.contains_key(path)
    }

    pub fn log_paths(&self) -> Vec<PathBuf> {
        self.containers.keys().cloned().collect()
    }

    pub fn containers(&self) -> &IndexMap<PathBuf, FileContainer> {
        &self.containers
    }

    pub fn containers_mut(&mut self) -> &mut IndexMap<PathBuf, FileContainer> {
        &mut self.containers
    }

    /// Check all files for new content and invoke `on_line(filename, line)` for each line found.
    pub fn poll_once<F: FnMut(&Path, &str)>(&mut self, mut on_line: F) -> std::io::Result<usize> {
        let mut total_lines = 0;
        for (path, container) in &mut self.containers {
            let modified = container.open(None)?;
            if !modified {
                continue;
            }
            while let Some(line) = container.readline(true)? {
                total_lines += 1;
                on_line(path, &line);
            }
            container.close()?;
        }
        Ok(total_lines)
    }
}
