//! Filesystem seam. Config reading goes through [`Fs`] so tests can run the
//! reader against a controlled view of the filesystem (log files that exist).

use std::fmt;
use std::io;
use std::path::Path;

pub trait Fs: fmt::Debug {
    /// Read a whole file as UTF-8. Invalid UTF-8 must yield `ErrorKind::InvalidData`.
    fn read_to_string(&self, path: &str) -> io::Result<String>;
    /// `os.path.exists` (follows symlinks).
    fn exists(&self, path: &str) -> bool;
    /// `os.path.isfile`.
    fn is_file(&self, path: &str) -> bool;
    /// `glob.glob(pattern)` with Python semantics: `*` does not cross `/` and
    /// does not match a leading dot. Result is sorted (upstream order is
    /// filesystem-arbitrary; sorting makes behavior deterministic).
    fn glob(&self, pattern: &str) -> Vec<String>;
}

/// The real filesystem.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealFs;

impl Fs for RealFs {
    fn read_to_string(&self, path: &str) -> io::Result<String> {
        std::fs::read_to_string(path)
    }

    fn exists(&self, path: &str) -> bool {
        Path::new(path).exists()
    }

    fn is_file(&self, path: &str) -> bool {
        Path::new(path).is_file()
    }

    fn glob(&self, pattern: &str) -> Vec<String> {
        let opts = glob::MatchOptions {
            case_sensitive: true,
            require_literal_separator: true,
            require_literal_leading_dot: true,
        };
        let Ok(paths) = glob::glob_with(pattern, opts) else {
            return Vec::new();
        };
        let mut out: Vec<String> = paths
            .filter_map(std::result::Result::ok)
            .filter_map(|p| p.to_str().map(str::to_owned))
            .collect();
        out.sort();
        out
    }
}
