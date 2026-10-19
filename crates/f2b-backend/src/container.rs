//! Exact port of upstream `FileContainer` (`fail2ban/server/filter.py`).

use md5::{Digest, Md5};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Port of upstream `FileContainer`.
///
/// Tracks log file position, rotation (inode change, size truncation, or first line MD5 mismatch),
/// and supports waiting for complete lines.
#[derive(Debug)]
pub struct FileContainer {
    filename: PathBuf,
    encoding: String,
    tail: bool,
    handler: Option<BufReader<File>>,
    pos: u64,
    ino: u64,
    hash: String,
    hash_next_time: Instant,
    pub wait_for_line_end: bool,
    pub in_operation: bool,
}

impl FileContainer {
    pub fn new(filename: impl AsRef<Path>, encoding: &str, tail: bool) -> io::Result<Self> {
        let path = filename.as_ref().to_path_buf();
        let mut container = Self {
            filename: path.clone(),
            encoding: encoding.to_owned(),
            tail,
            handler: None,
            pos: 0,
            ino: 0,
            hash: String::new(),
            hash_next_time: Instant::now() + Duration::from_secs(30),
            wait_for_line_end: true,
            in_operation: tail,
        };

        let file = File::open(&path)?;
        let meta = file.metadata()?;
        container.ino = meta.ino();

        if meta.len() > 0 {
            let mut reader = BufReader::new(file);
            let mut first_line = Vec::new();
            let n = reader.read_until(b'\n', &mut first_line)?;
            if n > 0 && (first_line.ends_with(b"\n") || first_line.ends_with(b"\r")) {
                let mut hasher = Md5::new();
                hasher.update(&first_line);
                container.hash = format!("{:x}", hasher.finalize());
            }

            if tail {
                container.pos = meta.len();
            }
        }

        Ok(container)
    }

    pub fn tail(&self) -> bool {
        self.tail
    }

    pub fn file_name(&self) -> &Path {
        &self.filename
    }

    pub fn encoding(&self) -> &str {
        &self.encoding
    }

    pub fn set_encoding(&mut self, enc: &str) {
        self.encoding = enc.to_owned();
    }

    pub fn hash(&self) -> &str {
        &self.hash
    }

    pub fn pos(&self) -> u64 {
        self.pos
    }

    pub fn set_pos(&mut self, pos: u64) {
        self.pos = pos;
    }

    /// Open or reopen file, detecting log rotation. Returns false if file is not modified.
    pub fn open(&mut self, force_pos: Option<u64>) -> io::Result<bool> {
        let file = File::open(&self.filename)?;
        let meta = file.metadata()?;
        let curr_size = meta.len();
        let curr_ino = meta.ino();

        let mut my_hash = self.hash.clone();
        let rot_flag = curr_size < self.pos || curr_ino != self.ino;

        if rot_flag || my_hash.is_empty() || Instant::now() > self.hash_next_time {
            my_hash.clear();
            let mut reader = BufReader::new(&file);
            let mut first_line = Vec::new();
            let n = reader.read_until(b'\n', &mut first_line)?;
            if n > 0 && (first_line.ends_with(b"\n") || first_line.ends_with(b"\r")) {
                let mut hasher = Md5::new();
                hasher.update(&first_line);
                my_hash = format!("{:x}", hasher.finalize());
                self.hash_next_time = Instant::now() + Duration::from_secs(30);
            }
        } else if curr_size == self.pos {
            my_hash = self.hash.clone();
        }

        // Compare rotation condition
        if rot_flag || my_hash != self.hash {
            if !self.hash.is_empty() {
                log::info!(
                    "Log rotation detected for {:?}, reason: size={}/{}, ino={}/{}",
                    self.filename,
                    curr_size,
                    self.pos,
                    curr_ino,
                    self.ino
                );
                self.ino = curr_ino;
                self.pos = 0;
            }
            self.hash = my_hash;
        }

        if let Some(fpos) = force_pos {
            self.pos = fpos;
        } else if curr_size <= self.pos {
            return Ok(false);
        }

        let mut reader = BufReader::new(file);
        reader.seek(SeekFrom::Start(self.pos))?;
        self.handler = Some(reader);

        Ok(true)
    }

    /// Read a line from the file. Returns `None` if EOF or if line is incomplete when `complete` is true.
    pub fn readline(&mut self, complete: bool) -> io::Result<Option<String>> {
        let Some(reader) = self.handler.as_mut() else {
            return Ok(None);
        };

        let start_pos = reader.stream_position()?;
        let mut raw_bytes = Vec::new();
        let n = reader.read_until(b'\n', &mut raw_bytes)?;

        if n == 0 {
            return Ok(None);
        }

        let has_newline = raw_bytes.ends_with(b"\n") || raw_bytes.ends_with(b"\r");
        if complete && self.wait_for_line_end && !has_newline {
            // Partial line in progress: seek back to start of partial line
            reader.seek(SeekFrom::Start(start_pos))?;
            return Ok(None);
        }

        self.pos = reader.stream_position()?;

        let s = decode_line(&raw_bytes, &self.encoding);
        let trimmed = s.trim_end_matches(['\r', '\n']).to_owned();
        Ok(Some(trimmed))
    }

    pub fn close(&mut self) -> io::Result<()> {
        if let Some(mut reader) = self.handler.take() {
            self.pos = reader.stream_position()?;
        }
        Ok(())
    }
}

/// Decode one raw log line. Single-byte Latin-1 family encodings map each byte
/// to the code point of the same value; everything else (`utf-8`, `auto`, ...)
/// is UTF-8 with replacement characters for invalid bytes.
fn decode_line<'a>(raw: &'a [u8], encoding: &str) -> std::borrow::Cow<'a, str> {
    match encoding.to_ascii_lowercase().replace('_', "-").as_str() {
        "latin-1" | "latin1" | "iso-8859-1" | "iso8859-1" | "l1" => raw
            .iter()
            .map(|&b| char::from(b))
            .collect::<String>()
            .into(),
        _ => String::from_utf8_lossy(raw),
    }
}
