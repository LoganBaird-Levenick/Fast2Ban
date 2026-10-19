//! Parser for the `journalctl -o export` stream (systemd "Journal Export Format").
//!
//! ```text
//! entry  := field* "\n"
//! field  := NAME "=" VALUE "\n"                      (VALUE without newline)
//!         | NAME "\n" <u64 little endian length> DATA "\n"   (binary-safe form)
//! ```

use std::io::{self, BufRead, Read};

use super::entry::JournalEntry;

/// Upper bound of one binary field. libsystemd stores at most 768 MiB per field; the data is
/// read incrementally, so a bogus length cannot force a huge allocation.
const MAX_FIELD_SIZE: u64 = 768 * 1024 * 1024;

/// Iterator over the entries of an export stream; see [`parse_export`].
#[derive(Debug)]
pub struct ExportEntries<R> {
    reader: R,
    done: bool,
}

/// Parse a `journalctl -o export` stream into [`JournalEntry`] values (python-systemd
/// converters applied).
///
/// A stream that ends in the middle of an entry (e.g. the child was killed) yields
/// [`io::ErrorKind::UnexpectedEof`] for the incomplete entry and then ends; a malformed stream
/// yields [`io::ErrorKind::InvalidData`] and then ends (the framing cannot be recovered). Blank
/// lines between entries are ignored. I/O errors are passed through once.
pub fn parse_export<R: BufRead>(reader: R) -> ExportEntries<R> {
    ExportEntries {
        reader,
        done: false,
    }
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_owned())
}

fn truncated() -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "journal export stream ended inside an entry",
    )
}

impl<R: BufRead> ExportEntries<R> {
    fn read_entry(&mut self) -> io::Result<Option<JournalEntry>> {
        let mut fields: Vec<(String, Vec<u8>)> = Vec::new();
        let mut line = Vec::new();
        loop {
            line.clear();
            let n = self.reader.read_until(b'\n', &mut line)?;
            if n == 0 {
                return if fields.is_empty() {
                    Ok(None)
                } else {
                    Err(truncated())
                };
            }
            if line.last() != Some(&b'\n') {
                // EOF in the middle of a line
                return Err(truncated());
            }
            line.pop();
            if line.is_empty() {
                if fields.is_empty() {
                    continue; // stray blank line between entries
                }
                return Ok(Some(JournalEntry::from_raw_fields(fields)));
            }
            if let Some(eq) = line.iter().position(|&b| b == b'=') {
                let name = field_name(&line[..eq])?;
                fields.push((name, line[eq + 1..].to_vec()));
            } else {
                let name = field_name(&line)?;
                let mut len = [0u8; 8];
                read_exact_or_truncated(&mut self.reader, &mut len)?;
                let len = u64::from_le_bytes(len);
                if len > MAX_FIELD_SIZE {
                    return Err(invalid("journal export field too large"));
                }
                let mut data = Vec::new();
                let got = (&mut self.reader).take(len).read_to_end(&mut data)?;
                if (got as u64) < len {
                    return Err(truncated());
                }
                let mut nl = [0u8; 1];
                read_exact_or_truncated(&mut self.reader, &mut nl)?;
                if nl[0] != b'\n' {
                    return Err(invalid(
                        "journal export binary field not terminated by a newline",
                    ));
                }
                fields.push((name, data));
            }
        }
    }
}

fn read_exact_or_truncated<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<()> {
    r.read_exact(buf).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            truncated()
        } else {
            e
        }
    })
}

fn field_name(raw: &[u8]) -> io::Result<String> {
    if raw.is_empty() {
        return Err(invalid("empty field name in journal export stream"));
    }
    String::from_utf8(raw.to_vec()).map_err(|_| invalid("non-UTF-8 field name"))
}

impl<R: BufRead> Iterator for ExportEntries<R> {
    type Item = io::Result<JournalEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match self.read_entry() {
            Ok(Some(entry)) => Some(Ok(entry)),
            Ok(None) => {
                self.done = true;
                None
            }
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}
