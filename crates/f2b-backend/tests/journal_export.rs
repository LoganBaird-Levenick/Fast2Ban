//! `parse_export` on hand-built `journalctl -o export` streams.

use std::io::{self, BufReader, Cursor, Read};

use f2b_backend::journal::{JournalEntry, JournalValue, parse_export};

fn binary(name: &str, data: &[u8]) -> Vec<u8> {
    let mut v = name.as_bytes().to_vec();
    v.push(b'\n');
    v.extend((data.len() as u64).to_le_bytes());
    v.extend(data);
    v.push(b'\n');
    v
}

fn parse(stream: &[u8]) -> Vec<io::Result<JournalEntry>> {
    parse_export(Cursor::new(stream.to_vec())).collect()
}

fn text(s: &str) -> JournalValue {
    JournalValue::Text(s.to_owned())
}

const BOOT: &str = "0123456789abcdef0123456789abcdef";

fn sample() -> Vec<u8> {
    let mut s = Vec::new();
    s.extend(b"__CURSOR=s=1;i=2\n__REALTIME_TIMESTAMP=1700000000123456\n");
    s.extend(b"__MONOTONIC_TIMESTAMP=5123456\n");
    s.extend(format!("_BOOT_ID={BOOT}\n").as_bytes());
    s.extend(b"_HOSTNAME=host\nSYSLOG_IDENTIFIER=sshd\nSYSLOG_PID=42\n");
    s.extend(binary("MESSAGE", b"line one\nline two\n\nafter blank"));
    s.extend(b"\n");
    s.extend(b"__CURSOR=s=1;i=3\n__REALTIME_TIMESTAMP=1700000001000000\n");
    s.extend(b"__MONOTONIC_TIMESTAMP=6000000\n");
    s.extend(format!("_BOOT_ID={BOOT}\n").as_bytes());
    s.extend(b"MESSAGE=second\nMESSAGE=third=with=equals\n\n");
    s
}

#[test]
fn text_and_binary_fields() {
    let entries = parse(&sample());
    assert_eq!(entries.len(), 2);
    let e = entries[0].as_ref().unwrap();
    assert_eq!(e.get("__CURSOR"), Some(&text("s=1;i=2")));
    assert_eq!(e.get("_HOSTNAME"), Some(&text("host")));
    assert_eq!(e.get("SYSLOG_PID"), Some(&JournalValue::Int(42)));
    assert_eq!(
        e.get("MESSAGE"),
        Some(&text("line one\nline two\n\nafter blank"))
    );
    assert_eq!(
        e.get("__REALTIME_TIMESTAMP"),
        Some(&JournalValue::Timestamp(1_700_000_000_123_456))
    );
    assert_eq!(
        e.get("__MONOTONIC_TIMESTAMP"),
        Some(&JournalValue::Monotonic {
            micros: 5_123_456,
            boot_id: Some(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef)
        })
    );
    // field order is the stream order
    let names: Vec<&str> = e.iter().map(|(k, _)| k).collect();
    assert_eq!(
        names,
        [
            "__CURSOR",
            "__REALTIME_TIMESTAMP",
            "__MONOTONIC_TIMESTAMP",
            "_BOOT_ID",
            "_HOSTNAME",
            "SYSLOG_IDENTIFIER",
            "SYSLOG_PID",
            "MESSAGE"
        ]
    );
    let e2 = entries[1].as_ref().unwrap();
    assert_eq!(
        e2.get("MESSAGE"),
        Some(&JournalValue::List(vec![
            text("second"),
            text("third=with=equals")
        ]))
    );
}

#[test]
fn non_utf8_and_nul_bytes_stay_bytes() {
    let mut s = Vec::new();
    s.extend(b"A=x\n");
    s.extend(binary("MESSAGE", b"caf\xe9\x00\xff"));
    s.extend(binary("EMPTY", b""));
    s.extend(binary("COREDUMP", b"plain"));
    s.extend(b"UTF=\xc3\xa9\n\n");
    let entries = parse(&s);
    let e = entries[0].as_ref().unwrap();
    assert_eq!(
        e.get("MESSAGE"),
        Some(&JournalValue::Bytes(b"caf\xe9\x00\xff".to_vec()))
    );
    assert_eq!(e.get("EMPTY"), Some(&text("")));
    assert_eq!(
        e.get("COREDUMP"),
        Some(&JournalValue::Bytes(b"plain".to_vec()))
    );
    assert_eq!(e.get("UTF"), Some(&text("\u{e9}")));
}

#[test]
fn blank_lines_between_entries_are_ignored_and_empty_stream_is_empty() {
    assert!(parse(b"").is_empty());
    assert!(parse(b"\n\n\n").is_empty());
    let mut s = b"\n\n".to_vec();
    s.extend(b"A=1\n\n\n\nB=2\n\n");
    let entries = parse(&s);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[1].as_ref().unwrap().get("B"), Some(&text("2")));
}

#[test]
fn truncation_at_every_offset_never_panics() {
    let full = sample();
    let complete: Vec<_> = parse(&full).into_iter().map(Result::unwrap).collect();
    let mut boundaries = 0;
    for cut in 0..full.len() {
        let got = parse(&full[..cut]);
        // entries before the cut are intact; at most one trailing error, then the stream ends
        let (oks, rest): (Vec<_>, Vec<_>) = got.into_iter().partition(Result::is_ok);
        assert!(rest.len() <= 1, "cut {cut}");
        for (i, e) in oks.iter().enumerate() {
            assert_eq!(e.as_ref().unwrap(), &complete[i], "cut {cut}");
        }
        match rest.first() {
            Some(Err(e)) => assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof, "cut {cut}"),
            None => boundaries += 1,
            _ => unreachable!(),
        }
    }
    // clean ends: before the first byte, and at the boundary after the first entry
    // (cut == 0 and the offset right after its blank line; the second blank line is a no-op)
    assert!(boundaries >= 2, "{boundaries}");
}

#[test]
fn truncated_stream_yields_complete_entries_then_unexpected_eof() {
    let mut s = Vec::new();
    s.extend(b"A=1\n\nB=2\nC");
    let got = parse(&s);
    assert_eq!(got.len(), 2);
    assert!(got[0].is_ok());
    assert_eq!(
        got[1].as_ref().unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
    // entry whose fields are complete but whose terminating blank line is missing
    let got = parse(b"A=1\nB=2\n");
    assert_eq!(got.len(), 1);
    assert_eq!(
        got[0].as_ref().unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
    // truncated binary payload
    let mut b = b"A=1\nMESSAGE\n".to_vec();
    b.extend(100u64.to_le_bytes());
    b.extend(b"only a few bytes");
    let got = parse(&b);
    assert_eq!(
        got[0].as_ref().unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
}

#[test]
fn malformed_streams_are_invalid_data() {
    let kind = |s: &[u8]| parse(s).pop().unwrap().unwrap_err().kind();
    // empty field name
    assert_eq!(kind(b"=x\n\n"), io::ErrorKind::InvalidData);
    // non UTF-8 field name
    assert_eq!(kind(b"\xff=x\n\n"), io::ErrorKind::InvalidData);
    // binary field not followed by a newline
    let mut b = b"M\n".to_vec();
    b.extend(2u64.to_le_bytes());
    b.extend(b"abX\n");
    assert_eq!(kind(&b), io::ErrorKind::InvalidData);
    // absurd length does not allocate: it is rejected
    let mut b = b"M\n".to_vec();
    b.extend(u64::MAX.to_le_bytes());
    assert_eq!(kind(&b), io::ErrorKind::InvalidData);
    // a modest bogus length is simply truncated data
    let mut b = b"M\n".to_vec();
    b.extend((1u64 << 29).to_le_bytes());
    b.extend(b"short");
    assert_eq!(kind(&b), io::ErrorKind::UnexpectedEof);
    // iteration ends after an error
    let mut it = parse_export(Cursor::new(b"=x\n\nA=1\n\n".to_vec()));
    assert!(it.next().unwrap().is_err());
    assert!(it.next().is_none());
}

/// A reader that hands out one byte at a time, like a slow pipe.
struct Dribble<R>(R);
impl<R: Read> Read for Dribble<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = buf.len().min(1);
        self.0.read(&mut buf[..n])
    }
}

#[test]
fn small_reads_parse_identically() {
    let full = sample();
    let whole = parse(&full);
    let dribbled: Vec<_> = parse_export(BufReader::with_capacity(
        1,
        Dribble(Cursor::new(full.clone())),
    ))
    .collect();
    assert_eq!(whole.len(), dribbled.len());
    for (a, b) in whole.iter().zip(&dribbled) {
        assert_eq!(a.as_ref().unwrap(), b.as_ref().unwrap());
    }
}

#[test]
fn io_errors_are_passed_through_once() {
    struct Broken(bool);
    impl Read for Broken {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.0 {
                return Err(io::Error::other("boom"));
            }
            self.0 = true;
            let data = b"A=1\n";
            buf[..data.len()].copy_from_slice(data);
            Ok(data.len())
        }
    }
    let mut it = parse_export(BufReader::new(Broken(false)));
    let err = it.next().unwrap().unwrap_err();
    assert_eq!(err.to_string(), "boom");
    assert!(it.next().is_none());
}

#[test]
fn unparsable_boot_id_leaves_monotonic_without_boot() {
    let e = parse(b"__MONOTONIC_TIMESTAMP=7\n_BOOT_ID=zz\n\n")
        .remove(0)
        .unwrap();
    assert_eq!(
        e.get("__MONOTONIC_TIMESTAMP"),
        Some(&JournalValue::Monotonic {
            micros: 7,
            boot_id: None
        })
    );
    assert_eq!(
        e.get("_BOOT_ID"),
        Some(&JournalValue::Bytes(b"zz".to_vec()))
    );
}
