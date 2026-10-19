use f2b_backend::{FileContainer, PollingBackend};
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_file_container_read_and_partial_line() {
    let mut tmp = NamedTempFile::new().unwrap();
    write!(tmp, "line 1\nline 2\n").unwrap();
    tmp.flush().unwrap();

    let mut container = FileContainer::new(tmp.path(), "utf-8", false).unwrap();
    assert!(container.open(None).unwrap());

    assert_eq!(container.readline(true).unwrap(), Some("line 1".to_owned()));
    assert_eq!(container.readline(true).unwrap(), Some("line 2".to_owned()));
    assert_eq!(container.readline(true).unwrap(), None); // EOF

    // Write incomplete line (no trailing newline)
    write!(tmp, "partial line").unwrap();
    tmp.flush().unwrap();

    assert!(container.open(None).unwrap());
    // Since wait_for_line_end is true by default, partial line is not returned
    assert_eq!(container.readline(true).unwrap(), None);

    // Complete the line
    writeln!(tmp, " finished").unwrap();
    tmp.flush().unwrap();

    assert!(container.open(None).unwrap());
    assert_eq!(
        container.readline(true).unwrap(),
        Some("partial line finished".to_owned())
    );
}

#[test]
fn test_file_container_rotation() {
    let mut tmp = NamedTempFile::new().unwrap();
    write!(tmp, "first line\nsecond line\n").unwrap();
    tmp.flush().unwrap();

    let mut container = FileContainer::new(tmp.path(), "utf-8", false).unwrap();
    assert!(container.open(None).unwrap());
    assert_eq!(
        container.readline(true).unwrap(),
        Some("first line".to_owned())
    );
    assert_eq!(
        container.readline(true).unwrap(),
        Some("second line".to_owned())
    );

    // Truncate / rewrite file (rotation)
    let file = tmp.reopen().unwrap();
    file.set_len(0).unwrap();
    let mut writer = std::io::BufWriter::new(file);
    writeln!(writer, "new first line").unwrap();
    writer.flush().unwrap();

    assert!(container.open(None).unwrap());
    assert_eq!(container.pos(), 0, "pos should be reset to 0 on rotation");
    assert_eq!(
        container.readline(true).unwrap(),
        Some("new first line".to_owned())
    );
}

#[test]
fn test_polling_backend() {
    let mut tmp1 = NamedTempFile::new().unwrap();
    let mut tmp2 = NamedTempFile::new().unwrap();

    writeln!(tmp1, "file1 line1").unwrap();
    tmp1.flush().unwrap();
    writeln!(tmp2, "file2 line1").unwrap();
    tmp2.flush().unwrap();

    let mut backend = PollingBackend::new();
    backend.add_log_path(tmp1.path(), false).unwrap();
    backend.add_log_path(tmp2.path(), false).unwrap();

    let mut collected = Vec::new();
    let count = backend
        .poll_once(|_path, line| {
            collected.push(line.to_owned());
        })
        .unwrap();

    assert_eq!(count, 2);
    assert_eq!(collected, vec!["file1 line1", "file2 line1"]);
}
