//! `JournalReader` against a fake `journalctl` (a shell script that records its argv and
//! prints canned export data). The binary is selected through `JournalOptions::journalctl`,
//! never through the process environment, so the tests can run in parallel.

use std::fs;
use std::io;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use f2b_backend::journal::{
    CURRENT_USER, JournalEntry, JournalMatches, JournalOptions, JournalReader, JournalValue,
    LOCAL_ONLY, OS_ROOT, RUNTIME_ONLY, ResolvedJournal, SYSTEM_ONLY, journalctl_args,
};

/// The fake journalctl; behaviour is selected by files next to the (symlinked) invocation path.
const SCRIPT: &str = r#"#!/bin/sh
dir=$(dirname "$0")
printf '%s\0' "$@" > "$dir/argv.tmp"
mv "$dir/argv.tmp" "$dir/argv"
echo $$ > "$dir/pid"
if [ -f "$dir/stderr" ]; then cat "$dir/stderr" >&2; fi
if [ -f "$dir/canned.export" ]; then cat "$dir/canned.export"; fi
if [ -f "$dir/hang" ]; then exec sleep 60; fi
if [ -f "$dir/exit" ]; then exit "$(cat "$dir/exit")"; fi
exit 0
"#;

/// Written (and closed) once, before any test spawns a process: avoids `ETXTBSY` from
/// concurrent forks holding the write descriptor.
static SCRIPT_FILE: LazyLock<(tempfile::TempDir, PathBuf)> = LazyLock::new(|| {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("fake-journalctl.sh");
    fs::write(&p, SCRIPT).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
    (dir, p)
});

fn script() -> &'static Path {
    &SCRIPT_FILE.1
}

/// A per-test directory with a `journalctl` symlink to the shared script.
struct Fake {
    dir: tempfile::TempDir,
    bin: PathBuf,
}

impl Fake {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("journalctl");
        symlink(script(), &bin).unwrap();
        Self { dir, bin }
    }

    fn put(&self, name: &str, data: impl AsRef<[u8]>) -> &Self {
        fs::write(self.dir.path().join(name), data).unwrap();
        self
    }

    fn argv(&self) -> Vec<String> {
        let raw = fs::read(self.dir.path().join("argv")).expect("script ran");
        raw.split(|&b| b == 0)
            .filter(|a| !a.is_empty())
            .map(|a| String::from_utf8(a.to_vec()).unwrap())
            .collect()
    }

    fn opts(&self) -> JournalOptions {
        JournalOptions {
            journalctl: Some(self.bin.clone()),
            rotated: true,
            journalflags: Some(LOCAL_ONLY | SYSTEM_ONLY),
            ..JournalOptions::default()
        }
    }
}

fn export_entry(n: usize) -> Vec<u8> {
    format!(
        "__CURSOR=c{n}\n__REALTIME_TIMESTAMP={}\n__MONOTONIC_TIMESTAMP={n}\n\
         _BOOT_ID=0123456789abcdef0123456789abcdef\n_HOSTNAME=h\nSYSLOG_IDENTIFIER=t\nMESSAGE=m{n}\n\n",
        1_700_000_000_000_000u64 + n as u64
    )
    .into_bytes()
}

fn wait_dead(r: &JournalReader) {
    let end = Instant::now() + Duration::from_secs(10);
    while r.is_alive() {
        assert!(Instant::now() < end, "reader did not finish");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn message(e: &JournalEntry) -> String {
    match e.get("MESSAGE") {
        Some(JournalValue::Text(s)) => s.clone(),
        other => panic!("{other:?}"),
    }
}

#[test]
fn delivers_entries_in_order_then_reports_dead() {
    let fake = Fake::new();
    let mut canned = Vec::new();
    for n in 0..3 {
        canned.extend(export_entry(n));
    }
    fake.put("canned.export", canned);
    let mut matches = JournalMatches::new();
    matches
        .add(&["_SYSTEMD_UNIT=sshd.service", "+", "_COMM=sshd"])
        .unwrap();
    let mut r = JournalReader::spawn(&fake.opts(), &matches, Some(1_700_000_000.0), false).unwrap();
    let got: Vec<String> = (0..3)
        .map(|_| message(&r.next_timeout(Duration::from_secs(10)).expect("entry")))
        .collect();
    assert_eq!(got, ["m0", "m1", "m2"]);
    wait_dead(&r);
    assert!(r.try_next().is_none());
    assert!(r.next_timeout(Duration::from_millis(10)).is_none());
    assert!(r.exit_status().unwrap().unwrap().success());
    assert_eq!(
        fake.argv(),
        [
            "--output=export",
            "--no-pager",
            "--quiet",
            "--system",
            "--since=@1700000000",
            "--no-tail",
            "_SYSTEMD_UNIT=sshd.service",
            "+",
            "_COMM=sshd"
        ]
    );
}

#[test]
fn try_next_is_non_blocking() {
    let fake = Fake::new();
    fake.put("hang", "");
    let mut r = JournalReader::spawn(&fake.opts(), &JournalMatches::new(), None, true).unwrap();
    let t = Instant::now();
    assert!(r.try_next().is_none());
    assert!(t.elapsed() < Duration::from_secs(1));
    assert!(r.is_alive());
    assert!(r.exit_status().unwrap().is_none());
}

#[test]
fn follow_without_since_starts_at_the_tail() {
    let fake = Fake::new();
    fake.put("hang", "").put("canned.export", export_entry(7));
    let mut r = JournalReader::spawn(&fake.opts(), &JournalMatches::new(), None, true).unwrap();
    assert_eq!(
        message(&r.next_timeout(Duration::from_secs(10)).expect("entry")),
        "m7"
    );
    assert!(r.is_alive(), "journalctl --follow keeps running");
    assert_eq!(
        fake.argv(),
        [
            "--output=export",
            "--no-pager",
            "--quiet",
            "--system",
            "--lines=0",
            "--follow"
        ]
    );
}

#[test]
fn follow_with_fractional_since() {
    let fake = Fake::new();
    fake.put("hang", "").put("canned.export", export_entry(1));
    let mut r = JournalReader::spawn(
        &fake.opts(),
        &JournalMatches::new(),
        Some(1_700_000_000.25),
        true,
    )
    .unwrap();
    assert!(r.next_timeout(Duration::from_secs(10)).is_some());
    let argv = fake.argv();
    assert_eq!(
        &argv[argv.len() - 3..],
        ["--since=@1700000000.250000", "--no-tail", "--follow"]
    );
}

#[test]
fn whole_journal_without_follow() {
    let fake = Fake::new();
    let mut r = JournalReader::spawn(&fake.opts(), &JournalMatches::new(), None, false).unwrap();
    wait_dead(&r);
    assert!(r.try_next().is_none());
    assert_eq!(
        fake.argv(),
        [
            "--output=export",
            "--no-pager",
            "--quiet",
            "--system",
            "--no-tail"
        ]
    );
}

#[test]
fn options_are_resolved_like_upstream_before_spawning() {
    // journalpath with journal files: upstream globs them and opens them as files
    let fake = Fake::new();
    let jdir = tempfile::tempdir().unwrap();
    fs::write(jdir.path().join("system.journal"), "").unwrap();
    fs::write(jdir.path().join("system@rotated.journal"), "").unwrap();
    let opts = JournalOptions {
        journalctl: Some(fake.bin.clone()),
        journalpath: Some(jdir.path().to_str().unwrap().to_owned()),
        ..JournalOptions::default()
    };
    let r = JournalReader::spawn(&opts, &JournalMatches::new(), None, false).unwrap();
    wait_dead(&r);
    let argv = fake.argv();
    assert_eq!(
        argv[3],
        format!("--file={}/system.journal", jdir.path().to_str().unwrap())
    );
    assert_eq!(argv.len(), 5, "{argv:?}");
}

#[test]
fn drop_kills_and_reaps_the_child() {
    let fake = Fake::new();
    fake.put("hang", "");
    let r = JournalReader::spawn(&fake.opts(), &JournalMatches::new(), None, true).unwrap();
    let pid_file = fake.dir.path().join("pid");
    let end = Instant::now() + Duration::from_secs(10);
    let pid = loop {
        if let Ok(s) = fs::read_to_string(&pid_file)
            && let Ok(p) = s.trim().parse::<i32>()
        {
            break p;
        }
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_millis(5));
    };
    // `exec sleep` keeps the pid of the shell
    // SAFETY: signal 0 only probes for the existence of the process.
    assert_eq!(unsafe { libc::kill(pid, 0) }, 0);
    let t = Instant::now();
    drop(r);
    assert!(t.elapsed() < Duration::from_secs(5));
    // SAFETY: as above; the child was reaped by Drop, so the pid is gone.
    assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
}

#[test]
fn many_entries_survive_backpressure() {
    let fake = Fake::new();
    let mut canned = Vec::new();
    for n in 0..5000 {
        canned.extend(export_entry(n));
    }
    fake.put("canned.export", canned);
    let mut r = JournalReader::spawn(&fake.opts(), &JournalMatches::new(), None, false).unwrap();
    for n in 0..5000 {
        let e = r
            .next_timeout(Duration::from_secs(20))
            .unwrap_or_else(|| panic!("entry {n}"));
        assert_eq!(message(&e), format!("m{n}"));
    }
    wait_dead(&r);
}

#[test]
fn stderr_and_exit_status_are_kept() {
    let fake = Fake::new();
    fake.put("stderr", "Failed to open journal: boom\n")
        .put("exit", "1");
    let mut r = JournalReader::spawn(&fake.opts(), &JournalMatches::new(), None, false).unwrap();
    wait_dead(&r);
    let end = Instant::now() + Duration::from_secs(10);
    while r.stderr_tail().is_empty() {
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(r.stderr_tail(), ["Failed to open journal: boom"]);
    let end = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(s) = r.exit_status().unwrap() {
            break s;
        }
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(status.code(), Some(1));
}

#[test]
fn truncated_output_ends_the_reader_without_the_partial_entry() {
    let fake = Fake::new();
    let mut canned = export_entry(0);
    canned.extend(b"__CURSOR=partial\nMESSAGE=cut");
    fake.put("canned.export", canned);
    let mut r = JournalReader::spawn(&fake.opts(), &JournalMatches::new(), None, false).unwrap();
    assert_eq!(
        message(&r.next_timeout(Duration::from_secs(10)).unwrap()),
        "m0"
    );
    wait_dead(&r);
    assert!(r.try_next().is_none());
}

#[test]
fn missing_binary_and_bad_arguments_fail_at_spawn() {
    let mut opts = JournalOptions {
        journalctl: Some(PathBuf::from("/nonexistent/journalctl")),
        rotated: true,
        ..JournalOptions::default()
    };
    let m = JournalMatches::new();
    let e = JournalReader::spawn(&opts, &m, None, false).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::NotFound);

    let fake = Fake::new();
    opts.journalctl = Some(fake.bin.clone());
    for bad in [-1.0, f64::NAN, f64::INFINITY] {
        let e = JournalReader::spawn(&opts, &m, Some(bad), false).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput, "{bad}");
    }
    // flags journalctl cannot express
    opts.journalflags = Some(RUNTIME_ONLY);
    let e = JournalReader::spawn(&opts, &m, None, false).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
    assert!(e.to_string().contains("RUNTIME_ONLY"), "{e}");
    assert!(!fake.dir.path().join("argv").exists(), "nothing was run");
}

#[test]
fn program_selection_prefers_the_explicit_field() {
    let opts = JournalOptions {
        journalctl: Some(PathBuf::from("/opt/jc")),
        ..JournalOptions::default()
    };
    assert_eq!(opts.journalctl_program(), "/opt/jc");
    if std::env::var_os("F2B_JOURNALCTL").is_none() {
        assert_eq!(JournalOptions::default().journalctl_program(), "journalctl");
    }
}

fn args(r: &ResolvedJournal, since: Option<f64>, follow: bool) -> io::Result<Vec<String>> {
    journalctl_args(r, &JournalMatches::new(), since, follow)
}

fn resolved(flags: Option<i64>) -> ResolvedJournal {
    ResolvedJournal {
        flags,
        path: None,
        files: None,
        namespace: None,
    }
}

const BASE: [&str; 3] = ["--output=export", "--no-pager", "--quiet"];

#[test]
fn source_flag_mapping() {
    let tail = |a: Vec<String>| a[3..].to_vec();
    // python-systemd default (flags None -> LOCAL_ONLY): journalctl's default
    assert_eq!(
        tail(args(&resolved(None), None, false).unwrap()),
        ["--no-tail"]
    );
    assert_eq!(
        tail(args(&resolved(Some(LOCAL_ONLY)), None, false).unwrap()),
        ["--no-tail"]
    );
    // no LOCAL_ONLY: also remote journals
    assert_eq!(
        tail(args(&resolved(Some(0)), None, false).unwrap()),
        ["--merge", "--no-tail"]
    );
    assert_eq!(
        tail(args(&resolved(Some(SYSTEM_ONLY)), None, true).unwrap()),
        ["--merge", "--system", "--lines=0", "--follow"]
    );
    assert_eq!(
        tail(
            args(
                &resolved(Some(LOCAL_ONLY | SYSTEM_ONLY | CURRENT_USER)),
                None,
                false
            )
            .unwrap()
        ),
        ["--system", "--user", "--no-tail"]
    );
    assert_eq!(args(&resolved(None), None, false).unwrap()[..3], BASE);
    // files
    let files = ResolvedJournal {
        flags: None,
        path: None,
        files: Some(vec!["/a/system.journal".into(), "/b/user-1.journal".into()]),
        namespace: None,
    };
    assert_eq!(
        tail(args(&files, Some(5.0), true).unwrap()),
        [
            "--file=/a/system.journal",
            "--file=/b/user-1.journal",
            "--since=@5",
            "--no-tail",
            "--follow"
        ]
    );
    // directory
    let dir = ResolvedJournal {
        flags: None,
        path: Some("/var/log/journal/x".into()),
        files: None,
        namespace: None,
    };
    assert_eq!(
        tail(args(&dir, None, false).unwrap()),
        ["--directory=/var/log/journal/x", "--no-tail"]
    );
    let root = ResolvedJournal {
        flags: Some(OS_ROOT | SYSTEM_ONLY),
        ..dir.clone()
    };
    assert_eq!(
        tail(args(&root, None, false).unwrap()),
        ["--root=/var/log/journal/x", "--system", "--no-tail"]
    );
    // namespace
    let ns = ResolvedJournal {
        namespace: Some("web".into()),
        ..resolved(None)
    };
    assert_eq!(
        tail(args(&ns, None, false).unwrap()),
        ["--namespace=web", "--no-tail"]
    );
    let ns_default = ResolvedJournal {
        flags: Some(LOCAL_ONLY | 64),
        ..ns.clone()
    };
    assert_eq!(
        tail(args(&ns_default, None, false).unwrap()),
        ["--namespace=+web", "--no-tail"]
    );
    let all = resolved(Some(LOCAL_ONLY | 32));
    assert_eq!(
        tail(args(&all, None, false).unwrap()),
        ["--namespace=*", "--no-tail"]
    );
    // namespace is ignored when a directory is given, like python-systemd
    let dir_ns = ResolvedJournal {
        namespace: Some("web".into()),
        ..dir
    };
    assert_eq!(
        tail(args(&dir_ns, None, false).unwrap()),
        ["--directory=/var/log/journal/x", "--no-tail"]
    );
}

#[test]
fn unsupported_combinations_are_rejected() {
    let both = ResolvedJournal {
        flags: None,
        path: Some("/x".into()),
        files: Some(vec!["/y".into()]),
        namespace: None,
    };
    let bad: Vec<ResolvedJournal> = vec![
        both,
        // files + non-zero flags
        ResolvedJournal {
            flags: Some(SYSTEM_ONLY),
            path: None,
            files: Some(vec!["/y".into()]),
            namespace: None,
        },
        // no files at all: python-systemd opens an empty journal
        ResolvedJournal {
            flags: None,
            path: None,
            files: Some(vec![]),
            namespace: None,
        },
        // directory + LOCAL_ONLY / RUNTIME_ONLY
        ResolvedJournal {
            flags: Some(LOCAL_ONLY),
            path: Some("/x".into()),
            files: None,
            namespace: None,
        },
        resolved(Some(RUNTIME_ONLY)),
        resolved(Some(OS_ROOT)),
        resolved(Some(LOCAL_ONLY | 128)),
        resolved(Some(LOCAL_ONLY | 64)),
        ResolvedJournal {
            flags: Some(LOCAL_ONLY | 32),
            namespace: Some("n".into()),
            ..resolved(None)
        },
        ResolvedJournal {
            namespace: Some(String::new()),
            ..resolved(None)
        },
    ];
    for (i, r) in bad.iter().enumerate() {
        let e = args(r, None, false).expect_err(&format!("case {i}: {r:?}"));
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput, "case {i}");
    }
}
