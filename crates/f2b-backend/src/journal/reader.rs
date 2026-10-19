//! Journal reader: a `journalctl -o export` child process parsed on a background thread.

use std::collections::VecDeque;
use std::ffi::OsStr;
use std::io::{self, BufRead, BufReader};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use super::entry::JournalEntry;
use super::export::parse_export;
use super::matches::JournalMatches;
use super::options::{JournalOptions, ResolvedJournal};

/// Entries buffered between the parser thread and the consumer; `journalctl` blocks on its
/// pipe when the consumer falls behind.
const CHANNEL_CAPACITY: usize = 1024;
/// Lines of `journalctl` stderr kept for diagnostics.
const STDERR_TAIL_LINES: usize = 16;

/// `--since` argument for an epoch time in seconds, truncated to microseconds like python's
/// `seek_realtime(int(t * 1e6))`.
fn since_arg(since: f64) -> io::Result<String> {
    if !since.is_finite() || since < 0.0 || since >= 9.0e12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid journal start time {since}"),
        ));
    }
    let micros = (since * 1e6) as i64;
    let (secs, frac) = (micros / 1_000_000, micros % 1_000_000);
    Ok(if frac == 0 {
        format!("--since=@{secs}")
    } else {
        format!("--since=@{secs}.{frac:06}")
    })
}

/// The complete `journalctl` argument vector (without the program name).
///
/// ```text
/// --output=export --no-pager --quiet <source options> <position options> <matches>
/// ```
///
/// Position options (oldest entry first in all cases):
/// * `since` given: `--since=@<secs>[.<micros>]` + `--no-tail` (all entries from that time on),
///   plus `--follow` when `follow`;
/// * `since` absent, `follow`: `--lines=0 --follow` (start at the tail, like upstream's
///   `seek_tail` at start-up, then only new entries);
/// * neither: `--no-tail` (the whole journal).
///
/// `--no-tail` overrides journalctl's implicit "last 10 lines" default of follow mode.
pub fn journalctl_args(
    resolved: &ResolvedJournal,
    matches: &JournalMatches,
    since: Option<f64>,
    follow: bool,
) -> io::Result<Vec<String>> {
    let mut args: Vec<String> = ["--output=export", "--no-pager", "--quiet"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    args.extend(resolved.to_journalctl_args()?);
    match since {
        Some(t) => {
            args.push(since_arg(t)?);
            args.push("--no-tail".to_owned());
        }
        None if follow => args.push("--lines=0".to_owned()),
        None => args.push("--no-tail".to_owned()),
    }
    if follow {
        args.push("--follow".to_owned());
    }
    args.extend(matches.to_journalctl_args());
    Ok(args)
}

/// A running `journalctl` whose export output is parsed into [`JournalEntry`] values.
///
/// Dropping the reader kills and reaps the child.
#[derive(Debug)]
pub struct JournalReader {
    child: Child,
    rx: Option<Receiver<JournalEntry>>,
    finished: Arc<AtomicBool>,
    stderr_tail: Arc<Mutex<VecDeque<String>>>,
}

impl JournalReader {
    /// Start `journalctl` for `opts` (resolved with [`JournalOptions::resolve`]), `matches`,
    /// the start time `since` (epoch seconds) and `follow`; see [`journalctl_args`] for the
    /// exact arguments. The program is `opts.journalctl`, else `$F2B_JOURNALCTL`, else
    /// `journalctl`. Nothing is run through a shell.
    pub fn spawn(
        opts: &JournalOptions,
        matches: &JournalMatches,
        since: Option<f64>,
        follow: bool,
    ) -> io::Result<Self> {
        let resolved = opts.resolve()?;
        Self::spawn_resolved(
            &opts.journalctl_program(),
            &resolved,
            matches,
            since,
            follow,
        )
    }

    /// Like [`JournalReader::spawn`] with an already resolved source and an explicit program.
    pub fn spawn_resolved(
        program: &OsStr,
        resolved: &ResolvedJournal,
        matches: &JournalMatches,
        since: Option<f64>,
        follow: bool,
    ) -> io::Result<Self> {
        let args = journalctl_args(resolved, matches, since, follow)?;
        let mut child = Command::new(program)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let stdout = child.stdout.take().expect("stdout is piped");
        let stderr = child.stderr.take().expect("stderr is piped");

        let (tx, rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
        let finished = Arc::new(AtomicBool::new(false));
        let done = Arc::clone(&finished);
        thread::Builder::new()
            .name("f2b-journal-reader".into())
            .spawn(move || {
                for item in parse_export(BufReader::with_capacity(64 * 1024, stdout)) {
                    match item {
                        Ok(entry) => {
                            if tx.send(entry).is_err() {
                                break; // reader dropped
                            }
                        }
                        Err(e) => {
                            log::debug!("journalctl export stream ended: {e}");
                            break;
                        }
                    }
                }
                done.store(true, Ordering::Release);
            })?;

        let stderr_tail = Arc::new(Mutex::new(VecDeque::new()));
        let tail = Arc::clone(&stderr_tail);
        thread::Builder::new()
            .name("f2b-journal-stderr".into())
            .spawn(move || {
                for line in BufReader::new(stderr).split(b'\n').map_while(Result::ok) {
                    let line = String::from_utf8_lossy(&line).into_owned();
                    log::warn!("journalctl: {line}");
                    if let Ok(mut t) = tail.lock() {
                        if t.len() == STDERR_TAIL_LINES {
                            t.pop_front();
                        }
                        t.push_back(line);
                    }
                }
            })?;

        Ok(Self {
            child,
            rx: Some(rx),
            finished,
            stderr_tail,
        })
    }

    /// The next entry if one is already available.
    pub fn try_next(&mut self) -> Option<JournalEntry> {
        self.rx.as_ref()?.try_recv().ok()
    }

    /// The next entry, waiting up to `timeout`.
    pub fn next_timeout(&mut self, timeout: Duration) -> Option<JournalEntry> {
        self.rx.as_ref()?.recv_timeout(timeout).ok()
    }

    /// `false` once `journalctl`'s output has ended (the process exited, or its stream broke).
    /// Entries already parsed stay available through [`JournalReader::try_next`]; upstream's
    /// equivalent is the "journal reader seems to be offline" check.
    pub fn is_alive(&self) -> bool {
        !self.finished.load(Ordering::Acquire)
    }

    /// The exit status of `journalctl` if it has already terminated.
    pub fn exit_status(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }

    /// The last lines `journalctl` wrote to stderr (oldest first).
    pub fn stderr_tail(&self) -> Vec<String> {
        self.stderr_tail
            .lock()
            .map(|t| t.iter().cloned().collect())
            .unwrap_or_default()
    }
}

impl Drop for JournalReader {
    fn drop(&mut self) {
        // unblock the parser thread if it waits on a full channel, then stop and reap the child
        self.rx = None;
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
