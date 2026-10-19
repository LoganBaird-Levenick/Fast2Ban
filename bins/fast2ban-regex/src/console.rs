//! Process-wide stdout/stderr, shared by the tool's own `print`s and the log
//! handler so both interleave in call order (as Python's `sys.stdout` does).
//!
//! Output is buffered; [`flush`] must run before the process exits. A closed
//! pipe ends the process quietly with status 0, like upstream's
//! `_loc_except_hook` does for `BrokenPipeError`/`EPIPE`.

use std::io::{self, BufWriter, Write};
use std::sync::{Mutex, MutexGuard, PoisonError};

static STDOUT: Mutex<Option<BufWriter<io::Stdout>>> = Mutex::new(None);

fn lock() -> MutexGuard<'static, Option<BufWriter<io::Stdout>>> {
    STDOUT.lock().unwrap_or_else(PoisonError::into_inner)
}

fn broken_pipe(e: &io::Error) -> ! {
    // pipe seems to be closed (head / tail / etc), thus simply exit
    let _ = e;
    std::process::exit(0);
}

/// `print(text)` to stdout.
pub fn out(text: &str) {
    let mut g = lock();
    let w = g.get_or_insert_with(|| BufWriter::with_capacity(64 * 1024, io::stdout()));
    let r = w
        .write_all(text.as_bytes())
        .and_then(|()| w.write_all(b"\n"));
    if let Err(e) = r {
        broken_pipe(&e);
    }
}

/// Write `text` verbatim (no added newline) to stdout.
pub fn out_raw(text: &str) {
    let mut g = lock();
    let w = g.get_or_insert_with(|| BufWriter::with_capacity(64 * 1024, io::stdout()));
    if let Err(e) = w.write_all(text.as_bytes()) {
        broken_pipe(&e);
    }
}

/// Write `text` verbatim to stderr (stdout is flushed first to keep ordering).
pub fn err_raw(text: &str) {
    flush();
    let mut e = io::stderr().lock();
    let _ = e.write_all(text.as_bytes());
    let _ = e.flush();
}

/// Flush buffered stdout.
pub fn flush() {
    let mut g = lock();
    if let Some(w) = g.as_mut() {
        if let Err(e) = w.flush() {
            broken_pipe(&e);
        }
    }
}
