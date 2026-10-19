//! Daemon logging backend: a runtime-switchable [`log::Log`] implementation
//! with the semantics of upstream's `Server.setLogLevel` / `setLogTarget` /
//! `setSyslogSocket` / `flushLogs` and the `fail2ban` Python logger.
//!
//! # Levels and the `log` crate
//!
//! Upstream levels (`logging.*`, see `fail2ban/__init__.py`) are numeric:
//! `CRITICAL`=50 `ERROR`=40 `WARNING`=30 `NOTICE`=25 `INFO`=20 `MSG`=15
//! `DEBUG`=10 `TRACEDEBUG`=7 `HEAVYDEBUG`=5 (names printed: `TRACE`, `HEAVY`,
//! `MSG`, ...). They map onto `log` as:
//!
//! | `log` record                                      | upstream  | level name |
//! |---------------------------------------------------|-----------|------------|
//! | `error!`                                          | ERROR     | `ERROR`    |
//! | `warn!`                                           | WARNING   | `WARNING`  |
//! | `log!(target: NOTICE_TARGET, Level::Info, ..)`    | NOTICE    | `NOTICE`   |
//! | `info!`                                           | INFO      | `INFO`     |
//! | `debug!`                                          | DEBUG     | `DEBUG`    |
//! | `trace!`                                          | TRACEDEBUG| `TRACE`    |
//! | `log!(target: HEAVY_TARGET, Level::Trace, ..)`    | HEAVYDEBUG| `HEAVY`    |
//!
//! There is no `CRITICAL` record (the `log` crate has no such level);
//! `CRITICAL` is accepted as a threshold only (it silences everything below).
//! Use the [`notice!`](crate::notice) macro for NOTICE records. The logger
//! name of NOTICE/HEAVY records comes from the record's `module_path`, other
//! records use their `target` (the module path by default); see
//! [`logger_name`].
//!
//! # Targets
//!
//! `STDOUT` (`SYSOUT` too), `STDERR`, `SYSLOG`, a file path (append mode,
//! created when missing), `INHERITED` (only records the name, like upstream).
//! Options `target[facility=..,padding=..,datetime=..,format=..]` are
//! parsed like upstream. `SYSTEMD-JOURNAL` is **not supported** in this build:
//! selecting it returns an error and leaves the previous target in place.
//!
//! # Differences from upstream
//!
//! * `level()` returns the upper-cased text given (upstream does the same:
//!   `"debug"` -> `"DEBUG"`, `"10"` -> `"10"`); the initial value is `INFO`
//!   and the initial target `STDOUT` (upstream starts unset).
//! * `format` supports only the keys `asctime`, `name`, `process`,
//!   `levelname`, `levelno`, `message` (with `-`/width/`.precision`); other
//!   keys are rejected when the target is set. The verbose (`-v`) formats of
//!   upstream are not implemented.
//! * `set_syslog_socket` really reconnects a `SYSLOG` target (upstream's
//!   reload is short-circuited by its own "same target" check).
//! * Syslog priorities follow upstream's `SysLogHandler` mapping, i.e. NOTICE,
//!   TRACE and HEAVY are sent with the `warning` priority.
//! * `flush()` decides between "rolled over" and "flushed" by the real sink
//!   kind, not by the case-sensitive target string.

use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use f2b_date::LocalZone;
use log::{Level, LevelFilter, Log, Metadata, Record, SetLoggerError};

/// `log` target marking a record as upstream NOTICE (use with `Level::Info`).
pub const NOTICE_TARGET: &str = "f2b::notice";
/// `log` target marking a record as upstream HEAVYDEBUG (use with `Level::Trace`).
pub const HEAVY_TARGET: &str = "f2b::heavy";

/// Log a NOTICE record (`logging.NOTICE`, level 25).
#[macro_export]
macro_rules! notice {
    ($($arg:tt)+) => {
        ::log::log!(target: $crate::logging::NOTICE_TARGET, ::log::Level::Info, $($arg)+)
    };
}

/// Numeric upstream levels.
const L_CRITICAL: i64 = 50;
const L_ERROR: i64 = 40;
const L_WARNING: i64 = 30;
const L_NOTICE: i64 = 25;
const L_INFO: i64 = 20;
const L_DEBUG: i64 = 10;
const L_TRACE: i64 = 7;
const L_HEAVY: i64 = 5;

const DEFAULT_TEMPLATE_PADDED: &str = "%(name)-24s[%(process)d]: %(levelname)-7s %(message)s";
const DEFAULT_TEMPLATE_PLAIN: &str = "%(name)s[%(process)d]: %(levelname)s %(message)s";

/// Python `repr()` of a string (enough for error messages).
fn py_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// `helpers.str2LogLevel` for an already upper-cased value: numeric text or a
/// level name; returns the numeric threshold.
///
/// # Errors
/// `Invalid log level 'X'` like upstream's `ValueError`.
pub fn parse_level(value: &str) -> Result<i64, String> {
    if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(value.parse::<i64>().unwrap_or(i64::MAX));
    }
    Ok(match value.to_uppercase().as_str() {
        "CRITICAL" | "FATAL" => L_CRITICAL,
        "ERROR" => L_ERROR,
        "WARNING" | "WARN" => L_WARNING,
        "NOTICE" => L_NOTICE,
        "INFO" => L_INFO,
        "MSG" => 15,
        "DEBUG" => L_DEBUG,
        "TRACEDEBUG" => L_TRACE,
        "HEAVYDEBUG" => L_HEAVY,
        "NOTSET" => 0,
        _ => return Err(format!("Invalid log level {}", py_repr(value))),
    })
}

/// Numeric upstream level and level name of a `log` record kind.
fn classify(level: Level, target: &str) -> (i64, &'static str) {
    match level {
        Level::Error => (L_ERROR, "ERROR"),
        Level::Warn => (L_WARNING, "WARNING"),
        Level::Info if target == NOTICE_TARGET => (L_NOTICE, "NOTICE"),
        Level::Info => (L_INFO, "INFO"),
        Level::Debug => (L_DEBUG, "DEBUG"),
        Level::Trace if target == HEAVY_TARGET => (L_HEAVY, "HEAVY"),
        Level::Trace => (L_TRACE, "TRACE"),
    }
}

/// Most verbose `log` filter that can still pass `threshold`.
fn filter_for(threshold: i64) -> LevelFilter {
    match threshold {
        i64::MIN..=L_TRACE => LevelFilter::Trace,
        8..=L_DEBUG => LevelFilter::Debug,
        11..=L_NOTICE => LevelFilter::Info,
        26..=L_WARNING => LevelFilter::Warn,
        31..=L_ERROR => LevelFilter::Error,
        _ => LevelFilter::Off,
    }
}

/// Upstream logger name (`fail2ban.<component>`) for a Rust module path.
#[must_use]
pub fn logger_name(path: &str) -> String {
    let mut segs = path.split("::");
    let krate = segs.next().unwrap_or("");
    let second = segs.next();
    let comp = match (krate, second) {
        ("f2b_server", Some("server")) => "server",
        ("f2b_server", Some("transmitter")) => "transmitter",
        ("f2b_action", Some("jail")) => "jail",
        ("f2b_action", Some("actions")) => "actions",
        ("f2b_action", Some("observer")) => "observer",
        ("f2b_filter", _) => "filter",
        ("f2b_db", _) => "database",
        ("f2b_server", Some("logging")) => "server",
        _ => path.rsplit("::").next().unwrap_or(path),
    };
    format!("fail2ban.{comp}")
}

/// One record, ready to be formatted.
#[derive(Debug, Clone, Copy)]
pub struct Entry<'a> {
    /// Unix seconds.
    pub secs: i64,
    /// Millisecond part of the timestamp.
    pub millis: u32,
    /// Logger name (`fail2ban.server`).
    pub name: &'a str,
    /// Numeric upstream level.
    pub levelno: i64,
    /// Upstream level name.
    pub levelname: &'a str,
    /// Message text.
    pub message: &'a str,
    /// Process id.
    pub pid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Key {
    Asctime,
    Name,
    Process,
    LevelName,
    LevelNo,
    Message,
}

#[derive(Debug, Clone)]
enum Piece {
    Lit(String),
    Field {
        key: Key,
        left: bool,
        width: usize,
        prec: Option<usize>,
    },
}

/// A compiled Python `%(key)s`-style log format.
#[derive(Debug, Clone)]
pub struct Formatter {
    pieces: Vec<Piece>,
    zone: LocalZone,
}

impl Formatter {
    /// Compile `template` (supported: `%(asctime|name|process|levelname|levelno|message)`
    /// with optional `-`, width and `.precision`, type `s` or `d`, and `%%`).
    ///
    /// # Errors
    /// Text describing the unsupported/invalid construct.
    pub fn new(template: &str, zone: LocalZone) -> Result<Self, String> {
        let mut pieces = Vec::new();
        let mut lit = String::new();
        let mut it = template.chars().peekable();
        while let Some(c) = it.next() {
            if c != '%' {
                lit.push(c);
                continue;
            }
            if it.peek() == Some(&'%') {
                it.next();
                lit.push('%');
                continue;
            }
            if it.next() != Some('(') {
                return Err(format!("unsupported log format {}", py_repr(template)));
            }
            let mut key = String::new();
            loop {
                match it.next() {
                    Some(')') => break,
                    Some(c) => key.push(c),
                    None => return Err(format!("incomplete format key in {}", py_repr(template))),
                }
            }
            let key = match key.as_str() {
                "asctime" => Key::Asctime,
                "name" => Key::Name,
                "process" => Key::Process,
                "levelname" => Key::LevelName,
                "levelno" => Key::LevelNo,
                "message" => Key::Message,
                other => return Err(format!("unsupported log format key {}", py_repr(other))),
            };
            let left = it.peek() == Some(&'-');
            if left {
                it.next();
            }
            let mut width = String::new();
            while let Some(d) = it.next_if(char::is_ascii_digit) {
                width.push(d);
            }
            let prec = if it.next_if_eq(&'.').is_some() {
                let mut p = String::new();
                while let Some(d) = it.next_if(char::is_ascii_digit) {
                    p.push(d);
                }
                Some(p.parse().unwrap_or(0))
            } else {
                None
            };
            match it.next() {
                Some('s') => {}
                Some('d') if matches!(key, Key::Process | Key::LevelNo) => {}
                _ => return Err(format!("unsupported log format {}", py_repr(template))),
            }
            if !lit.is_empty() {
                pieces.push(Piece::Lit(std::mem::take(&mut lit)));
            }
            pieces.push(Piece::Field {
                key,
                left,
                width: width.parse().unwrap_or(0),
                prec,
            });
        }
        if !lit.is_empty() {
            pieces.push(Piece::Lit(lit));
        }
        Ok(Self { pieces, zone })
    }

    /// Upstream's `getVerbosityFormat(0, addtime, padding)`.
    ///
    /// # Panics
    /// Never (the built-in templates are valid).
    #[must_use]
    pub fn default_for(addtime: bool, padding: bool, zone: LocalZone) -> Self {
        let base = if padding {
            DEFAULT_TEMPLATE_PADDED
        } else {
            DEFAULT_TEMPLATE_PLAIN
        };
        let template = if addtime {
            format!("%(asctime)s {base}")
        } else {
            base.to_owned()
        };
        Self::new(&template, zone).expect("built-in template is valid")
    }

    /// `asctime`: `YYYY-MM-DD HH:MM:SS,mmm` in the local zone.
    fn asctime(&self, e: &Entry<'_>) -> String {
        let f = self.zone.local_fields(e.secs as f64);
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02},{:03}",
            f.year, f.month, f.day, f.hour, f.minute, f.second, e.millis
        )
    }

    /// Format one record (no trailing newline).
    #[must_use]
    pub fn format(&self, e: &Entry<'_>) -> String {
        let mut out = String::with_capacity(e.message.len() + 64);
        for p in &self.pieces {
            match p {
                Piece::Lit(s) => out.push_str(s),
                Piece::Field {
                    key,
                    left,
                    width,
                    prec,
                } => {
                    let owned;
                    let mut val: &str = match key {
                        Key::Asctime => {
                            owned = self.asctime(e);
                            &owned
                        }
                        Key::Name => e.name,
                        Key::Process => {
                            owned = e.pid.to_string();
                            &owned
                        }
                        Key::LevelName => e.levelname,
                        Key::LevelNo => {
                            owned = e.levelno.to_string();
                            &owned
                        }
                        Key::Message => e.message,
                    };
                    if let Some(n) = prec
                        && let Some((idx, _)) = val.char_indices().nth(*n)
                    {
                        val = &val[..idx];
                    }
                    let pad = width.saturating_sub(val.chars().count());
                    if !*left {
                        out.extend(std::iter::repeat_n(' ', pad));
                    }
                    out.push_str(val);
                    if *left {
                        out.extend(std::iter::repeat_n(' ', pad));
                    }
                }
            }
        }
        out
    }
}

#[derive(Debug)]
enum SyslogConn {
    Dgram(UnixDatagram),
    Stream(UnixStream),
}

impl SyslogConn {
    /// `SysLogHandler._connect_unixsocket`: datagram first, then stream.
    fn connect(path: &std::path::Path) -> Option<Self> {
        if let Ok(s) = UnixDatagram::unbound()
            && s.connect(path).is_ok()
        {
            return Some(Self::Dgram(s));
        }
        UnixStream::connect(path).ok().map(Self::Stream)
    }

    fn send(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Dgram(s) => s.send(buf).map(drop),
            Self::Stream(s) => s.write_all(buf),
        }
    }
}

#[derive(Debug)]
enum Sink {
    Stdout,
    Stderr,
    File {
        path: PathBuf,
        file: File,
    },
    Syslog {
        path: PathBuf,
        facility: u8,
        conn: Option<SyslogConn>,
    },
}

/// `SysLogHandler.priority_map` / default `warning`.
fn syslog_priority(levelname: &str) -> u8 {
    match levelname {
        "DEBUG" => 7,
        "INFO" => 6,
        "ERROR" => 3,
        "CRITICAL" => 2,
        _ => 4,
    }
}

fn facility_code(name: &str) -> Option<u8> {
    Some(match name {
        "KERN" => 0,
        "USER" => 1,
        "MAIL" => 2,
        "DAEMON" => 3,
        "AUTH" => 4,
        "SYSLOG" => 5,
        "LPR" => 6,
        "NEWS" => 7,
        "UUCP" => 8,
        "CRON" => 9,
        "AUTHPRIV" => 10,
        "FTP" => 11,
        "LOCAL0" => 16,
        "LOCAL1" => 17,
        "LOCAL2" => 18,
        "LOCAL3" => 19,
        "LOCAL4" => 20,
        "LOCAL5" => 21,
        "LOCAL6" => 22,
        "LOCAL7" => 23,
        _ => return None,
    })
}

fn open_append(path: &str) -> std::io::Result<File> {
    OpenOptions::new().append(true).create(true).open(path)
}

impl Sink {
    /// Write one formatted line; I/O errors drop the record.
    fn write(&mut self, line: &str, levelname: &str) {
        match self {
            Self::Stdout => {
                let mut out = std::io::stdout().lock();
                let _ = out.write_all(format!("{line}\n").as_bytes());
                let _ = out.flush();
            }
            Self::Stderr => {
                let _ = std::io::stderr()
                    .lock()
                    .write_all(format!("{line}\n").as_bytes());
            }
            Self::File { file, .. } => {
                let _ = file.write_all(format!("{line}\n").as_bytes());
            }
            Self::Syslog {
                path,
                facility,
                conn,
            } => {
                let mut msg = String::with_capacity(line.len() + 8);
                let _ = write!(
                    msg,
                    "<{}>{line}",
                    (u32::from(*facility) << 3) | u32::from(syslog_priority(levelname))
                );
                let mut bytes = msg.into_bytes();
                bytes.push(0);
                if let Some(c) = conn
                    && c.send(&bytes).is_ok()
                {
                    return;
                }
                // reconnect once (syslogd restart)
                *conn = SyslogConn::connect(path);
                if let Some(c) = conn
                    && c.send(&bytes).is_err()
                {
                    *conn = None;
                }
            }
        }
    }
}

#[derive(Debug)]
struct State {
    level: String,
    target: String,
    /// False until a target was explicitly set (upstream is silent then).
    configured: bool,
    syslog_socket: String,
    sink: Sink,
    formatter: Formatter,
    zone: LocalZone,
}

/// Default syslog socket for this platform (`__autoSyslogSocketPaths`).
fn auto_syslog_socket() -> Option<&'static str> {
    if cfg!(target_os = "macos") {
        Some("/var/run/syslog")
    } else if cfg!(target_os = "freebsd") {
        Some("/var/run/log")
    } else if cfg!(target_os = "linux") {
        Some("/dev/log")
    } else {
        None
    }
}

/// The daemon logger. Use [`Logging::install`] for the process-wide instance;
/// [`Logging::new`] builds an independent (non-global) one.
#[derive(Debug)]
pub struct Logging {
    threshold: AtomicI64,
    global: AtomicBool,
    state: Mutex<State>,
}

static GLOBAL: LazyLock<Logging> = LazyLock::new(|| {
    let l = Logging::new();
    l.global.store(true, Ordering::Relaxed);
    l
});
static INSTALLED: Mutex<bool> = Mutex::new(false);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Default for Logging {
    fn default() -> Self {
        Self::new()
    }
}

impl Logging {
    /// New logger: level `INFO`, target `STDOUT`, syslog socket `auto`.
    #[must_use]
    pub fn new() -> Self {
        let zone = LocalZone::system();
        Self {
            threshold: AtomicI64::new(L_INFO),
            global: AtomicBool::new(false),
            state: Mutex::new(State {
                level: "INFO".into(),
                target: "STDOUT".into(),
                configured: false,
                syslog_socket: "auto".into(),
                sink: Sink::Stdout,
                formatter: Formatter::default_for(true, true, zone.clone()),
                zone,
            }),
        }
    }

    /// Install the process-wide logger (idempotent) and return it.
    ///
    /// # Errors
    /// Another `log` logger is already installed.
    pub fn install() -> Result<&'static Self, SetLoggerError> {
        let me: &'static Self = &GLOBAL;
        let mut done = lock(&INSTALLED);
        if !*done {
            log::set_logger(me)?;
            *done = true;
        }
        drop(done);
        me.sync_max_level();
        Ok(me)
    }

    /// The installed process-wide logger, if any.
    #[must_use]
    pub fn global() -> Option<&'static Self> {
        if *lock(&INSTALLED) {
            Some(&GLOBAL)
        } else {
            None
        }
    }

    fn sync_max_level(&self) {
        if self.global.load(Ordering::Relaxed) {
            log::set_max_level(filter_for(self.threshold.load(Ordering::Relaxed)));
        }
    }

    /// `Server.setLogLevel`: name (case-insensitive) or number.
    ///
    /// # Errors
    /// `Invalid log level 'X'`.
    pub fn set_level(&self, value: &str) -> Result<(), String> {
        let value = value.to_uppercase();
        {
            let mut st = lock(&self.state);
            if st.level == value {
                return Ok(());
            }
            let ll = parse_level(&value)?;
            st.level = value;
            self.threshold.store(ll, Ordering::Relaxed);
        }
        self.sync_max_level();
        Ok(())
    }

    /// `Server.getLogLevel`: the upper-cased value last set.
    #[must_use]
    pub fn level(&self) -> String {
        lock(&self.state).level.clone()
    }

    /// `Server.setLogTarget`; on failure the previous target stays active.
    ///
    /// # Errors
    /// Option syntax error, unsupported target, unusable syslog socket or
    /// unwritable file (upstream returns `False`).
    pub fn set_target(&self, target: &str) -> Result<(), String> {
        self.apply_target(target, false)
    }

    fn apply_target(&self, target: &str, force: bool) -> Result<(), String> {
        let (target, opts) = f2b_helpers::extract_options(target).map_err(|e| e.to_string())?;
        let systarget = target.to_uppercase();
        let mut msgs: Vec<(i64, &'static str, String)> = Vec::new();
        let result = {
            let mut st = lock(&self.state);
            if st.target == target && !force {
                return Ok(());
            }
            if systarget == "INHERITED" {
                st.target = target;
                return Ok(());
            }
            let r = Self::build(&mut st, &target, &systarget, &opts, &mut msgs);
            if let Ok((sink, formatter)) = r {
                st.sink = sink;
                st.formatter = formatter;
                if st.configured {
                    let shown = if target == "SYSLOG" {
                        format!("{target} ({})", st.syslog_socket)
                    } else {
                        target.clone()
                    };
                    let v = env!("CARGO_PKG_VERSION");
                    msgs.push((L_INFO, "INFO", format!("Start Fail2ban v{v}")));
                    msgs.push((
                        L_INFO,
                        "INFO",
                        format!("Changed logging target to {shown} for Fail2ban v{v}"),
                    ));
                }
                st.configured = true;
                st.target = target;
                Ok(())
            } else {
                let prev = st.target.clone();
                if !msgs.is_empty() {
                    msgs.push((
                        L_INFO,
                        "INFO",
                        format!("Logging to previous target {}", py_repr(&prev)),
                    ));
                }
                r.map(drop)
            }
        };
        for (no, name, m) in msgs {
            self.emit(no, name, "fail2ban.server", &m);
        }
        result
    }

    fn build(
        st: &mut State,
        target: &str,
        systarget: &str,
        opts: &indexmap::IndexMap<String, String>,
        msgs: &mut Vec<(i64, &'static str, String)>,
    ) -> Result<(Sink, Formatter), String> {
        let mut padding = opts.get("padding").cloned();
        let sink = match systarget {
            "SYSTEMD-JOURNAL" => {
                return Err("SYSTEMD-JOURNAL logging target is not supported by this build".into());
            }
            "SYSLOG" => {
                let fac_opt = opts.get("facility").map_or("DAEMON", String::as_str);
                let facility = facility_code(&fac_opt.to_uppercase()).unwrap_or_else(|| {
                    msgs.push((
                        L_ERROR,
                        "ERROR",
                        format!(
                            "Unable to set facility {}, using 'DAEMON'",
                            py_repr(fac_opt)
                        ),
                    ));
                    3
                });
                if padding.is_none() {
                    padding = Some("0".into());
                }
                if st.syslog_socket == "auto"
                    && let Some(p) = auto_syslog_socket()
                {
                    st.syslog_socket = p.into();
                }
                let path = PathBuf::from(&st.syslog_socket);
                let is_sock = std::fs::metadata(&path).is_ok_and(|m| m.file_type().is_socket());
                if !is_sock {
                    let m = format!(
                        "Syslog socket file: {} does not exists or is not a socket",
                        st.syslog_socket
                    );
                    msgs.push((L_ERROR, "ERROR", m.clone()));
                    return Err(m);
                }
                let conn = SyslogConn::connect(&path);
                Sink::Syslog {
                    path,
                    facility,
                    conn,
                }
            }
            "STDOUT" | "SYSOUT" => Sink::Stdout,
            "STDERR" => Sink::Stderr,
            _ => match open_append(target) {
                Ok(file) => Sink::File {
                    path: PathBuf::from(target),
                    file,
                },
                Err(_) => {
                    let m = format!("Unable to log to {}", py_repr(target));
                    msgs.push((L_ERROR, "ERROR", m.clone()));
                    return Err(m);
                }
            },
        };
        let addtime = opts
            .get("datetime")
            .map_or(!matches!(systarget, "SYSLOG" | "SYSOUT"), |v| {
                f2b_helpers::as_bool(v)
            });
        let padding = padding.is_none_or(|v| f2b_helpers::as_bool(&v));
        let formatter = match opts.get("format").filter(|f| !f.is_empty()) {
            Some(fmt) => Formatter::new(fmt, st.zone.clone())?,
            None => Formatter::default_for(addtime, padding, st.zone.clone()),
        };
        Ok((sink, formatter))
    }

    /// `Server.getLogTarget`.
    #[must_use]
    pub fn target(&self) -> String {
        lock(&self.state).target.clone()
    }

    /// `Server.setSyslogSocket`: stores the path and, when the target is
    /// `SYSLOG`, reconnects to it.
    ///
    /// # Errors
    /// The reconnect failed (the new path stays stored, like upstream).
    pub fn set_syslog_socket(&self, path: &str) -> Result<(), String> {
        let reload = {
            let mut st = lock(&self.state);
            if st.syslog_socket == path {
                return Ok(());
            }
            st.syslog_socket = path.to_owned();
            st.target == "SYSLOG"
        };
        if reload {
            self.apply_target("SYSLOG", true)
        } else {
            Ok(())
        }
    }

    /// `Server.getSyslogSocket`.
    #[must_use]
    pub fn syslog_socket(&self) -> String {
        lock(&self.state).syslog_socket.clone()
    }

    /// `Server.flushLogs`: reopens a file target (logrotate hook) and returns
    /// `"rolled over"`; other targets are flushed and return `"flushed"`.
    ///
    /// # Errors
    /// The file could not be reopened (the old handle is kept).
    pub fn flush(&self) -> Result<&'static str, String> {
        let (msg, ret) = {
            let mut st = lock(&self.state);
            let target = st.target.clone();
            match &mut st.sink {
                Sink::File { path, file } => {
                    let new = open_append(&path.to_string_lossy())
                        .map_err(|e| format!("Unable to reopen {}: {e}", py_repr(&target)))?;
                    *file = new;
                    (format!("rollover performed on {target}"), "rolled over")
                }
                sink => {
                    match sink {
                        Sink::Stdout => drop(std::io::stdout().flush()),
                        Sink::Stderr => drop(std::io::stderr().flush()),
                        _ => {}
                    }
                    (format!("flush performed on {target}"), "flushed")
                }
            }
        };
        self.emit(L_INFO, "INFO", "fail2ban.server", &msg);
        Ok(ret)
    }

    fn emit(&self, levelno: i64, levelname: &str, name: &str, message: &str) {
        if levelno < self.threshold.load(Ordering::Relaxed) {
            return;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let entry = Entry {
            secs: now.as_secs() as i64,
            millis: now.subsec_millis(),
            name,
            levelno,
            levelname,
            message,
            pid: std::process::id(),
        };
        let mut st = lock(&self.state);
        let line = st.formatter.format(&entry);
        st.sink.write(&line, levelname);
    }
}

impl Log for Logging {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        classify(metadata.level(), metadata.target()).0 >= self.threshold.load(Ordering::Relaxed)
    }

    fn log(&self, record: &Record<'_>) {
        let (levelno, levelname) = classify(record.level(), record.target());
        if levelno < self.threshold.load(Ordering::Relaxed) {
            return;
        }
        let path = if record.target() == NOTICE_TARGET || record.target() == HEAVY_TARGET {
            record.module_path().unwrap_or("")
        } else {
            record.target()
        };
        self.emit(
            levelno,
            levelname,
            &logger_name(path),
            &record.args().to_string(),
        );
    }

    fn flush(&self) {
        let mut st = lock(&self.state);
        match &mut st.sink {
            Sink::Stdout => drop(std::io::stdout().flush()),
            Sink::Stderr => drop(std::io::stderr().flush()),
            Sink::File { file, .. } => drop(file.flush()),
            Sink::Syslog { .. } => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(level: Level, target: &str, module: &str, msg: &str, l: &Logging) {
        l.log(
            &Record::builder()
                .args(format_args!("{msg}"))
                .level(level)
                .target(target)
                .module_path(Some(module))
                .build(),
        );
    }

    fn utc_entry() -> Entry<'static> {
        Entry {
            secs: 1_792_365_305,
            millis: 80,
            name: "fail2ban.server",
            levelno: L_INFO,
            levelname: "INFO",
            message: "hello",
            pid: 42,
        }
    }

    #[test]
    fn level_table() {
        for (inp, want) in [
            ("critical", 50),
            ("ERROR", 40),
            ("warn", 30),
            ("Warning", 30),
            ("notice", 25),
            ("info", 20),
            ("debug", 10),
            ("tracedebug", 7),
            ("heavydebug", 5),
            ("msg", 15),
            ("10", 10),
            ("0", 0),
        ] {
            assert_eq!(parse_level(&inp.to_uppercase()), Ok(want), "{inp}");
        }
        assert_eq!(
            parse_level("FOO"),
            Err("Invalid log level 'FOO'".to_owned())
        );
        assert_eq!(parse_level("-1"), Err("Invalid log level '-1'".to_owned()));
        assert_eq!(parse_level(""), Err("Invalid log level ''".to_owned()));
    }

    #[test]
    fn level_getter_and_filter() {
        let l = Logging::new();
        assert_eq!(l.level(), "INFO");
        l.set_level("debug").unwrap();
        assert_eq!(l.level(), "DEBUG");
        l.set_level("10").unwrap();
        assert_eq!(l.level(), "10");
        assert!(l.set_level("bogus").is_err());
        assert_eq!(l.level(), "10");
        assert_eq!(filter_for(5), LevelFilter::Trace);
        assert_eq!(filter_for(7), LevelFilter::Trace);
        assert_eq!(filter_for(10), LevelFilter::Debug);
        assert_eq!(filter_for(20), LevelFilter::Info);
        assert_eq!(filter_for(25), LevelFilter::Info);
        assert_eq!(filter_for(30), LevelFilter::Warn);
        assert_eq!(filter_for(40), LevelFilter::Error);
        assert_eq!(filter_for(50), LevelFilter::Off);
    }

    #[test]
    fn names() {
        assert_eq!(logger_name("f2b_server::server"), "fail2ban.server");
        assert_eq!(
            logger_name("f2b_server::transmitter"),
            "fail2ban.transmitter"
        );
        assert_eq!(logger_name("f2b_action::jail"), "fail2ban.jail");
        assert_eq!(logger_name("f2b_action::actions::x"), "fail2ban.actions");
        assert_eq!(logger_name("f2b_action::observer"), "fail2ban.observer");
        assert_eq!(logger_name("f2b_filter::filter::y"), "fail2ban.filter");
        assert_eq!(logger_name("f2b_db::db"), "fail2ban.database");
        assert_eq!(logger_name("f2b_server::listener"), "fail2ban.listener");
        assert_eq!(logger_name("weird"), "fail2ban.weird");
    }

    #[test]
    fn formats_match_upstream() {
        let z = LocalZone::utc();
        // from upstream getVerbosityFormat(0, ...) via logging.Formatter
        let e = utc_entry();
        let f = Formatter::default_for(true, true, z.clone());
        assert_eq!(
            f.format(&e),
            "2026-10-18 23:15:05,080 fail2ban.server         [42]: INFO    hello"
        );
        let f = Formatter::default_for(false, false, z.clone());
        assert_eq!(f.format(&e), "fail2ban.server[42]: INFO hello");
        let f = Formatter::new("%(levelno)d|%(levelname)-7.4s|%(name).4s|%%", z).unwrap();
        assert_eq!(f.format(&e), "20|INFO   |fail|%");
        assert!(Formatter::new("%(thread)d", LocalZone::utc()).is_err());
        assert!(Formatter::new("%(name", LocalZone::utc()).is_err());
    }

    #[test]
    fn file_target_append_flush_and_failure() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f.log");
        let ps = p.to_str().unwrap();
        let l = Logging::new();
        l.set_target(ps).unwrap();
        assert_eq!(l.target(), ps);
        rec(Level::Info, "f2b_server::server", "x", "one", &l);
        rec(Level::Debug, "f2b_server::server", "x", "hidden", &l);
        // append across a second logger
        let l2 = Logging::new();
        l2.set_target(ps).unwrap();
        rec(Level::Warn, "f2b_action::jail", "x", "two", &l2);
        let text = std::fs::read_to_string(&p).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        let re_ok = |s: &str, tail: &str| {
            let b = s.as_bytes();
            s.len() > 24
                && b[4] == b'-'
                && b[10] == b' '
                && b[19] == b','
                && s[23..].starts_with(tail)
        };
        let pid = std::process::id();
        assert!(
            re_ok(
                lines[0],
                &format!(" fail2ban.server         [{pid}]: INFO    one")
            ),
            "{}",
            lines[0]
        );
        assert!(
            re_ok(
                lines[1],
                &format!(" fail2ban.jail           [{pid}]: WARNING two")
            ),
            "{}",
            lines[1]
        );

        // logrotate: rename, flush reopens a fresh file
        let rotated = dir.path().join("f.log.1");
        std::fs::rename(&p, &rotated).unwrap();
        rec(Level::Error, "f2b_server::server", "x", "to-old", &l);
        assert_eq!(l.flush(), Ok("rolled over"));
        rec(Level::Error, "f2b_server::server", "x", "to-new", &l);
        assert!(
            std::fs::read_to_string(&rotated)
                .unwrap()
                .contains("to-old")
        );
        let new = std::fs::read_to_string(&p).unwrap();
        assert!(new.contains("to-new") && !new.contains("to-old"), "{new}");

        // failure keeps the previous target
        let bad = dir.path().join("nodir/x.log");
        let err = l.set_target(bad.to_str().unwrap()).unwrap_err();
        assert!(err.starts_with("Unable to log to '"), "{err}");
        assert_eq!(l.target(), ps);
        rec(Level::Error, "f2b_server::server", "x", "still", &l);
        assert!(std::fs::read_to_string(&p).unwrap().contains("still"));
        assert!(l.set_target("SYSTEMD-JOURNAL").is_err());
        assert_eq!(l.target(), ps);
        assert!(l.set_target("STDOUT[").is_err());
    }

    #[test]
    fn notice_and_heavy_levels() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("n.log");
        let l = Logging::new();
        l.set_target(p.to_str().unwrap()).unwrap();
        l.set_level("NOTICE").unwrap();
        rec(Level::Info, NOTICE_TARGET, "f2b_action::actions", "ban", &l);
        rec(
            Level::Info,
            "f2b_action::actions",
            "f2b_action::actions",
            "info",
            &l,
        );
        l.set_level("HEAVYDEBUG").unwrap();
        rec(
            Level::Trace,
            HEAVY_TARGET,
            "f2b_filter::filter",
            "heavy",
            &l,
        );
        rec(
            Level::Trace,
            "f2b_filter::filter",
            "f2b_filter::filter",
            "trace",
            &l,
        );
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(
            text.contains("fail2ban.actions") && text.contains("NOTICE  ban"),
            "{text}"
        );
        assert!(!text.contains("info"), "{text}");
        assert!(
            text.contains("HEAVY   heavy") && text.contains("TRACE   trace"),
            "{text}"
        );
    }

    #[test]
    fn syslog_target_datagram() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("log.sock");
        let rx = UnixDatagram::bind(&sock).unwrap();
        rx.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let l = Logging::new();
        let missing = dir.path().join("none.sock");
        l.set_syslog_socket(missing.to_str().unwrap()).unwrap();
        let err = l.set_target("SYSLOG").unwrap_err();
        assert!(err.contains("does not exists or is not a socket"), "{err}");
        assert_eq!(l.target(), "STDOUT");
        l.set_syslog_socket(sock.to_str().unwrap()).unwrap();
        assert_eq!(l.syslog_socket(), sock.to_str().unwrap());
        l.set_target("SYSLOG").unwrap();
        rec(Level::Info, "f2b_server::server", "x", "hi", &l);
        let mut buf = [0u8; 512];
        let n = rx.recv(&mut buf).unwrap();
        let want = format!("<30>fail2ban.server[{}]: INFO hi\0", std::process::id());
        assert_eq!(&buf[..n], want.as_bytes());
        // facility option; NOTICE maps to the syslog `warning` priority
        let l = Logging::new();
        l.set_syslog_socket(sock.to_str().unwrap()).unwrap();
        l.set_target("SYSLOG[facility=local3]").unwrap();
        rec(Level::Info, NOTICE_TARGET, "f2b_server::server", "n", &l);
        let n = rx.recv(&mut buf).unwrap();
        let want = format!("<156>fail2ban.server[{}]: NOTICE n\0", std::process::id());
        assert_eq!(&buf[..n], want.as_bytes());
    }

    #[test]
    fn global_install_idempotent() {
        let a = Logging::install().unwrap();
        let b = Logging::install().unwrap();
        assert!(std::ptr::eq(a, b));
        assert!(Logging::global().is_some());
        a.set_level("DEBUG").unwrap();
        assert_eq!(log::max_level(), LevelFilter::Debug);
        a.set_level("ERROR").unwrap();
        assert_eq!(log::max_level(), LevelFilter::Error);
    }
}
