//! Port of `Fail2banReader` (`fail2ban/client/fail2banreader.py`): the global
//! `fail2ban.conf` options.

use std::rc::Rc;

use indexmap::IndexMap;

use crate::arg::{Arg, Command, Val};
use crate::error::{ConfigError, Result};
use crate::fs::Fs;
use crate::reader::{ConfigReader, Def, OptDef, Share, Ty, opt};

const MAIN_OPTS: &[OptDef] = &[
    opt(Ty::Str, "loglevel", Def::Str("INFO")),
    opt(Ty::Str, "logtarget", Def::Str("STDERR")),
    opt(Ty::Str, "syslogsocket", Def::Str("auto")),
    opt(Ty::Str, "allowipv6", Def::Str("auto")),
    opt(
        Ty::Str,
        "dbfile",
        Def::Str("/var/lib/fail2ban/fail2ban.sqlite3"),
    ),
    opt(Ty::Int, "dbmaxmatches", Def::None),
    opt(Ty::Str, "dbpurgeage", Def::Str("1d")),
];

/// `Fail2banReader.getEarlyOptions` template.
const EARLY_OPTS: &[OptDef] = &[
    opt(
        Ty::Str,
        "socket",
        Def::Str("/var/run/fail2ban/fail2ban.sock"),
    ),
    opt(
        Ty::Str,
        "pidfile",
        Def::Str("/var/run/fail2ban/fail2ban.pid"),
    ),
    opt(Ty::Str, "loglevel", Def::Str("INFO")),
    opt(Ty::Str, "logtarget", Def::Str("/var/log/fail2ban.log")),
    opt(Ty::Str, "syslogsocket", Def::Str("auto")),
];

const THREAD_OPTS: &[OptDef] = &[opt(Ty::Int, "stacksize", Def::None)];

/// Order of the generated `set` commands (ties broken by option name).
fn order(name: &str) -> Option<u8> {
    Some(match name {
        "thread" => 0,
        "syslogsocket" => 11,
        "loglevel" => 12,
        "logtarget" => 13,
        "allowipv6" => 14,
        "dbfile" => 50,
        "dbmaxmatches" | "dbpurgeage" => 51,
        _ => return None,
    })
}

/// `helpers.str2LogLevel` validity check (names of the standard + fail2ban levels).
pub fn check_log_level(v: &str) -> Result<()> {
    if v.chars().all(|c| c.is_ascii_digit()) && !v.is_empty() {
        return Ok(());
    }
    const LEVELS: &[&str] = &[
        "CRITICAL",
        "FATAL",
        "ERROR",
        "WARN",
        "WARNING",
        "NOTICE",
        "INFO",
        "DEBUG",
        "TRACEDEBUG",
        "HEAVYDEBUG",
        "MSG",
        "NOTSET",
    ];
    if LEVELS.contains(&v.to_uppercase().as_str()) {
        Ok(())
    } else {
        Err(ConfigError::Value(format!(
            "Invalid log level {}",
            crate::pyutil::py_repr(v)
        )))
    }
}

#[derive(Debug)]
pub struct Fail2banReader {
    base: ConfigReader,
    opts: IndexMap<String, Val>,
    thread: Option<IndexMap<String, Val>>,
}

impl Fail2banReader {
    pub fn new(fs: Rc<dyn Fs>, share: Share) -> Self {
        Self {
            base: ConfigReader::with_share(fs, share, None),
            opts: IndexMap::new(),
            thread: None,
        }
    }

    pub fn set_base_dir(&mut self, dir: &str) {
        self.base.set_base_dir(dir);
    }

    pub fn base_dir(&self) -> Option<String> {
        self.base.base_dir()
    }

    pub fn read(&mut self) -> Result<bool> {
        self.base.read("fail2ban")
    }

    /// `Fail2banReader.getEarlyOptions`: socket, pidfile and logging options
    /// (with their built-in defaults) needed before the full configuration.
    pub fn get_early_options(&self) -> Result<IndexMap<String, Val>> {
        self.base
            .get_options("Definition", EARLY_OPTS, &IndexMap::new(), false, true)
    }

    /// `Fail2banReader.getOptions(updateMainOpt)`.
    pub fn get_options(&mut self, update_main_opt: &IndexMap<String, Val>) -> Result<()> {
        let empty = IndexMap::new();
        let mut opts = self
            .base
            .get_options("Definition", MAIN_OPTS, &empty, false, true)?;
        for (k, v) in update_main_opt {
            opts.insert(k.clone(), v.clone());
        }
        let level = opts.get("loglevel").map(Val::py_str);
        if let Some(l) = level {
            check_log_level(&l)?;
        }
        self.thread = None;
        if self.base.has_section("Thread") {
            let t = self
                .base
                .get_options("Thread", THREAD_OPTS, &empty, false, true)?;
            if !t.is_empty() {
                self.thread = Some(t);
            }
        }
        self.opts = opts;
        Ok(())
    }

    /// `Fail2banReader.convert`.
    pub fn convert(&self) -> Vec<Command> {
        let mut items: Vec<(u8, String, Command)> = Vec::new();
        if let Some(t) = &self.thread {
            let map = t
                .iter()
                .map(|(k, v)| (k.clone(), v.clone().into_arg()))
                .collect();
            items.push((
                0,
                "thread".to_owned(),
                vec![Arg::from("set"), Arg::from("thread"), Arg::Map(map)],
            ));
        }
        for (k, v) in &self.opts {
            if k == "thread" {
                continue;
            }
            if let Some(o) = order(k) {
                items.push((
                    o,
                    k.clone(),
                    vec![
                        Arg::from("set"),
                        Arg::from(k.as_str()),
                        v.clone().into_arg(),
                    ],
                ));
            }
        }
        items.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
        items.into_iter().map(|(_, _, c)| c).collect()
    }
}
