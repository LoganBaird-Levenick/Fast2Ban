//! Port of `JailReader` (`fail2ban/client/jailreader.py`).

use std::collections::HashSet;
use std::rc::Rc;

use f2b_helpers::{extract_options, split_with_options, splitwords};
use f2b_types::UPSTREAM_COMPAT_VERSION;
use indexmap::IndexMap;

use crate::arg::{Arg, Command, Val};
use crate::definition::{DefinitionReader, FILTER_OPTS, fill_stream};
use crate::error::{ConfigError, Result};
use crate::fs::Fs;
use crate::pyjson::dumps_str_map;
use crate::pyutil::{join, py_repr, py_strip, splitext_root};
use crate::reader::{Cfg, ConfigReader, Def, OptDef, Share, Ty, opt};

/// `JailReader._configOpts1st`
const JAIL_OPTS_1ST: &[OptDef] = &[
    opt(Ty::Bool, "enabled", Def::Bool(false)),
    opt(Ty::Str, "backend", Def::Str("auto")),
    opt(Ty::Str, "filter", Def::Str("")),
];

/// `JailReader._configOpts` (jail options, then the filter options).
const JAIL_OPTS: &[OptDef] = &[
    opt(Ty::Bool, "enabled", Def::Bool(false)),
    opt(Ty::Str, "backend", Def::Str("auto")),
    opt(Ty::Int, "maxretry", Def::None),
    opt(Ty::Int, "maxmatches", Def::None),
    opt(Ty::Str, "findtime", Def::None),
    opt(Ty::Str, "bantime", Def::None),
    opt(Ty::Bool, "bantime.increment", Def::None),
    opt(Ty::Str, "bantime.factor", Def::None),
    opt(Ty::Str, "bantime.formula", Def::None),
    opt(Ty::Str, "bantime.multipliers", Def::None),
    opt(Ty::Str, "bantime.maxtime", Def::None),
    opt(Ty::Str, "bantime.rndtime", Def::None),
    opt(Ty::Bool, "bantime.overalljails", Def::None),
    opt(Ty::Str, "ignorecommand", Def::None),
    opt(Ty::Bool, "ignoreself", Def::None),
    opt(Ty::Str, "ignoreip", Def::None),
    opt(Ty::Str, "ignorecache", Def::None),
    opt(Ty::Str, "filter", Def::Str("")),
    opt(Ty::Str, "logtimezone", Def::None),
    opt(Ty::Str, "logencoding", Def::None),
    opt(Ty::Str, "logpath", Def::None),
    opt(Ty::Bool, "skip_if_nologs", Def::Bool(false)),
    opt(Ty::Bool, "systemd_if_nologs", Def::Bool(true)),
    opt(Ty::Str, "action", Def::Str("")),
    // FilterReader._configOpts
    opt(Ty::Str, "usedns", Def::None),
    opt(Ty::Str, "prefregex", Def::None),
    opt(Ty::Str, "ignoreregex", Def::None),
    opt(Ty::Str, "failregex", Def::None),
    opt(Ty::Int, "maxlines", Def::None),
    opt(Ty::Str, "datepattern", Def::None),
    opt(Ty::Str, "journalmatch", Def::None),
];

/// `JailReader._ignoreOpts`: options not forwarded as plain `set` commands.
fn is_ignored_opt(name: &str) -> bool {
    matches!(
        name,
        "action" | "filter" | "enabled" | "backend" | "skip_if_nologs" | "systemd_if_nologs"
    ) || FILTER_OPTS.iter().any(|d| d.name == name)
}

/// Failure while reading a jail: `JailDefError` (turns the jail into a
/// `config-error` stub) or any other error (aborts configuration).
enum JailErr {
    Def(String),
    Other(ConfigError),
}

impl From<ConfigError> for JailErr {
    fn from(e: ConfigError) -> Self {
        Self::Other(e)
    }
}

#[derive(Debug)]
enum ActionEntry {
    Reader(Box<DefinitionReader>),
    /// Python (`.py`) action: ready-made `addaction` command.
    Py(Command),
}

/// Failure of [`JailReader::read`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JailReadError {
    /// upstream's `NoJailError`: the jail is not among the available ones.
    NoJail(String),
    Config(ConfigError),
}

impl std::fmt::Display for JailReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoJail(m) => f.write_str(m),
            Self::Config(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for JailReadError {}

impl From<ConfigError> for JailReadError {
    fn from(e: ConfigError) -> Self {
        Self::Config(e)
    }
}

#[derive(Debug)]
pub struct JailReader {
    base: ConfigReader,
    name: String,
    filter: Option<DefinitionReader>,
    force_enable: bool,
    actions: Vec<ActionEntry>,
    opts: Option<IndexMap<String, Val>>,
    fs: Rc<dyn Fs>,
    share: Share,
}

impl JailReader {
    /// `JailReader(name, force_enable, share_config=share, use_config=cfg)`.
    pub fn new(fs: Rc<dyn Fs>, share: Share, cfg: Cfg, name: &str, force_enable: bool) -> Self {
        Self {
            base: ConfigReader::with_cfg(fs.clone(), share.clone(), cfg),
            name: name.to_owned(),
            filter: None,
            force_enable,
            actions: Vec::new(),
            opts: None,
            fs,
            share,
        }
    }

    /// `JailReader(name, force_enable, share_config=share, basedir=basedir)`:
    /// a reader that loads `jail.conf` itself (see [`JailReader::read`]).
    pub fn standalone(
        fs: Rc<dyn Fs>,
        share: Share,
        basedir: &str,
        name: &str,
        force_enable: bool,
    ) -> Self {
        Self {
            base: ConfigReader::with_share(fs.clone(), share.clone(), Some(basedir.to_owned())),
            name: name.to_owned(),
            filter: None,
            force_enable,
            actions: Vec::new(),
            opts: None,
            fs,
            share,
        }
    }

    /// `JailReader.read()`: reads `jail.conf` (+ `.d`, `.local`) and verifies
    /// the jail exists. `Ok(false)`: the files could not be read.
    pub fn read(&mut self) -> std::result::Result<bool, JailReadError> {
        let out = self.base.read("jail")?;
        if !self.base.sections().contains(&self.name) {
            return Err(JailReadError::NoJail(format!(
                "Jail {} was not found among available",
                py_repr(&self.name)
            )));
        }
        Ok(out)
    }

    /// The filter reader of the jail (`JailReader.filter`).
    pub fn filter(&self) -> Option<&DefinitionReader> {
        self.filter.as_ref()
    }

    /// `JailReader.getCombined()`: jail options merged with the combined
    /// filter options.
    pub fn get_combined(&self) -> Result<IndexMap<String, Val>> {
        let mut out = self.opts.clone().unwrap_or_default();
        if let Some(f) = &self.filter {
            out.extend(f.get_combined(&HashSet::new())?);
        }
        Ok(out)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Jail options as read (`JailReader.options`).
    pub fn options(&self) -> Option<&IndexMap<String, Val>> {
        self.opts.as_ref()
    }

    fn opt_truthy(&self, key: &str) -> bool {
        self.opts
            .as_ref()
            .and_then(|o| o.get(key))
            .is_some_and(Val::truthy)
    }

    pub fn is_enabled(&self) -> bool {
        self.force_enable || self.opt_truthy("enabled")
    }

    fn opt_str(&self, key: &str) -> Option<&str> {
        self.opts.as_ref()?.get(key)?.as_str()
    }

    /// `JailReader.getOptions()`. `Ok(false)`: the jail definition is wrong
    /// (a `config-error` option was recorded); `Err`: configuration aborts.
    pub fn get_options(&mut self) -> Result<bool> {
        self.get_options_with(&IndexMap::new())
    }

    /// `JailReader.getOptions(addOpts)`: `add_opts` override the first-stage
    /// jail options and the options handed to the jail's filter.
    pub fn get_options_with(&mut self, add_opts: &IndexMap<String, String>) -> Result<bool> {
        let basedir = self.base.base_dir().unwrap_or_default();
        self.base.merge_defaults([
            ("fail2ban_version", UPSTREAM_COMPAT_VERSION),
            ("fail2ban_confpath", basedir.as_str()),
        ]);
        match self.read_options(&basedir, add_opts) {
            Ok(()) => Ok(true),
            Err(JailErr::Def(e)) => {
                let o = self.opts.get_or_insert_with(IndexMap::new);
                o.insert("config-error".to_owned(), Val::Str(e));
                Ok(false)
            }
            Err(JailErr::Other(e)) => Err(e),
        }
    }

    fn read_options(
        &mut self,
        basedir: &str,
        add_opts: &IndexMap<String, String>,
    ) -> std::result::Result<(), JailErr> {
        let empty = IndexMap::new();
        let mut first = self
            .base
            .get_options(&self.name, JAIL_OPTS_1ST, &empty, true, true)?;
        for (k, v) in add_opts {
            first.insert(k.clone(), Val::Str(v.clone()));
        }
        self.opts = Some(first);
        if !self.is_enabled() {
            return Ok(());
        }

        // Read filter
        let flt = self.opt_str("filter").unwrap_or_default().to_owned();
        if flt.is_empty() {
            self.filter = None;
        } else {
            let (filter_name, mut filter_opt) = extract_options(&flt).map_err(|e| {
                JailErr::Def(format!(
                    "Invalid filter definition {}: {}",
                    py_repr(&flt),
                    e
                ))
            })?;
            filter_opt.extend(add_opts.iter().map(|(k, v)| (k.clone(), v.clone())));
            let mut reader = DefinitionReader::filter(
                &filter_name,
                &self.name,
                filter_opt,
                ConfigReader::with_share(
                    self.fs.clone(),
                    self.share.clone(),
                    Some(basedir.to_owned()),
                ),
            );
            if !reader.read()? {
                return Err(JailErr::Def(format!(
                    "Unable to read the filter {}",
                    py_repr(&filter_name)
                )));
            }
            let backend = self.opt_str("backend").unwrap_or_default().to_owned();
            reader.apply_auto_options(&backend);
            let jail_opts = self.opts.clone().unwrap_or_default();
            reader.get_options(&jail_opts, true)?;
            // merge options from filter as 'known/...' (all options unfiltered)
            let combined = reader.get_combined(&HashSet::new())?;
            let pairs: Vec<(String, String)> = combined
                .iter()
                .filter(|(_, v)| !matches!(v, Val::None))
                .map(|(k, v)| (k.clone(), v.py_str()))
                .collect();
            self.base.merge_section(
                &self.name,
                pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())),
                "known/",
            )?;
            self.filter = Some(reader);
        }

        // Read second all options (so variables like %(known/param) can be interpolated)
        let all = self
            .base
            .get_options(&self.name, JAIL_OPTS, &empty, false, true)?;
        self.opts = Some(all);

        // cumulate filter options again (ignore given in jail)
        if let Some(f) = &mut self.filter {
            let jail_opts = self.opts.clone().unwrap_or_default();
            f.get_options(&jail_opts, false)?;
        }

        // Read actions
        let action_str = self.opt_str("action").unwrap_or_default().to_owned();
        for act in split_with_options(&action_str) {
            let act = py_strip(&act);
            if act.is_empty() {
                continue;
            }
            let (act_name, mut act_opt) = extract_options(act).map_err(|e| {
                JailErr::Def(format!("Invalid action definition {}: {}", py_repr(act), e))
            })?;
            if act_name.ends_with(".py") {
                let actname = act_opt
                    .shift_remove("actname")
                    .unwrap_or_else(|| splitext_root(&act_name).to_owned());
                let cmd: Command = vec![
                    Arg::from("set"),
                    Arg::from(self.name.as_str()),
                    Arg::from("addaction"),
                    Arg::from(actname),
                    Arg::from(join(&join(basedir, "action.d"), &act_name)),
                    Arg::from(dumps_str_map(&act_opt)),
                ];
                self.actions.push(ActionEntry::Py(cmd));
                continue;
            }
            let wrap = |e: ConfigError| {
                JailErr::Other(ConfigError::Value(format!(
                    "Error in action definition {}: {}",
                    py_repr(act),
                    e.py_repr()
                )))
            };
            let mut reader = DefinitionReader::action(
                &act_name,
                &self.name,
                act_opt,
                ConfigReader::with_share(
                    self.fs.clone(),
                    self.share.clone(),
                    Some(basedir.to_owned()),
                ),
            );
            if reader.read().map_err(wrap)? {
                let jail_opts = self.opts.clone().unwrap_or_default();
                reader.get_options(&jail_opts, false).map_err(wrap)?;
                self.actions.push(ActionEntry::Reader(Box::new(reader)));
            } else {
                return Err(JailErr::Def(format!(
                    "Unable to read action {}",
                    py_repr(&act_name)
                )));
            }
        }
        Ok(())
    }

    /// `JailReader.convert`: the jail's command stream.
    pub fn convert(
        &mut self,
        allow_no_files: bool,
        systemd_if_nologs: bool,
    ) -> Result<Vec<Command>> {
        let name = self.name.clone();
        if let Some(e) = self.opt_str("config-error") {
            return Ok(vec![vec![
                Arg::from("config-error"),
                Arg::from(format!(
                    "Jail '{name}' skipped, because of wrong configuration: {e}"
                )),
            ]]);
        }
        let mut stream: Vec<Command> = Vec::new();
        let mut stream2: Vec<Command> = Vec::new();
        // fill jail with filter options, using filter (only not overridden in jail)
        if let Some(f) = &self.filter {
            stream.extend(f.convert()?);
        }
        let opts = self.opts.clone().unwrap_or_default();
        // and using options from jail
        fill_stream(&mut stream, &opts, &name)?;
        let mut backend = self.opt_str("backend").unwrap_or("auto").to_owned();
        for (o, value) in &opts {
            match o.as_str() {
                "logpath" => {
                    if backend.starts_with("systemd") {
                        continue;
                    }
                    let mut found_files = 0;
                    for path in value.py_str().split('\n') {
                        let (path, tail) = path.rsplit_once(' ').unwrap_or((path, "head"));
                        for p in self.fs.glob(path) {
                            // dangling symlinks are not monitored
                            if !self.fs.exists(&p) {
                                continue;
                            }
                            found_files += 1;
                            stream2.push(vec![
                                Arg::from("set"),
                                Arg::from(name.as_str()),
                                Arg::from("addlogpath"),
                                Arg::from(p),
                                Arg::from(tail),
                            ]);
                        }
                    }
                    if found_files == 0 {
                        let mut msg = format!("Have not found any log file for '{name}' jail.");
                        let mut skip_if_nologs = self.opt_truthy("skip_if_nologs");
                        let jail_systemd_if_nologs = self
                            .opts
                            .as_ref()
                            .and_then(|o| o.get("systemd_if_nologs"))
                            .is_none_or(Val::truthy);
                        let has_journalmatch = self
                            .opts
                            .as_ref()
                            .and_then(|o| o.get("journalmatch"))
                            .is_some_and(|v| !matches!(v, Val::None));
                        if backend.starts_with("auto")
                            && systemd_if_nologs
                            && jail_systemd_if_nologs
                            && has_journalmatch
                        {
                            // switch backend to systemd (only possible if jail has journalmatch)
                            backend = "systemd".to_owned();
                            msg.push_str(" Jail will monitor systemd journal.");
                            skip_if_nologs = false;
                        } else if !allow_no_files && !skip_if_nologs {
                            return Err(ConfigError::Value(msg));
                        }
                        if skip_if_nologs {
                            if let Some(o) = self.opts.as_mut() {
                                o.insert("runtime-error".to_owned(), Val::Str(msg));
                            }
                            return Ok(vec![vec![
                                Arg::from("config-error"),
                                Arg::from(format!(
                                    "Jail '{name}' skipped, because of missing log files."
                                )),
                            ]]);
                        }
                    }
                }
                "ignoreip" => {
                    let mut c: Command = vec![
                        Arg::from("set"),
                        Arg::from(name.as_str()),
                        Arg::from("addignoreip"),
                    ];
                    c.extend(
                        splitwords(&value.py_str(), false)
                            .into_iter()
                            .map(Arg::from),
                    );
                    stream.push(c);
                }
                other if !is_ignored_opt(other) => {
                    stream.push(vec![
                        Arg::from("set"),
                        Arg::from(name.as_str()),
                        Arg::from(other),
                        value.clone().into_arg(),
                    ]);
                }
                _ => {}
            }
        }
        // consider options order (after other options)
        stream.extend(stream2);
        for action in &self.actions {
            match action {
                ActionEntry::Reader(r) => stream.extend(r.convert()?),
                ActionEntry::Py(c) => stream.push(c.clone()),
            }
        }
        stream.insert(
            0,
            vec![
                Arg::from("add"),
                Arg::from(name.as_str()),
                Arg::from(backend),
            ],
        );
        Ok(stream)
    }
}
