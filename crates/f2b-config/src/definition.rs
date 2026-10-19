//! Ports of `DefinitionInitConfigReader`, `FilterReader` and `ActionReader`
//! (`fail2ban/client/{configreader,filterreader,actionreader}.py`).
//!
//! Filters and actions read their `[Definition]` options, collect `[Init]`
//! options (overridable from the jail via `name[opt=value]`), resolve nested
//! `<tag>` references and finally convert to client commands.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

use f2b_helpers::{shlex_split, substitute_recursive_tags};
use indexmap::IndexMap;

use crate::arg::{Arg, Command, Val};
use crate::error::{ConfigError, Result};
use crate::ini::{Section, split_conditional};
use crate::reader::{ConfigReader, Def, OptDef, Ty, convert_value, opt, vals_to_vars};

/// `FilterReader._configOpts`
pub const FILTER_OPTS: &[OptDef] = &[
    opt(Ty::Str, "usedns", Def::None),
    opt(Ty::Str, "prefregex", Def::None),
    opt(Ty::Str, "ignoreregex", Def::None),
    opt(Ty::Str, "failregex", Def::None),
    opt(Ty::Int, "maxlines", Def::None),
    opt(Ty::Str, "datepattern", Def::None),
    opt(Ty::Str, "journalmatch", Def::None),
];

/// `ActionReader._configOpts`
pub const ACTION_OPTS: &[OptDef] = &[
    opt(Ty::Str, "actionstart", Def::None),
    opt(Ty::Bool, "actionstart_on_demand", Def::None),
    opt(Ty::Str, "actionstop", Def::None),
    opt(Ty::Str, "actionflush", Def::None),
    opt(Ty::Str, "actionreload", Def::None),
    opt(Ty::Str, "actioncheck", Def::None),
    opt(Ty::Str, "actionrepair", Def::None),
    opt(Ty::Bool, "actionrepair_on_unban", Def::None),
    opt(Ty::Str, "actionban", Def::None),
    opt(Ty::Str, "actionprolong", Def::None),
    opt(Ty::Str, "actionreban", Def::None),
    opt(Ty::Str, "actionunban", Def::None),
    opt(Ty::Bool, "norestored", Def::None),
];

/// `CommandAction._escapedTags`: tags whose content is out of our control.
pub const ESCAPED_TAGS: &[&str] = &["matches", "ipmatches", "ipjailmatches"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    Filter,
    /// Action with its (jail-unique) action name.
    Action {
        name: String,
    },
}

/// A filter or action definition reader.
#[derive(Debug)]
pub struct DefinitionReader {
    base: ConfigReader,
    kind: Kind,
    /// User-facing file name (`getFile`), e.g. `sshd`.
    file: String,
    /// Path below the base dir, e.g. `filter.d/sshd`.
    full_file: String,
    jail_name: String,
    init_opts: IndexMap<String, String>,
    p_opts: IndexMap<String, Val>,
    /// `_opts`: `[Definition]` options (strings; `None` only if the section is missing).
    opts: IndexMap<String, Val>,
    def_cache: RefCell<HashMap<String, Option<String>>>,
}

impl DefinitionReader {
    /// `FilterReader(file, jailName, initOpts, ...)`.
    pub fn filter(
        file: &str,
        jail_name: &str,
        init_opts: IndexMap<String, String>,
        base: ConfigReader,
    ) -> Self {
        Self::new(Kind::Filter, "filter.d", file, jail_name, init_opts, base)
    }

    /// `ActionReader(file, jailName, initOpts, ...)`: supplies the `name` and
    /// `actname` init options exactly like upstream.
    pub fn action(
        file: &str,
        jail_name: &str,
        mut init_opts: IndexMap<String, String>,
        base: ConfigReader,
    ) -> Self {
        let n = match init_opts.get("name") {
            Some(n) => n.clone(),
            None => {
                init_opts.insert("name".to_owned(), jail_name.to_owned());
                jail_name.to_owned()
            }
        };
        let actname = match init_opts.get("actname") {
            Some(a) => a.clone(),
            None => {
                let mut a = file.to_owned();
                if n != jail_name {
                    match n.strip_prefix(jail_name) {
                        Some(rest) => a.push_str(rest),
                        None => {
                            a.push('-');
                            a.push_str(&n);
                        }
                    }
                }
                init_opts.insert("actname".to_owned(), a.clone());
                a
            }
        };
        Self::new(
            Kind::Action { name: actname },
            "action.d",
            file,
            jail_name,
            init_opts,
            base,
        )
    }

    fn new(
        kind: Kind,
        dir: &str,
        file: &str,
        jail_name: &str,
        init_opts: IndexMap<String, String>,
        base: ConfigReader,
    ) -> Self {
        Self {
            base,
            kind,
            file: file.to_owned(),
            full_file: crate::pyutil::join(dir, file),
            jail_name: jail_name.to_owned(),
            init_opts,
            p_opts: IndexMap::new(),
            opts: IndexMap::new(),
            def_cache: RefCell::new(HashMap::new()),
        }
    }

    pub fn file(&self) -> &str {
        &self.file
    }

    /// Action name (`ActionReader.getName`); `None` for filters.
    pub fn name(&self) -> Option<&str> {
        match &self.kind {
            Kind::Action { name } => Some(name),
            Kind::Filter => None,
        }
    }

    pub fn init_opts(&self) -> &IndexMap<String, String> {
        &self.init_opts
    }

    pub fn init_opts_mut(&mut self) -> &mut IndexMap<String, String> {
        &mut self.init_opts
    }

    fn config_opts(&self) -> &'static [OptDef] {
        match self.kind {
            Kind::Filter => FILTER_OPTS,
            Kind::Action { .. } => ACTION_OPTS,
        }
    }

    pub fn read(&mut self) -> Result<bool> {
        self.base.read(&self.full_file)
    }

    /// `readexplicit`: read the file itself (with its includes), independent
    /// of the base dir. `Ok(false)`: nothing was read.
    pub fn read_explicit(&mut self) -> Result<bool> {
        Ok(!self.base.read_explicit(&self.full_file)?.is_empty())
    }

    /// `get(section, option)` of the underlying reader (interpolated, no extra vars).
    pub fn get(&self, section: &str, option: &str) -> Result<String> {
        self.base.get(section, option, false, &Section::new())
    }

    /// `FilterReader.applyAutoOptions`: logtype from the backend.
    pub fn apply_auto_options(&mut self, backend: &str) {
        let has_logtype = self.init_opts.get("logtype").is_some_and(|v| !v.is_empty());
        if !has_logtype && !self.base.has_option("Definition", "logtype", false) {
            let lt = if backend.starts_with("systemd") {
                "journal"
            } else {
                "file"
            };
            self.init_opts.insert("logtype".to_owned(), lt.to_owned());
        }
    }

    /// `DefinitionInitConfigReader.getOptions(pOpts, all)`.
    pub fn get_options(&mut self, p_opts: &IndexMap<String, Val>, all: bool) -> Result<()> {
        let mut p_opts = p_opts.clone();
        if !self.init_opts.is_empty() {
            for (k, v) in &self.init_opts {
                p_opts.insert(k.clone(), Val::Str(v.clone()));
            }
        }
        // type conversion happens only on the combined options
        self.opts =
            self.base
                .get_options("Definition", self.config_opts(), &p_opts, false, false)?;
        self.p_opts = p_opts.clone();
        let no_vars = Section::new();
        if self.base.has_section("Init") {
            for o in self.base.options_own("Init")? {
                if o == "__name__" {
                    continue;
                }
                let mut v: Option<String> = None;
                if !o.starts_with("known/") {
                    let g = self.base.get("Init", &o, false, &no_vars)?;
                    self.init_opts.insert(format!("known/{o}"), g.clone());
                    v = Some(g);
                }
                if !self.init_opts.contains_key(&o) {
                    // overwrite also conditional init options (from `Init?...`)
                    if let Some((optc, _)) = split_conditional(&o) {
                        if let Some(pv) = p_opts.get(optc) {
                            v = Some(pv.py_str());
                        }
                    }
                    let v = match v {
                        Some(v) => v,
                        None => self.base.get("Init", &o, false, &no_vars)?,
                    };
                    self.init_opts.insert(o, v);
                }
            }
        }
        if all && self.base.has_section("Definition") {
            for o in self.base.options_own("Definition")? {
                if o == "__name__" || self.opts.contains_key(&o) {
                    continue;
                }
                let v = self.base.get("Definition", &o, false, &no_vars)?;
                self.opts.insert(o, Val::Str(v));
            }
        }
        Ok(())
    }

    /// `getCombOption`: combined definition option, cached for the reader's lifetime.
    fn comb_option(&self, name: &str, failure: &RefCell<Option<ConfigError>>) -> Option<String> {
        if let Some(c) = self.def_cache.borrow().get(name) {
            return c.clone();
        }
        let vars = vals_to_vars(&self.p_opts);
        let v = match self.base.get_ex("Definition", name, false, &vars) {
            Ok(v) => Some(v),
            Err(
                ConfigError::NoSection(_) | ConfigError::NoOption { .. } | ConfigError::Value(_),
            ) => None,
            Err(e) => {
                failure.borrow_mut().get_or_insert(e);
                return None;
            }
        };
        self.def_cache
            .borrow_mut()
            .insert(name.to_owned(), v.clone());
        v
    }

    /// `getCombined(ignore)`: definition + init options with all `<tag>`
    /// references resolved and typed options converted.
    pub fn get_combined(&self, ignore: &HashSet<String>) -> Result<IndexMap<String, Val>> {
        let mut combined = self.opts.clone();
        for (k, v) in &self.init_opts {
            combined.insert(k.clone(), Val::Str(v.clone()));
        }
        if combined.is_empty() {
            return Ok(IndexMap::new());
        }
        let mut ignore = ignore.clone();
        for n in combined.keys() {
            if let Some((base, _)) = split_conditional(n) {
                ignore.insert(base.to_owned());
            }
        }
        // `None` values never contain tags and are never substitution targets
        let strs: IndexMap<String, String> = combined
            .iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
            .collect();
        let failure = RefCell::new(None);
        let resolved =
            substitute_recursive_tags(&strs, "", &ignore, Some(&|t| self.comb_option(t, &failure)));
        if let Some(e) = failure.into_inner() {
            return Err(e);
        }
        let resolved = resolved.map_err(|e| ConfigError::Value(e.to_string()))?;
        let mut opts: IndexMap<String, Val> = combined
            .keys()
            .map(|k| {
                let v = resolved.get(k).map_or(Val::None, |s| Val::Str(s.clone()));
                (k.clone(), v)
            })
            .collect();
        self.convert_options(&mut opts);
        Ok(opts)
    }

    /// `convertOptions`: convert interpolated options to their declared type.
    fn convert_options(&self, opts: &mut IndexMap<String, Val>) {
        for o in self.config_opts() {
            if o.ty == Ty::Str {
                continue;
            }
            let Some(Val::Str(s)) = opts.get(o.name) else {
                continue;
            };
            let conv = convert_value(o.ty, s).unwrap_or_else(|| o.default.to_val());
            opts.insert(o.name.to_owned(), conv);
        }
    }

    /// `FilterReader.convert` / `ActionReader.convert`.
    pub fn convert(&self) -> Result<Vec<Command>> {
        match &self.kind {
            Kind::Filter => {
                let opts = self.get_combined(&HashSet::new())?;
                let mut stream = Vec::new();
                if !opts.is_empty() {
                    fill_stream(&mut stream, &opts, &self.jail_name)?;
                }
                Ok(stream)
            }
            Kind::Action { name } => {
                let ignore: HashSet<String> = ESCAPED_TAGS
                    .iter()
                    .chain(&["timeout", "bantime"])
                    .map(|s| (*s).to_owned())
                    .collect();
                let opts = self.get_combined(&ignore)?;
                let mut stream: Vec<Command> = vec![vec![
                    Arg::from("set"),
                    Arg::from(self.jail_name.as_str()),
                    Arg::from("addaction"),
                    Arg::from(name.as_str()),
                ]];
                let mut multi: Vec<Arg> = Vec::new();
                for (o, v) in &opts {
                    if ACTION_OPTS.iter().any(|d| d.name == o) && !o.starts_with("known/") {
                        multi.push(Arg::List(vec![Arg::from(o.as_str()), v.clone().into_arg()]));
                    }
                }
                for (o, v) in &self.init_opts {
                    if !ACTION_OPTS.iter().any(|d| d.name == o) && !o.starts_with("known/") {
                        multi.push(Arg::List(vec![
                            Arg::from(o.as_str()),
                            Arg::from(v.as_str()),
                        ]));
                    }
                }
                match multi.len() {
                    0 => {}
                    1 => {
                        let mut c: Command = vec![
                            Arg::from("set"),
                            Arg::from(self.jail_name.as_str()),
                            Arg::from("action"),
                            Arg::from(name.as_str()),
                        ];
                        if let Some(Arg::List(pair)) = multi.pop() {
                            c.extend(pair);
                        }
                        stream.push(c);
                    }
                    _ => stream.push(vec![
                        Arg::from("multi-set"),
                        Arg::from(self.jail_name.as_str()),
                        Arg::from("action"),
                        Arg::from(name.as_str()),
                        Arg::List(multi),
                    ]),
                }
                Ok(stream)
            }
        }
    }
}

/// `FilterReader._fillStream`: filter-related options to commands.
pub fn fill_stream(
    stream: &mut Vec<Command>,
    opts: &IndexMap<String, Val>,
    jail_name: &str,
) -> Result<()> {
    let mut prio0idx = 0usize;
    let set = |opt: &str, v: Val| -> Command {
        vec![
            Arg::from("set"),
            Arg::from(jail_name),
            Arg::from(opt),
            v.into_arg(),
        ]
    };
    for (opt, value) in opts {
        if matches!(value, Val::None) {
            continue;
        }
        match opt.as_str() {
            "failregex" | "ignoreregex" => {
                let text = value.py_str();
                let multi: Vec<&str> = text.split('\n').filter(|r| !r.is_empty()).collect();
                let cmd = format!("add{opt}");
                match multi.len() {
                    0 => {}
                    1 => stream.push(vec![
                        Arg::from("set"),
                        Arg::from(jail_name),
                        Arg::from(cmd.as_str()),
                        Arg::from(multi[0]),
                    ]),
                    _ => stream.push(vec![
                        Arg::from("multi-set"),
                        Arg::from(jail_name),
                        Arg::from(cmd.as_str()),
                        Arg::List(multi.into_iter().map(Arg::from).collect()),
                    ]),
                }
            }
            "usedns" | "maxlines" | "prefregex" => {
                // set these first, and usedns before all regexes
                let at = if opt == "usedns" { 0 } else { prio0idx };
                stream.insert(at, set(opt, value.clone()));
                prio0idx += 1;
            }
            "datepattern" => stream.push(set(opt, value.clone())),
            "journalmatch" => {
                for m in value.py_str().split('\n') {
                    if m.is_empty() {
                        continue;
                    }
                    let words = shlex_split(m).map_err(|e| ConfigError::Value(e.to_string()))?;
                    let mut c: Command = vec![
                        Arg::from("set"),
                        Arg::from(jail_name),
                        Arg::from("addjournalmatch"),
                    ];
                    c.extend(words.into_iter().map(Arg::from));
                    stream.push(c);
                }
            }
            _ => {}
        }
    }
    Ok(())
}
