//! Ports of upstream's `ConfigReaderUnshared` and `ConfigReader`
//! (`fail2ban/client/configreader.py`): base-dir handling, the
//! `<name>.conf` / `<name>.d/*.conf` / `<name>.local` / `<name>.d/*.local`
//! file selection, shared (cached) readers and typed option extraction.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use f2b_helpers::as_bool;

use crate::arg::Val;
use crate::error::{ConfigError, Result};
use crate::fs::Fs;
use crate::ini::{Ini, Section};
use crate::pyutil::{join, py_int};

pub const DEFAULT_BASEDIR: &str = "/etc/fail2ban";

/// Option type of a template entry (`CONVERTER` keys).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ty {
    Str,
    Bool,
    Int,
}

/// Default of an option template entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Def {
    None,
    Str(&'static str),
    Bool(bool),
}

impl Def {
    pub fn to_val(self) -> Val {
        match self {
            Self::None => Val::None,
            Self::Str(s) => Val::Str(s.to_owned()),
            Self::Bool(b) => Val::Bool(b),
        }
    }
}

/// One entry of an options template (`[type, name, default]`).
#[derive(Debug, Clone, Copy)]
pub struct OptDef {
    pub ty: Ty,
    pub name: &'static str,
    pub default: Def,
}

pub const fn opt(ty: Ty, name: &'static str, default: Def) -> OptDef {
    OptDef { ty, name, default }
}

/// Convert an interpolated string value to its declared type (`CONVERTER`).
/// `None` on a failed conversion (Python `ValueError`).
pub fn convert_value(ty: Ty, v: &str) -> Option<Val> {
    match ty {
        Ty::Str => Some(Val::Str(v.to_owned())),
        Ty::Bool => Some(Val::Bool(as_bool(v))),
        Ty::Int => py_int(v).map(Val::Int),
    }
}

/// `str(value)` of every entry, as used for interpolation `vars`.
pub fn vals_to_vars(v: &indexmap::IndexMap<String, Val>) -> Section {
    v.iter().map(|(k, v)| (k.clone(), v.py_str())).collect()
}

/// Upstream `ConfigReaderUnshared`: one parsed configuration plus its base dir.
#[derive(Debug)]
pub struct ConfigReaderUnshared {
    pub(crate) ini: Ini,
    basedir: String,
    read_cfg_files: Option<bool>,
    fs: Rc<dyn Fs>,
}

impl ConfigReaderUnshared {
    pub fn new(fs: Rc<dyn Fs>, basedir: Option<&str>) -> Self {
        let mut r = Self {
            ini: Ini::new(),
            basedir: String::new(),
            read_cfg_files: None,
            fs,
        };
        r.set_base_dir(basedir);
        r
    }

    pub fn set_base_dir(&mut self, basedir: Option<&str>) {
        self.basedir = basedir
            .unwrap_or(DEFAULT_BASEDIR)
            .trim_end_matches('/')
            .to_owned();
    }

    pub fn base_dir(&self) -> &str {
        &self.basedir
    }

    pub fn ini(&self) -> &Ini {
        &self.ini
    }

    pub fn ini_mut(&mut self) -> &mut Ini {
        &mut self.ini
    }

    pub fn fs(&self) -> &Rc<dyn Fs> {
        &self.fs
    }

    /// `ConfigReaderUnshared.read(filename)`.
    pub fn read(&mut self, filename: &str) -> Result<bool> {
        if !self.fs.exists(&self.basedir) {
            return Err(ConfigError::Value(format!(
                "Base configuration directory {} does not exist ",
                self.basedir
            )));
        }
        let basename = join(&self.basedir, filename);
        let config_dir = format!("{basename}.d");
        let mut files = vec![format!("{basename}.conf")];
        files.extend(self.fs.glob(&format!("{config_dir}/*.conf")));
        files.push(format!("{basename}.local"));
        files.extend(self.fs.glob(&format!("{config_dir}/*.local")));
        files.retain(|f| self.fs.exists(f));
        if files.is_empty() {
            return Ok(false);
        }
        let read = self.ini.read(self.fs.as_ref(), &files)?;
        if files.iter().any(|f| !read.contains(f)) {
            return Ok(false);
        }
        Ok(!read.is_empty())
    }

    /// `ConfigReaderUnshared.getOptions`: read `options` of `sec`, applying
    /// defaults and (if `convert`) type conversion. `p_options` entries are
    /// skipped and act as interpolation variables.
    pub fn get_options(
        &self,
        sec: &str,
        options: &[OptDef],
        p_options: &indexmap::IndexMap<String, Val>,
        should_exist: bool,
        convert: bool,
    ) -> Result<indexmap::IndexMap<String, Val>> {
        let vars = vals_to_vars(p_options);
        let mut values = indexmap::IndexMap::new();
        for o in options {
            if p_options.contains_key(o.name) {
                continue;
            }
            match self.ini.get(sec, o.name, false, &vars) {
                Ok(v) => {
                    if convert {
                        match convert_value(o.ty, &v) {
                            Some(c) => {
                                values.insert(o.name.to_owned(), c);
                            }
                            // ValueError: "Wrong value ... Using default one"
                            None => {
                                values.insert(o.name.to_owned(), o.default.to_val());
                            }
                        }
                    } else {
                        values.insert(o.name.to_owned(), Val::Str(v));
                    }
                }
                Err(ConfigError::NoSection(s)) => {
                    if should_exist {
                        return Err(ConfigError::NoSection(s));
                    }
                    // upstream logs the error and falls back to the default (even None)
                    values.insert(o.name.to_owned(), o.default.to_val());
                }
                Err(ConfigError::NoOption { .. }) => {
                    if o.default != Def::None {
                        values.insert(o.name.to_owned(), o.default.to_val());
                    }
                }
                Err(ConfigError::Value(_)) => {
                    values.insert(o.name.to_owned(), o.default.to_val());
                }
                Err(e) => return Err(e),
            }
        }
        Ok(values)
    }
}

/// A reader configuration shared (by name) between readers.
pub type Cfg = Rc<RefCell<ConfigReaderUnshared>>;
/// Upstream `share_config` dict.
pub type Share = Rc<RefCell<HashMap<String, Cfg>>>;

/// Upstream `ConfigReader`: a (possibly shared) lazily created reader.
#[derive(Debug)]
pub struct ConfigReader {
    cfg: Option<Cfg>,
    share: Option<Share>,
    share_basedir: Option<String>,
    kw_basedir: Option<String>,
    fs: Rc<dyn Fs>,
}

impl ConfigReader {
    /// `ConfigReader(share_config=share, basedir=basedir)`.
    pub fn with_share(fs: Rc<dyn Fs>, share: Share, basedir: Option<String>) -> Self {
        Self {
            cfg: None,
            share: Some(share),
            share_basedir: None,
            kw_basedir: basedir,
            fs,
        }
    }

    /// `ConfigReader(use_config=cfg, share_config=share)`.
    pub fn with_cfg(fs: Rc<dyn Fs>, share: Share, cfg: Cfg) -> Self {
        Self {
            cfg: Some(cfg),
            share: Some(share),
            share_basedir: None,
            kw_basedir: None,
            fs,
        }
    }

    pub fn cfg(&self) -> Option<&Cfg> {
        self.cfg.as_ref()
    }

    pub fn fs(&self) -> &Rc<dyn Fs> {
        &self.fs
    }

    pub fn set_base_dir(&mut self, basedir: &str) {
        match &self.cfg {
            Some(c) => c.borrow_mut().set_base_dir(Some(basedir)),
            None => self.share_basedir = Some(basedir.to_owned()),
        }
    }

    pub fn base_dir(&self) -> Option<String> {
        match &self.cfg {
            Some(c) => Some(c.borrow().base_dir().to_owned()),
            None => self.share_basedir.clone(),
        }
    }

    fn create_unshared(&mut self, name: &str) {
        if let Some(share) = &self.share {
            let existing = share.borrow().get(name).cloned();
            let cfg = existing.unwrap_or_else(|| {
                let mut c = ConfigReaderUnshared::new(self.fs.clone(), self.kw_basedir.as_deref());
                if let Some(b) = &self.share_basedir {
                    c.set_base_dir(Some(b));
                }
                let c = Rc::new(RefCell::new(c));
                share.borrow_mut().insert(name.to_owned(), c.clone());
                c
            });
            self.cfg = Some(cfg);
        } else {
            self.cfg = Some(Rc::new(RefCell::new(ConfigReaderUnshared::new(
                self.fs.clone(),
                self.kw_basedir.as_deref(),
            ))));
        }
    }

    /// `ConfigReader.read(name, once=True)`.
    pub fn read(&mut self, name: &str) -> Result<bool> {
        if self.cfg.is_none() {
            self.create_unshared(name);
        }
        let Some(cfg) = &self.cfg else {
            return Ok(false);
        };
        if let Some(done) = cfg.borrow().read_cfg_files {
            return Ok(done);
        }
        let ret = cfg.borrow_mut().read(name)?;
        cfg.borrow_mut().read_cfg_files = Some(ret);
        Ok(ret)
    }

    /// `sections()` without internal `KNOWN/...` sections.
    pub fn sections(&self) -> Vec<String> {
        self.cfg.as_ref().map_or_else(Vec::new, |c| {
            c.borrow()
                .ini
                .sections()
                .filter(|n| !n.starts_with("KNOWN/"))
                .map(str::to_owned)
                .collect()
        })
    }

    pub fn has_section(&self, sec: &str) -> bool {
        self.cfg
            .as_ref()
            .is_some_and(|c| c.borrow().ini.has_section(sec))
    }

    /// `has_option(sec, opt, withDefault)`; without defaults the exact
    /// (non-lowercased) name is looked up in the section only.
    pub fn has_option(&self, sec: &str, opt: &str, with_default: bool) -> bool {
        let Some(c) = &self.cfg else {
            return false;
        };
        let c = c.borrow();
        if with_default {
            c.ini.has_option(sec, opt)
        } else {
            c.ini.section(sec).is_some_and(|s| s.contains_key(opt))
        }
    }

    pub fn merge_defaults<'a>(&self, d: impl IntoIterator<Item = (&'a str, &'a str)>) {
        if let Some(c) = &self.cfg {
            let mut c = c.borrow_mut();
            for (k, v) in d {
                c.ini.defaults_mut().insert(k.to_lowercase(), v.to_owned());
            }
        }
    }

    pub fn merge_section<'a>(
        &self,
        section: &str,
        options: impl IntoIterator<Item = (&'a str, &'a str)>,
        pref: &str,
    ) -> Result<()> {
        let Some(c) = &self.cfg else {
            return Err(ConfigError::NoSection(section.to_owned()));
        };
        c.borrow_mut().ini.merge_section(section, options, pref);
        Ok(())
    }

    /// Own option names (`options(section)` with `withDefault=False`).
    pub fn options_own(&self, section: &str) -> Result<Vec<String>> {
        match &self.cfg {
            Some(c) => c.borrow().ini.options_own(section),
            None => Err(ConfigError::NoSection(section.to_owned())),
        }
    }

    pub fn get(&self, sec: &str, opt: &str, raw: bool, vars: &Section) -> Result<String> {
        match &self.cfg {
            Some(c) => c.borrow().ini.get(sec, opt, raw, vars),
            None => Err(ConfigError::NoSection(sec.to_owned())),
        }
    }

    pub fn get_ex(&self, sec: &str, opt: &str, raw: bool, vars: &Section) -> Result<String> {
        match &self.cfg {
            Some(c) => c.borrow().ini.get_ex(sec, opt, raw, vars),
            None => Err(ConfigError::NoSection(sec.to_owned())),
        }
    }

    pub fn get_options(
        &self,
        sec: &str,
        options: &[OptDef],
        p_options: &indexmap::IndexMap<String, Val>,
        should_exist: bool,
        convert: bool,
    ) -> Result<indexmap::IndexMap<String, Val>> {
        match &self.cfg {
            Some(c) => c
                .borrow()
                .get_options(sec, options, p_options, should_exist, convert),
            None => Err(ConfigError::NoSection(sec.to_owned())),
        }
    }
}
