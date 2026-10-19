//! Port of `Configurator` (`fail2ban/client/configurator.py`) and
//! `Fail2banCmdLine.readConfig`.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use indexmap::IndexMap;

use crate::arg::{Command, Val};
use crate::error::{ConfigError, Result};
use crate::fail2ban::{Fail2banReader, check_log_level};
use crate::fs::Fs;
use crate::jails::JailsReader;

#[derive(Debug)]
pub struct Configurator {
    fail2ban: Fail2banReader,
    jails: JailsReader,
    general: Vec<Command>,
    jail_streams: Vec<Command>,
}

impl Configurator {
    pub fn new(fs: Rc<dyn Fs>, force_enable: bool) -> Self {
        // always share all config readers
        let share = Rc::new(RefCell::new(HashMap::new()));
        Self {
            fail2ban: Fail2banReader::new(fs.clone(), share.clone()),
            jails: JailsReader::new(fs, share, force_enable),
            general: Vec::new(),
            jail_streams: Vec::new(),
        }
    }

    pub fn set_base_dir(&mut self, dir: &str) {
        self.fail2ban.set_base_dir(dir);
        self.jails.set_base_dir(dir);
    }

    pub fn base_dir(&self) -> Option<String> {
        self.fail2ban.base_dir()
    }

    pub fn read_all(&mut self) -> Result<()> {
        if !self.fail2ban.read()? {
            return Err(ConfigError::Value(
                "Read fail2ban configuration failed.".to_owned(),
            ));
        }
        if !self.jails.read()? {
            return Err(ConfigError::Value(
                "Read jails configuration failed.".to_owned(),
            ));
        }
        Ok(())
    }

    /// `Configurator.readEarly` + `getEarlyOptions`.
    pub fn read_early_options(&mut self) -> Result<IndexMap<String, Val>> {
        if !self.fail2ban.read()? {
            return Err(ConfigError::Value(
                "Read fail2ban configuration failed.".to_owned(),
            ));
        }
        self.fail2ban.get_early_options()
    }

    pub fn get_options(
        &mut self,
        jail: Option<&str>,
        update_main_opt: &IndexMap<String, Val>,
        ignore_wrong: bool,
    ) -> Result<bool> {
        self.fail2ban.get_options(update_main_opt)?;
        self.jails.get_options(jail, ignore_wrong)
    }

    pub fn convert_to_protocol(&mut self, allow_no_files: bool) -> Result<()> {
        self.general = self.fail2ban.convert();
        self.jail_streams = self.jails.convert(allow_no_files, true)?;
        Ok(())
    }

    pub fn config_stream(&self) -> Vec<Command> {
        self.general
            .iter()
            .chain(&self.jail_streams)
            .cloned()
            .collect()
    }
}

/// `CONFIG_PARAMS`: options taken from `fail2ban.conf` unless given explicitly.
pub const CONFIG_PARAMS: [&str; 5] = ["socket", "pidfile", "logtarget", "loglevel", "syslogsocket"];

/// Outcome of [`read_config`], mirroring `(ret, stream)` of upstream's `readConfig`.
#[derive(Debug)]
pub struct ConfigResult {
    /// Upstream `ret`: process exit status is 0 when true, 255 otherwise.
    pub ret: bool,
    /// `None` when configuration failed with an exception.
    pub stream: Option<Vec<Command>>,
    /// The exception behind a `None` stream.
    pub error: Option<ConfigError>,
    /// The failure happened while completing command-line options from the
    /// early configuration (upstream prints `ERROR: <message>`), not while
    /// reading the full configuration (`Failed during configuration: ...`).
    pub init_failed: bool,
}

/// `Fail2banCmdLine.initCmdLine` option completion plus `readConfig`: read
/// everything below `basedir` and produce the client command stream.
///
/// `cli_conf` holds explicitly given command-line values (`-s`, `-p`,
/// `--logtarget`, ...); [`CONFIG_PARAMS`] missing from it are taken from
/// `fail2ban.conf` (with upstream's built-in defaults) and override the main
/// options, as upstream does. `allow_no_files` mirrors `dump` mode (missing
/// log files are tolerated).
pub fn read_config(
    fs: Rc<dyn Fs>,
    basedir: &str,
    jail: Option<&str>,
    cli_conf: &IndexMap<String, Val>,
    ignore_wrong: bool,
    allow_no_files: bool,
) -> ConfigResult {
    let mut c = Configurator::new(fs, false);
    c.set_base_dir(basedir);
    let mut init_failed = false;
    let mut run = || -> Result<(bool, Vec<Command>)> {
        init_failed = true;
        let mut conf = cli_conf.clone();
        let mut early: Option<IndexMap<String, Val>> = None;
        for o in CONFIG_PARAMS {
            if matches!(conf.get(o), None | Some(Val::None)) {
                if early.is_none() {
                    early = Some(c.read_early_options()?);
                }
                if let Some(v) = early.as_ref().and_then(|e| e.get(o)) {
                    conf.insert(o.to_owned(), v.clone());
                }
            }
        }
        if let Some(level) = conf.get("loglevel") {
            check_log_level(&level.py_str())?;
        }
        init_failed = false;
        c.read_all()?;
        let ret = c.get_options(jail, &conf, ignore_wrong)?;
        c.convert_to_protocol(allow_no_files)?;
        Ok((ret, c.config_stream()))
    };
    match run() {
        Ok((ret, stream)) => ConfigResult {
            ret,
            stream: Some(stream),
            error: None,
            init_failed: false,
        },
        Err(e) => ConfigResult {
            ret: false,
            stream: None,
            error: Some(e),
            init_failed,
        },
    }
}
