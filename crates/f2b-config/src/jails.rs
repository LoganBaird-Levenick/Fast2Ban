//! Port of `JailsReader` (`fail2ban/client/jailsreader.py`).

use std::rc::Rc;

use crate::arg::{Arg, Command, Val};
use crate::error::{ConfigError, Result};
use crate::fs::Fs;
use crate::jail::JailReader;
use crate::reader::{ConfigReader, Share};

#[derive(Debug)]
pub struct JailsReader {
    base: ConfigReader,
    jails: Vec<JailReader>,
    force_enable: bool,
    fs: Rc<dyn Fs>,
    share: Share,
}

impl JailsReader {
    pub fn new(fs: Rc<dyn Fs>, share: Share, force_enable: bool) -> Self {
        Self {
            base: ConfigReader::with_share(fs.clone(), share.clone(), None),
            jails: Vec::new(),
            force_enable,
            fs,
            share,
        }
    }

    pub fn set_base_dir(&mut self, dir: &str) {
        self.base.set_base_dir(dir);
    }

    pub fn base_dir(&self) -> Option<String> {
        self.base.base_dir()
    }

    pub fn jails(&self) -> &[JailReader] {
        &self.jails
    }

    /// `JailsReader.read`: reads `jail.conf` (+ `.d`, `.local`).
    pub fn read(&mut self) -> Result<bool> {
        self.jails.clear();
        self.base.read("jail")
    }

    /// `JailsReader.getOptions(section, ignoreWrong)`.
    pub fn get_options(&mut self, section: Option<&str>, ignore_wrong: bool) -> Result<bool> {
        let sections = match section {
            Some(s) => vec![s.to_owned()],
            None => self.base.sections(),
        };
        let Some(cfg) = self.base.cfg().cloned() else {
            return Err(ConfigError::NoSection("jail".to_owned()));
        };
        let mut parse_status = 0u8;
        for sec in sections {
            if sec == "INCLUDES" {
                continue;
            }
            let mut jail = JailReader::new(
                self.fs.clone(),
                self.share.clone(),
                cfg.clone(),
                &sec,
                self.force_enable,
            );
            if jail.get_options()? {
                if jail.is_enabled() {
                    // at least one jail was successful; only enabled jails are added
                    parse_status |= 1;
                    self.jails.push(jail);
                }
            } else {
                // at least one jail was invalid
                parse_status |= 2;
                self.jails.push(jail);
            }
        }
        Ok((ignore_wrong && parse_status & 1 != 0) || parse_status & 2 == 0)
    }

    /// `JailsReader.convert`: convert jails, then start them.
    pub fn convert(
        &mut self,
        allow_no_files: bool,
        systemd_if_nologs: bool,
    ) -> Result<Vec<Command>> {
        let mut stream: Vec<Command> = Vec::new();
        for jail in &mut self.jails {
            stream.extend(jail.convert(allow_no_files, systemd_if_nologs)?);
        }
        for jail in &mut self.jails {
            let has = |k: &str| {
                jail.options()
                    .and_then(|o| o.get(k))
                    .is_some_and(Val::truthy)
            };
            if !has("config-error") && !has("runtime-error") {
                stream.push(vec![Arg::from("start"), Arg::from(jail.name())]);
            }
        }
        Ok(stream)
    }
}
