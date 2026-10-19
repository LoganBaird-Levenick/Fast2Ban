//! Implementation of `CommandAction` (`fail2ban/server/action.py`).

use indexmap::IndexMap;
use std::collections::HashMap;
use std::time::Duration;

use crate::exec::execute_cmd;
use crate::tags::{ActionInfo, TagReplacer};

/// Represents an action executing shell commands (`CommandAction`).
#[derive(Debug, Clone)]
pub struct CommandAction {
    pub name: String,
    pub jail_name: String,
    pub timeout: Duration,
    pub actionstart: String,
    pub actionstart_on_demand: bool,
    pub actionstop: String,
    pub actionflush: String,
    pub actionreload: String,
    pub actioncheck: String,
    pub actionrepair: String,
    pub actionban: String,
    pub actionunban: String,
    pub norestored: bool,
    pub properties: IndexMap<String, String>,
    started: HashMap<String, bool>,
}

impl CommandAction {
    pub fn new(jail_name: &str, name: &str) -> Self {
        Self {
            name: name.to_owned(),
            jail_name: jail_name.to_owned(),
            timeout: Duration::from_secs(60),
            actionstart: String::new(),
            actionstart_on_demand: false,
            actionstop: String::new(),
            actionflush: String::new(),
            actionreload: String::new(),
            actioncheck: String::new(),
            actionrepair: String::new(),
            actionban: String::new(),
            actionunban: String::new(),
            norestored: false,
            properties: IndexMap::new(),
            started: HashMap::new(),
        }
    }

    pub fn set_property(&mut self, key: impl Into<String>, val: impl Into<String>) {
        let k = key.into();
        let v = val.into();
        match k.as_str() {
            "actionstart" => self.actionstart = v,
            "actionstart_on_demand" => self.actionstart_on_demand = f2b_helpers::as_bool(&v),
            "actionstop" => self.actionstop = v,
            "actionflush" => self.actionflush = v,
            "actionreload" => self.actionreload = v,
            "actioncheck" => self.actioncheck = v,
            "actionrepair" => self.actionrepair = v,
            "actionban" => self.actionban = v,
            "actionunban" => self.actionunban = v,
            "norestored" => self.norestored = f2b_helpers::as_bool(&v),
            "timeout" => {
                if let Ok(secs) = v.parse::<u64>() {
                    self.timeout = Duration::from_secs(secs);
                }
            }
            _ => {
                self.properties.insert(k, v);
            }
        }
    }

    pub fn is_started(&self, family: &str) -> bool {
        self.started.get(family).copied().unwrap_or(false)
    }

    /// Prepares and executes a command with dynamic tag substitution.
    pub fn run_operation(
        &self,
        template: &str,
        ainfo: Option<&ActionInfo>,
        family: Option<&str>,
    ) -> Result<bool, String> {
        if template.trim().is_empty() {
            return Ok(true);
        }

        let mut props = self.properties.clone();
        if let Some(f) = family {
            props.insert("family".to_owned(), f.to_owned());
        }
        props.insert("name".to_owned(), self.jail_name.clone());
        props.insert("actname".to_owned(), self.name.clone());

        // Resolve static properties first
        let resolved_props =
            TagReplacer::resolve_properties(&props, family.unwrap_or("")).unwrap_or(props);

        // Replace dynamic tags and generate safe shell command
        let (real_cmd, vars) = TagReplacer::replace_dynamic_tags(template, ainfo, &resolved_props);

        log::debug!(
            "[{}] action '{}': exec: {}",
            self.jail_name,
            self.name,
            real_cmd
        );
        let res = execute_cmd(&real_cmd, self.timeout, &vars)?;
        if !res.success {
            log::error!(
                "[{}] action '{}' failed with status {}: {}\nstderr: {}",
                self.jail_name,
                self.name,
                res.status,
                real_cmd,
                res.stderr
            );
            return Ok(false);
        }

        Ok(true)
    }

    pub fn start(&mut self, family: Option<&str>) -> Result<bool, String> {
        let fam = family.unwrap_or("inet4");
        if self.is_started(fam) {
            return Ok(true);
        }

        if !self.actionstart.is_empty() {
            let ok = self.run_operation(&self.actionstart, None, Some(fam))?;
            if !ok {
                return Ok(false);
            }
        }

        self.started.insert(fam.to_owned(), true);
        Ok(true)
    }

    pub fn stop(&mut self, family: Option<&str>) -> Result<bool, String> {
        let fam = family.unwrap_or("inet4");
        if !self.actionstop.is_empty() {
            let _ = self.run_operation(&self.actionstop, None, Some(fam));
        }
        self.started.insert(fam.to_owned(), false);
        Ok(true)
    }

    pub fn check(&self, family: Option<&str>) -> Result<bool, String> {
        if self.actioncheck.is_empty() {
            return Ok(true);
        }
        self.run_operation(&self.actioncheck, None, family)
    }

    pub fn repair(&mut self, family: Option<&str>) -> Result<bool, String> {
        if !self.actionrepair.is_empty() {
            let ok = self.run_operation(&self.actionrepair, None, family)?;
            if ok {
                let fam = family.unwrap_or("inet4");
                self.started.insert(fam.to_owned(), true);
                return Ok(true);
            }
        }
        // Fallback: restart action
        self.stop(family)?;
        self.start(family)
    }

    pub fn ban(&mut self, ainfo: &ActionInfo) -> Result<bool, String> {
        let fam = &ainfo.family;
        // Start on demand if not yet started
        if !self.is_started(fam) {
            self.start(Some(fam))?;
        }

        // Invariant check
        if !self.actioncheck.is_empty() {
            let check_ok = self.check(Some(fam))?;
            if !check_ok {
                log::warn!(
                    "[{}] Invariant check failed for action '{}', repairing...",
                    self.jail_name,
                    self.name
                );
                self.repair(Some(fam))?;
            }
        }

        self.run_operation(&self.actionban, Some(ainfo), Some(fam))
    }

    pub fn unban(&mut self, ainfo: &ActionInfo) -> Result<bool, String> {
        let fam = &ainfo.family;
        if self.actionunban.is_empty() {
            return Ok(true);
        }
        self.run_operation(&self.actionunban, Some(ainfo), Some(fam))
    }

    pub fn flush(&mut self) -> Result<bool, String> {
        if self.actionflush.is_empty() {
            return Ok(true);
        }
        self.run_operation(&self.actionflush, None, None)
    }

    pub fn reload(&mut self) -> Result<bool, String> {
        if self.actionreload.is_empty() {
            return Ok(true);
        }
        self.run_operation(&self.actionreload, None, None)
    }
}
