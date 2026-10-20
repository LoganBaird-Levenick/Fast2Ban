//! Port of `Transmitter` (`fail2ban/server/transmitter.py`): dispatch of the
//! client commands onto the [`Server`] and its jails.

use std::sync::{Arc, Mutex, MutexGuard};

use f2b_action::Jail;
use f2b_proto::Value;
use f2b_regex::UseDns;

use crate::logging::Logging;
use crate::server::{JailHandle, Server, lock_jail};

type Res = Result<Value, String>;

#[derive(Debug)]
pub struct Transmitter {
    server: Arc<Mutex<Server>>,
}

// ------------------------------------------------------------------ helpers

fn text(args: &[Value], i: usize) -> Result<String, String> {
    args.get(i)
        .map(|v| v.clone().into_string())
        .ok_or_else(|| "Invalid command (missing argument)".to_owned())
}

fn int(args: &[Value], i: usize) -> Result<i64, String> {
    match args.get(i) {
        Some(Value::Int(n)) => Ok(*n),
        Some(Value::Bool(b)) => Ok(i64::from(*b)),
        Some(Value::Str(s)) => s
            .trim()
            .parse()
            .map_err(|_| format!("invalid literal for int() with base 10: {s:?}")),
        _ => Err("Invalid command (integer argument expected)".to_owned()),
    }
}

fn strs(items: impl IntoIterator<Item = String>) -> Value {
    Value::List(items.into_iter().map(Value::Str).collect())
}

fn opt_str(s: Option<String>) -> Value {
    s.map_or(Value::None, Value::Str)
}

/// `MyTime.str2seconds` as a number.
fn seconds(value: &str) -> Result<f2b_expr::Num, String> {
    f2b_expr::str2seconds(value).map_err(|e| e.to_string())
}

fn num_value(n: f64) -> Value {
    if n.fract() == 0.0 && n.abs() < 9.0e15 {
        Value::Int(n as i64)
    } else {
        Value::Float(n)
    }
}

fn use_dns_text(u: UseDns) -> &'static str {
    match u {
        UseDns::Yes => "yes",
        UseDns::Warn => "warn",
        UseDns::No => "no",
        UseDns::Raw => "raw",
    }
}

fn quiet_or(quiet: bool, v: Value) -> Value {
    if quiet { Value::None } else { v }
}

fn lock_server(server: &Mutex<Server>) -> MutexGuard<'_, Server> {
    server.lock().unwrap_or_else(|e| e.into_inner())
}

/// Encodings the log readers can decode. `auto` follows the UTF-8 locale.
fn normalize_encoding(enc: &str) -> Result<String, String> {
    let lower = enc.to_ascii_lowercase().replace('_', "-");
    match lower.as_str() {
        "auto" | "utf-8" | "utf8" => Ok("UTF-8".to_owned()),
        "ascii" | "us-ascii" => Ok("ASCII".to_owned()),
        "latin-1" | "latin1" | "iso-8859-1" | "iso8859-1" | "l1" => Ok("latin-1".to_owned()),
        _ => Err(format!("unknown encoding: {enc}")),
    }
}

impl Transmitter {
    pub fn new(server: Arc<Mutex<Server>>) -> Self {
        Self { server }
    }

    pub fn is_running(&self) -> bool {
        lock_server(&self.server).running
    }

    /// Process an incoming command list and return `(0, result)` on success or
    /// `(1, Exception(msg))` on failure.
    pub fn proceed(&self, command: Value) -> Value {
        let result = match &command {
            Value::List(args) => self.handle(args, false),
            _ => Err("Invalid command format (expected list)".to_owned()),
        };
        match result {
            Ok(ret) => Value::Tuple(vec![Value::Int(0), ret]),
            Err(e) => {
                log::error!("Command {command:?} has failed. Received {e:?}");
                Value::Tuple(vec![Value::Int(1), Value::Exception(e)])
            }
        }
    }

    fn jail(&self, name: &str) -> Result<JailHandle, String> {
        lock_server(&self.server).jail(name)
    }

    // -------------------------------------------------------------- commands

    fn handle(&self, args: &[Value], quiet: bool) -> Res {
        let name = text(args, 0)?;
        match name.as_str() {
            "ping" => Ok(Value::Str("pong".to_owned())),
            "add" => {
                let jail = text(args, 1)?;
                if jail == "--all" {
                    return Err(format!("Reserved name {jail:?}"));
                }
                let backend = if args.len() > 2 {
                    text(args, 2)?
                } else {
                    "auto".to_owned()
                };
                lock_server(&self.server).add_jail(&jail, &backend)?;
                Ok(Value::Str(jail))
            }
            "multi-set" => self.set(&args[1..], true, quiet),
            "set" => self.set(&args[1..], false, quiet),
            "start" => {
                lock_server(&self.server).start_jail(&text(args, 1)?)?;
                Ok(Value::None)
            }
            "stop" => {
                let mut s = lock_server(&self.server);
                if args.len() == 1 {
                    s.quit();
                } else if text(args, 1)? == "--all" {
                    s.stop_all_jails();
                } else {
                    s.stop_jail(&text(args, 1)?)?;
                }
                Ok(Value::None)
            }
            "reload" => self.reload(args),
            "unban" if args.len() >= 2 => {
                let ips: Vec<String> = args[1..].iter().map(|v| v.clone().into_string()).collect();
                let refs: Vec<&str> = ips.iter().map(String::as_str).collect();
                if refs == ["--all"] {
                    self.unban(None, None, true)
                } else {
                    self.unban(None, Some(&refs), true)
                }
            }
            "banned" => {
                let ids: Vec<String> = args[1..].iter().map(|v| v.clone().into_string()).collect();
                self.banned(None, &ids)
            }
            "echo" => Ok(Value::List(args[1..].to_vec())),
            "server-status" => Ok(Value::Str("Server ready".to_owned())),
            "server-stream" => {
                if let Some(Value::List(cmds)) = args.get(1) {
                    for cmd in cmds {
                        let Value::List(c) = cmd else {
                            return Err("Invalid command format (expected list)".to_owned());
                        };
                        self.handle(c, true)?;
                    }
                }
                Ok(Value::None)
            }
            "sleep" => {
                let secs: f64 = text(args, 1)?
                    .parse()
                    .map_err(|_| "could not convert string to float".to_owned())?;
                std::thread::sleep(std::time::Duration::from_secs_f64(secs.max(0.0)));
                Ok(Value::None)
            }
            "flushlogs" => match Logging::global() {
                Some(l) => l.flush().map(|s| Value::Str(s.to_owned())),
                None => Ok(Value::Str("flushed".to_owned())),
            },
            "get" => self.get(&args[1..]),
            "status" => self.status(&args[1..]),
            "stats" | "statistic" | "statistics" => self.status(&[
                Value::Str("--all".to_owned()),
                Value::Str("stats".to_owned()),
            ]),
            "version" => Ok(Value::Str(f2b_types::UPSTREAM_COMPAT_VERSION.to_owned())),
            "config-error" => {
                log::error!("{}", text(args, 1)?);
                Ok(Value::None)
            }
            _ => Err("Invalid command".to_owned()),
        }
    }

    /// `reload <jail|--all> <opts> <stream>`: begin, run the stream quietly,
    /// always finish the reload.
    fn reload(&self, args: &[Value]) -> Res {
        let name = text(args, 1)?;
        let opts: Vec<String> = match args.get(2) {
            Some(Value::List(l)) => l.iter().map(|v| v.clone().into_string()).collect(),
            _ => Vec::new(),
        };
        let opt_refs: Vec<&str> = opts.iter().map(String::as_str).collect();
        lock_server(&self.server).reload_jails(&name, &opt_refs, true)?;
        let run = || -> Result<(), String> {
            if let Some(Value::List(cmds)) = args.get(3) {
                for cmd in cmds {
                    let Value::List(c) = cmd else {
                        return Err("Invalid command format (expected list)".to_owned());
                    };
                    self.handle(c, true)?;
                }
            }
            Ok(())
        };
        let ran = run();
        let end = lock_server(&self.server).reload_jails(&name, &opt_refs, false);
        ran?;
        end?;
        Ok(Value::Str("OK".to_owned()))
    }

    /// `Server.setUnbanIP`.
    fn unban(&self, name: Option<&str>, ips: Option<&[&str]>, if_exists: bool) -> Res {
        let jails = match name {
            Some(n) => vec![(n.to_owned(), self.jail(n)?)],
            None => lock_server(&self.server).jails_sorted(),
        };
        let if_exists = if_exists || name.is_none();
        let mut count = 0;
        for (_, handle) in jails {
            count += lock_jail(&handle).unban_ips(ips, if_exists)?;
        }
        Ok(Value::Int(i64::try_from(count).unwrap_or(i64::MAX)))
    }

    /// `Server.banned`.
    fn banned(&self, name: Option<&str>, ids: &[String]) -> Res {
        if let Some(n) = name {
            let handle = self.jail(n)?;
            let jail = lock_jail(&handle);
            return Ok(Self::banned_in(&jail, ids));
        }
        let jails = lock_server(&self.server).jails_sorted();
        if ids.is_empty() {
            let mut out = Vec::new();
            for (n, handle) in jails {
                let jail = lock_jail(&handle);
                out.push(Value::Dict(vec![(
                    Value::Str(n),
                    Self::banned_in(&jail, ids),
                )]));
            }
            return Ok(Value::List(out));
        }
        Ok(Value::List(
            ids.iter()
                .map(|ip| {
                    strs(
                        jails
                            .iter()
                            .filter(|(_, h)| lock_jail(h).is_banned(ip))
                            .map(|(n, _)| n.clone()),
                    )
                })
                .collect(),
        ))
    }

    fn banned_in(jail: &Jail, ids: &[String]) -> Value {
        match ids {
            [] => strs(jail.ban_list(false)),
            [one] => Value::Int(i64::from(jail.is_banned(one))),
            many => Value::List(
                many.iter()
                    .map(|ip| Value::Int(i64::from(jail.is_banned(ip))))
                    .collect(),
            ),
        }
    }

    // ------------------------------------------------------------------- set

    fn set(&self, args: &[Value], multiple: bool, quiet: bool) -> Res {
        let name = text(args, 0)?;
        match name.as_str() {
            "loglevel" => {
                let value = text(args, 1)?;
                match Logging::global() {
                    Some(l) => l.set_level(&value)?,
                    None => lock_server(&self.server).log_level = value.to_uppercase(),
                }
                Ok(quiet_or(quiet, Value::Str(self.log_level())))
            }
            "logtarget" => {
                let value = text(args, 1)?;
                match Logging::global() {
                    Some(l) => l.set_target(&value)?,
                    None => lock_server(&self.server).log_target = value,
                }
                Ok(quiet_or(quiet, Value::Str(self.log_target())))
            }
            "syslogsocket" => {
                let value = text(args, 1)?;
                match Logging::global() {
                    Some(l) => l.set_syslog_socket(&value)?,
                    None => lock_server(&self.server).syslog_socket = value,
                }
                Ok(quiet_or(quiet, Value::Str(self.syslog_socket())))
            }
            "allowipv6" => {
                let value = text(args, 1)?;
                lock_server(&self.server).allow_ipv6.clone_from(&value);
                Ok(quiet_or(quiet, Value::Str(value)))
            }
            "thread" => {
                let value = text(args, 1)?;
                lock_server(&self.server).thread_options = value;
                Ok(Value::None)
            }
            "dbfile" => {
                let mut s = lock_server(&self.server);
                s.set_database(&text(args, 1)?)?;
                Ok(match (&s.db, quiet) {
                    (Some(db), false) => Value::Str(db.filename().to_string_lossy().into_owned()),
                    _ => Value::None,
                })
            }
            "dbmaxmatches" => {
                let n = int(args, 1)?;
                let s = lock_server(&self.server);
                let Some(db) = &s.db else {
                    log::debug!("dbmaxmatches setting was not in effect since no db yet");
                    return Ok(Value::None);
                };
                db.set_max_matches(usize::try_from(n).unwrap_or(0));
                Ok(quiet_or(quiet, num_value(db.max_matches() as f64)))
            }
            "dbpurgeage" => {
                let value = seconds(&text(args, 1)?)?;
                let s = lock_server(&self.server);
                let Some(db) = &s.db else {
                    log::debug!("dbpurgeage setting was not in effect since no db yet");
                    return Ok(Value::None);
                };
                db.set_purge_age(value.as_i64().map_err(|e| e.to_string())?);
                Ok(quiet_or(quiet, Value::Int(db.purge_age())))
            }
            jail_name => {
                if args.len() < 2 {
                    return Err(format!("Usage: set {jail_name} <option> <value...>"));
                }
                let handle = self.jail(jail_name)?;
                let mut jail = lock_jail(&handle);
                self.set_jail(&mut jail, args, multiple, quiet)
            }
        }
    }

    fn set_jail(&self, jail: &mut Jail, args: &[Value], multiple: bool, quiet: bool) -> Res {
        let opt = text(args, 1)?;
        let now = jail.clock.time();
        let done =
            |jail: &Jail, key: &str| -> Res { Ok(quiet_or(quiet, get_jail_opt(jail, key, &[])?)) };
        match opt.as_str() {
            "idle" => {
                match text(args, 2)?.as_str() {
                    "on" => jail.idle = true,
                    "off" => jail.idle = false,
                    _ => return Err("Invalid idle option, must be 'on' or 'off'".to_owned()),
                }
                done(jail, "idle")
            }
            "ignoreself" => {
                jail.set_ignore_self(f2b_helpers::as_bool(&text(args, 2)?));
                done(jail, "ignoreself")
            }
            "addignoreip" => {
                for v in &args[2..] {
                    let ip = v.clone().into_string();
                    if ip.is_empty() {
                        continue;
                    }
                    jail.add_ignore_ip(&ip)
                        .map_err(|_| format!("Unable to add ignore IP {ip:?}: invalid address"))?;
                }
                done(jail, "ignoreip")
            }
            "delignoreip" => {
                jail.del_ignore_ip(&text(args, 2)?);
                done(jail, "ignoreip")
            }
            "ignorecommand" => {
                let v = text(args, 2)?;
                jail.set_ignore_command((!v.is_empty()).then_some(v));
                done(jail, "ignorecommand")
            }
            "ignorecache" => {
                let v = text(args, 2)?;
                jail.set_ignore_cache((!v.is_empty()).then_some(v));
                done(jail, "ignorecache")
            }
            "addlogpath" => {
                let path = text(args, 2)?;
                let mut tail = false;
                if args.len() == 4 {
                    match text(args, 3)?.to_lowercase().as_str() {
                        "tail" => tail = true,
                        "head" => {}
                        _ => return Err("File option must be 'head' or 'tail'".to_owned()),
                    }
                } else if args.len() > 4 {
                    return Err("Only one file can be added at a time".to_owned());
                }
                jail.add_log_path(&path, tail)
                    .map_err(|e| format!("Failed to open {path}: {e}"))?;
                done(jail, "logpath")
            }
            "dellogpath" => {
                jail.del_log_path(&text(args, 2)?);
                done(jail, "logpath")
            }
            "logencoding" => {
                let enc = normalize_encoding(&text(args, 2)?)?;
                jail.set_log_encoding(&enc);
                done(jail, "logencoding")
            }
            "addjournalmatch" => {
                let m: Vec<String> = args[2..].iter().map(|v| v.clone().into_string()).collect();
                jail.add_journal_match(&m)?;
                done(jail, "journalmatch")
            }
            "deljournalmatch" => {
                let m: Vec<String> = args[2..].iter().map(|v| v.clone().into_string()).collect();
                jail.del_journal_match(&m)?;
                done(jail, "journalmatch")
            }
            "prefregex" => {
                jail.filter
                    .set_pref_regex(Some(&text(args, 2)?))
                    .map_err(|e| e.to_string())?;
                done(jail, "prefregex")
            }
            "addfailregex" => {
                if multiple {
                    let Some(Value::List(items)) = args.get(2) else {
                        return Err("addfailregex expects a list of regular expressions".to_owned());
                    };
                    for item in items {
                        jail.filter
                            .add_fail_regex(&item.clone().into_string())
                            .map_err(|e| e.to_string())?;
                    }
                    return Ok(Value::Bool(true));
                }
                jail.filter
                    .add_fail_regex(&text(args, 2)?)
                    .map_err(|e| e.to_string())?;
                done(jail, "failregex")
            }
            "delfailregex" => {
                let i =
                    usize::try_from(int(args, 2)?).map_err(|_| "Index is not valid".to_owned())?;
                jail.filter.del_fail_regex(i).map_err(|e| e.to_string())?;
                done(jail, "failregex")
            }
            "addignoreregex" => {
                if multiple {
                    let Some(Value::List(items)) = args.get(2) else {
                        return Err(
                            "addignoreregex expects a list of regular expressions".to_owned()
                        );
                    };
                    for item in items {
                        jail.filter
                            .add_ignore_regex(&item.clone().into_string())
                            .map_err(|e| e.to_string())?;
                    }
                    return Ok(Value::Bool(true));
                }
                jail.filter
                    .add_ignore_regex(&text(args, 2)?)
                    .map_err(|e| e.to_string())?;
                done(jail, "ignoreregex")
            }
            "delignoreregex" => {
                let i =
                    usize::try_from(int(args, 2)?).map_err(|_| "Index is not valid".to_owned())?;
                jail.filter.del_ignore_regex(i).map_err(|e| e.to_string())?;
                done(jail, "ignoreregex")
            }
            "usedns" => {
                jail.filter.set_use_dns(&text(args, 2)?);
                done(jail, "usedns")
            }
            "findtime" => {
                let secs = seconds(&text(args, 2)?)?.as_f64();
                jail.set_find_time(secs);
                done(jail, "findtime")
            }
            "datepattern" => {
                let v = args.get(2).and_then(|v| match v {
                    Value::None => None,
                    other => Some(other.clone().into_string()),
                });
                jail.filter
                    .set_date_pattern(v.as_deref())
                    .map_err(|e| e.to_string())?;
                done(jail, "datepattern")
            }
            "logtimezone" => {
                jail.filter
                    .set_log_time_zone(&text(args, 2)?)
                    .map_err(|e| e.to_string())?;
                done(jail, "logtimezone")
            }
            "maxmatches" => {
                let n = usize::try_from(int(args, 2)?).unwrap_or(0);
                jail.fail_manager.set_max_matches(n);
                done(jail, "maxmatches")
            }
            "maxretry" => {
                jail.fail_manager.set_max_retry(int(args, 2)?);
                done(jail, "maxretry")
            }
            "maxlines" => {
                jail.filter
                    .set_max_lines(int(args, 2)?)
                    .map_err(|e| e.to_string())?;
                done(jail, "maxlines")
            }
            "bantime" => {
                let n = seconds(&text(args, 2)?)?
                    .as_i64()
                    .map_err(|e| e.to_string())?;
                jail.actions.ban_manager.set_ban_time(n);
                done(jail, "bantime")
            }
            "attempt" => {
                let ip = text(args, 2)?;
                let matches: Vec<String> =
                    args[3..].iter().map(|v| v.clone().into_string()).collect();
                Ok(Value::Int(jail.add_attempt(&ip, matches, now)?))
            }
            o if o.starts_with("bantime.") => {
                let extra = &o["bantime.".len()..];
                let v = args.get(2).and_then(|v| match v {
                    Value::None => None,
                    other => Some(other.clone().into_string()),
                });
                jail.set_ban_time_extra(extra, v.as_deref())?;
                Ok(quiet_or(quiet, opt_str(jail.get_ban_time_extra(extra))))
            }
            "banip" => {
                let ips: Vec<String> = args[2..].iter().map(|v| v.clone().into_string()).collect();
                let refs: Vec<&str> = ips.iter().map(String::as_str).collect();
                let n = jail.ban_ips(&refs, now)?;
                Ok(Value::Int(i64::try_from(n).unwrap_or(i64::MAX)))
            }
            "unbanip" => {
                let mut if_exists = true;
                let mut first = 2;
                if text(args, 2)? == "--report-absent" {
                    if_exists = false;
                    first = 3;
                }
                let ips: Vec<String> = args[first..]
                    .iter()
                    .map(|v| v.clone().into_string())
                    .collect();
                let refs: Vec<&str> = ips.iter().map(String::as_str).collect();
                let n = jail.unban_ips(Some(&refs), if_exists)?;
                Ok(Value::Int(i64::try_from(n).unwrap_or(i64::MAX)))
            }
            "addaction" => {
                if args.len() > 3 {
                    return Err(format!(
                        "Python actions are not supported (action {:?}, module {:?}); use a command action",
                        text(args, 2)?,
                        text(args, 3)?
                    ));
                }
                let act = text(args, 2)?;
                jail.add_action(&act);
                Ok(quiet_or(quiet, Value::Str(act)))
            }
            "delaction" => {
                let act = text(args, 2)?;
                jail.actions.actions.shift_remove(&act);
                Ok(Value::None)
            }
            "action" => self.set_action(jail, args, multiple, quiet),
            other => Err(format!(
                "Invalid command {other:?} (no set action or not yet implemented)"
            )),
        }
    }

    fn set_action(&self, jail: &mut Jail, args: &[Value], multiple: bool, quiet: bool) -> Res {
        let act_name = text(args, 2)?;
        let jail_name = jail.name.clone();
        let action = jail
            .actions
            .get_action_mut(&act_name)
            .ok_or_else(|| format!("Invalid Action name: {act_name}"))?;
        if multiple {
            let Some(Value::List(pairs)) = args.get(3) else {
                return Err("multi-set action expects a list of [key, value]".to_owned());
            };
            for pair in pairs {
                let Value::List(kv) = pair else {
                    return Err("multi-set action expects [key, value] pairs".to_owned());
                };
                let key = text(kv, 0)?;
                let value = kv
                    .get(1)
                    .map(|v| v.clone().into_string())
                    .unwrap_or_default();
                action.set_property(key, value);
            }
            return Ok(Value::Bool(true));
        }
        let key = text(args, 3)?;
        match key.as_str() {
            "start" | "stop" | "flush" | "reload" | "check" | "repair" => {
                let r = match key.as_str() {
                    "start" => action.start(None),
                    "stop" => action.stop(None),
                    "flush" => action.flush(),
                    "reload" => action.reload(),
                    "check" => action.check(None),
                    _ => action.repair(None),
                };
                let ok = r.map_err(|e| format!("[{jail_name}] action {act_name} {key}: {e}"))?;
                Ok(quiet_or(quiet, Value::Bool(ok)))
            }
            _ => {
                action.set_property(key.clone(), text(args, 4)?);
                Ok(quiet_or(quiet, opt_str(action.get_property(&key))))
            }
        }
    }

    // ------------------------------------------------------------------- get

    fn get(&self, args: &[Value]) -> Res {
        let name = text(args, 0)?;
        match name.as_str() {
            "loglevel" => Ok(Value::Str(self.log_level())),
            "logtarget" => Ok(Value::Str(self.log_target())),
            "syslogsocket" => Ok(Value::Str(self.syslog_socket())),
            "thread" => Ok(Value::Str(lock_server(&self.server).thread_options.clone())),
            "dbfile" => Ok(lock_server(&self.server)
                .db
                .as_ref()
                .map_or(Value::None, |d| {
                    Value::Str(d.filename().to_string_lossy().into_owned())
                })),
            "dbmaxmatches" => Ok(lock_server(&self.server)
                .db
                .as_ref()
                .map_or(Value::None, |d| Value::Int(d.max_matches() as i64))),
            "dbpurgeage" => Ok(lock_server(&self.server)
                .db
                .as_ref()
                .map_or(Value::None, |d| Value::Int(d.purge_age()))),
            jail_name => {
                if args.len() < 2 {
                    return Err(format!("Usage: get {jail_name} <option>"));
                }
                let opt = text(args, 1)?;
                if opt == "banned" {
                    let ids: Vec<String> =
                        args[2..].iter().map(|v| v.clone().into_string()).collect();
                    return self.banned(Some(jail_name), &ids);
                }
                let handle = self.jail(jail_name)?;
                let jail = lock_jail(&handle);
                get_jail_opt(&jail, &opt, &args[2..])
            }
        }
    }

    fn log_level(&self) -> String {
        Logging::global().map_or_else(
            || lock_server(&self.server).log_level.clone(),
            Logging::level,
        )
    }

    fn log_target(&self) -> String {
        Logging::global().map_or_else(
            || lock_server(&self.server).log_target.clone(),
            Logging::target,
        )
    }

    fn syslog_socket(&self) -> String {
        Logging::global().map_or_else(
            || lock_server(&self.server).syslog_socket.clone(),
            Logging::syslog_socket,
        )
    }

    // ---------------------------------------------------------------- status

    fn status(&self, args: &[Value]) -> Res {
        if args.is_empty() {
            return Ok(self.server_status("", "basic"));
        }
        if args.len() > 2 {
            return Err("Invalid command (no status)".to_owned());
        }
        let name = text(args, 0)?;
        let flavor = if args.len() == 2 {
            text(args, 1)?
        } else {
            "basic".to_owned()
        };
        if name == "--all" {
            return Ok(self.server_status("--all", &flavor));
        }
        let handle = self.jail(&name)?;
        let jail = lock_jail(&handle);
        jail_status(&jail, &flavor)
    }

    /// `Server.status`: jail overview, with `--all` the status of every jail.
    fn server_status(&self, name: &str, flavor: &str) -> Value {
        let jails = lock_server(&self.server).jails_sorted();
        let mut ret = Vec::new();
        if flavor != "stats" {
            ret.push(Value::Tuple(vec![
                Value::Str("Number of jail".to_owned()),
                Value::Int(i64::try_from(jails.len()).unwrap_or(i64::MAX)),
            ]));
            ret.push(Value::Tuple(vec![
                Value::Str("Jail list".to_owned()),
                Value::Str(
                    jails
                        .iter()
                        .map(|(n, _)| n.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                ),
            ]));
        }
        if name == "--all" {
            let mut stat = Vec::new();
            for (n, handle) in &jails {
                let jail = lock_jail(handle);
                let st = jail_status(&jail, flavor).unwrap_or(Value::None);
                stat.push((Value::Str(n.clone()), st));
            }
            if flavor == "stats" {
                return Value::Dict(stat);
            }
            ret.push(Value::Dict(stat));
        }
        Value::List(ret)
    }
}

fn count_value(n: usize) -> Value {
    Value::Int(i64::try_from(n).unwrap_or(i64::MAX))
}

/// `Jail.status(flavor)`.
fn jail_status(jail: &Jail, flavor: &str) -> Res {
    let (failed, total_failed) = jail.filter_counts();
    let (banned, total_banned) = jail.action_counts();
    if flavor == "stats" {
        return Ok(Value::List(vec![
            Value::Str(jail.backend_name.clone()),
            Value::Tuple(vec![count_value(failed), count_value(total_failed)]),
            Value::Tuple(vec![count_value(banned), count_value(total_banned)]),
        ]));
    }
    if flavor == "cymru" {
        return Err("status flavor 'cymru' is not supported (it needs DNS lookups)".to_owned());
    }
    let pair = |k: &str, v: Value| Value::Tuple(vec![Value::Str(k.to_owned()), v]);
    let mut filter = vec![
        pair("Currently failed", count_value(failed)),
        pair("Total failed", count_value(total_failed)),
    ];
    if jail.backend.is_journal() {
        let groups: Vec<String> = jail.journal_matches().iter().map(|g| g.join(" ")).collect();
        filter.push(pair("Journal matches", strs([groups.join(" + ")])));
    } else {
        filter.push(pair("File list", strs(jail.log_paths())));
    }
    let mut actions = vec![
        pair("Currently banned", count_value(banned)),
        pair("Total banned", count_value(total_banned)),
    ];
    if flavor != "short" {
        actions.push(pair("Banned IP list", strs(jail.ban_list(false))));
    }
    Ok(Value::List(vec![
        pair("Filter", Value::List(filter)),
        pair("Actions", Value::List(actions)),
    ]))
}

/// The getters of `Transmitter.__commandGet` for jail options (also used to
/// report the result of the matching setters).
fn get_jail_opt(jail: &Jail, opt: &str, rest: &[Value]) -> Res {
    Ok(match opt {
        "idle" => Value::Bool(jail.idle),
        "logpath" => strs(jail.log_paths()),
        "logencoding" => Value::Str(match jail.log_encoding() {
            "auto" => "UTF-8".to_owned(),
            other => other.to_owned(),
        }),
        "journalmatch" => Value::List(jail.journal_matches().into_iter().map(strs).collect()),
        "ignoreself" => Value::Bool(jail.ignore_self),
        "ignoreip" => strs(jail.ignore_list.iter().cloned()),
        "ignorecommand" => Value::Str(jail.ignore_command.clone().unwrap_or_default()),
        "ignorecache" => opt_str(jail.ignore_cache_spec.clone()),
        "prefregex" => Value::Str(
            jail.filter
                .pref_regex()
                .map(|r| r.regex().to_owned())
                .unwrap_or_default(),
        ),
        "failregex" => strs(
            jail.filter
                .fail_regexes()
                .iter()
                .map(|r| r.regex().to_owned()),
        ),
        "ignoreregex" => strs(
            jail.filter
                .ignore_regexes()
                .iter()
                .map(|r| r.regex().to_owned()),
        ),
        "usedns" => Value::Str(use_dns_text(jail.filter.use_dns()).to_owned()),
        "findtime" => num_value(jail.filter.find_time()),
        "datepattern" => match jail.filter.date_detector() {
            Some(dd) => {
                let (pattern, name) = dd.get_date_pattern();
                Value::Tuple(vec![
                    opt_str(pattern.map(str::to_owned)),
                    Value::Str(name.to_owned()),
                ])
            }
            None => Value::None,
        },
        "logtimezone" => opt_str(jail.filter.log_time_zone().map(str::to_owned)),
        "maxmatches" => count_value(jail.fail_manager.max_matches()),
        "maxretry" => Value::Int(jail.fail_manager.max_retry()),
        "maxlines" => count_value(jail.filter.max_lines()),
        "bantime" => Value::Int(jail.actions.ban_manager.ban_time()),
        "banip" => {
            strs(jail.ban_list(matches!(rest.first(), Some(Value::Str(s)) if s == "--with-time")))
        }
        o if o.starts_with("bantime.") => opt_str(jail.get_ban_time_extra(&o["bantime.".len()..])),
        "actions" => strs(jail.actions.names()),
        "action" => {
            let act = text(rest, 0)?;
            let key = text(rest, 1)?;
            let action = jail
                .actions
                .get_action(&act)
                .ok_or_else(|| format!("Invalid Action name: {act}"))?;
            opt_str(action.get_property(&key))
        }
        "actionproperties" => {
            let act = text(rest, 0)?;
            let action = jail
                .actions
                .get_action(&act)
                .ok_or_else(|| format!("Invalid Action name: {act}"))?;
            strs(action.property_names())
        }
        "actionmethods" => {
            let act = text(rest, 0)?;
            jail.actions
                .get_action(&act)
                .ok_or_else(|| format!("Invalid Action name: {act}"))?;
            strs(
                [
                    "ban", "check", "flush", "reload", "repair", "start", "stop", "unban",
                ]
                .iter()
                .map(|s| (*s).to_owned()),
            )
        }
        _ => return Err("Invalid command (no get action or not yet implemented)".to_owned()),
    })
}
