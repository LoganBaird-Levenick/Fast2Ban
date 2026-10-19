//! Port of `Transmitter` (`fail2ban/server/transmitter.py`).

use f2b_proto::Value;
use std::sync::{Arc, Mutex};

use crate::server::Server;

#[derive(Debug)]
pub struct Transmitter {
    server: Arc<Mutex<Server>>,
}

impl Transmitter {
    pub fn new(server: Arc<Mutex<Server>>) -> Self {
        Self { server }
    }
    pub fn is_running(&self) -> bool {
        self.server.lock().unwrap().running
    }

    /// Process an incoming command list and return `(0, result)` on success or `(1, Exception(msg))` on failure.
    pub fn proceed(&self, command: Value) -> Value {
        match self.handle_command(command) {
            Ok(ret) => Value::Tuple(vec![Value::Int(0), ret]),
            Err(e) => Value::Tuple(vec![Value::Int(1), Value::Exception(e)]),
        }
    }

    fn handle_command(&self, command: Value) -> Result<Value, String> {
        let Value::List(args) = command else {
            return Err("Invalid command format (expected list)".to_owned());
        };

        if args.is_empty() {
            return Err("Empty command".to_owned());
        }

        let name = args[0].as_str().ok_or("command name must be string")?;

        match name {
            "ping" => Ok(Value::Str("pong".to_owned())),
            "echo" => {
                let rest = args[1..].to_vec();
                Ok(Value::List(rest))
            }
            "version" => Ok(Value::Str(f2b_types::UPSTREAM_COMPAT_VERSION.to_owned())),
            "server-status" => Ok(Value::Str("Server ready".to_owned())),
            "flushlogs" => Ok(Value::Str("reopened".to_owned())),
            "add" => {
                if args.len() < 2 {
                    return Err("Usage: add <jail> [backend]".to_owned());
                }
                let jail_name = args[1].as_str().ok_or("jail name must be string")?;
                if jail_name == "--all" {
                    return Err("Reserved name '--all'".to_owned());
                }
                let backend = if args.len() >= 3 {
                    args[2].as_str().unwrap_or("auto")
                } else {
                    "auto"
                };

                let mut s = self.server.lock().unwrap();
                s.add_jail(jail_name, backend)?;
                Ok(Value::Str(jail_name.to_owned()))
            }
            "start" => {
                if args.len() < 2 {
                    return Err("Usage: start <jail>".to_owned());
                }
                let jail_name = args[1].as_str().ok_or("jail name must be string")?;
                let mut s = self.server.lock().unwrap();
                s.start_jail(jail_name)?;
                Ok(Value::None)
            }
            "stop" => {
                if args.len() == 1 {
                    let mut s = self.server.lock().unwrap();
                    s.quit();
                    Ok(Value::None)
                } else if args[1].as_str() == Some("--all") {
                    let mut s = self.server.lock().unwrap();
                    s.stop_all_jails()?;
                    Ok(Value::None)
                } else {
                    let jail_name = args[1].as_str().ok_or("jail name must be string")?;
                    let mut s = self.server.lock().unwrap();
                    s.stop_jail(jail_name)?;
                    Ok(Value::None)
                }
            }
            "status" => {
                let s = self.server.lock().unwrap();
                if args.len() == 1 {
                    s.status(None)
                } else {
                    let jail_name = args[1].as_str().ok_or("jail name must be string")?;
                    s.status(Some(jail_name))
                }
            }
            "unban" => {
                if args.len() < 2 {
                    return Err("Usage: unban <ip>...".to_owned());
                }
                let ips: Vec<&str> = args[1..].iter().filter_map(|v| v.as_str()).collect();
                let mut s = self.server.lock().unwrap();
                let count = s.unban_ip(None, &ips)?;
                Ok(Value::Int(count as i64))
            }
            "banned" => {
                let s = self.server.lock().unwrap();
                let mut dict = Vec::new();
                for (name, jail) in &s.jails {
                    let list: Vec<Value> = jail
                        .actions
                        .ban_manager
                        .get_ban_list()
                        .into_iter()
                        .map(|ip| Value::Str(ip.ntoa().to_string()))
                        .collect();
                    dict.push((Value::Str(name.clone()), Value::List(list)));
                }
                Ok(Value::Dict(dict))
            }
            "set" => self.handle_set(&args[1..]),
            "multi-set" => self.handle_multi_set(&args[1..]),
            "get" => self.handle_get(&args[1..]),
            "server-stream" => {
                if args.len() >= 2 {
                    if let Value::List(cmds) = &args[1] {
                        for cmd in cmds {
                            let _ = self.handle_command(cmd.clone())?;
                        }
                    }
                }
                Ok(Value::None)
            }
            other => Err(format!("Invalid command '{other}'")),
        }
    }

    fn handle_set(&self, args: &[Value]) -> Result<Value, String> {
        if args.is_empty() {
            return Err("Empty set command".to_owned());
        }

        let key = args[0].as_str().ok_or("set key must be string")?;

        match key {
            "loglevel" => {
                let val = args.get(1).and_then(|v| v.as_str()).unwrap_or("INFO");
                let mut s = self.server.lock().unwrap();
                s.log_level = val.to_owned();
                Ok(Value::Str(s.log_level.clone()))
            }
            "logtarget" => {
                let val = args.get(1).and_then(|v| v.as_str()).unwrap_or("STDERR");
                let mut s = self.server.lock().unwrap();
                s.log_target = val.to_owned();
                Ok(Value::Str(s.log_target.clone()))
            }
            "syslogsocket" => {
                let val = args.get(1).and_then(|v| v.as_str()).unwrap_or("auto");
                let mut s = self.server.lock().unwrap();
                s.syslog_socket = val.to_owned();
                Ok(Value::Str(s.syslog_socket.clone()))
            }
            "allowipv6" => {
                let val = args.get(1).and_then(|v| v.as_str()).unwrap_or("auto");
                let mut s = self.server.lock().unwrap();
                s.allow_ipv6 = val.to_owned();
                Ok(Value::Str(s.allow_ipv6.clone()))
            }
            "dbfile" => {
                let val = args.get(1).and_then(|v| v.as_str()).unwrap_or("None");
                let mut s = self.server.lock().unwrap();
                s.set_database(val)?;
                Ok(Value::Str(val.to_owned()))
            }
            jail_name => {
                // Per-jail set options: set <jail> <opt> <value...>
                if args.len() < 3 {
                    return Err(format!("Usage: set {jail_name} <option> <value...>"));
                }
                let opt = args[1].as_str().ok_or("jail option must be string")?;
                let mut s = self.server.lock().unwrap();
                let jail = s
                    .jails
                    .get_mut(jail_name)
                    .ok_or_else(|| format!("Jail {jail_name} not found"))?;

                match opt {
                    "maxretry" => {
                        let n = match &args[2] {
                            Value::Int(i) => *i,
                            Value::Str(s) => s.parse::<i64>().unwrap_or(3),
                            _ => 3,
                        };
                        jail.fail_manager.set_max_retry(n);
                        Ok(Value::Int(n))
                    }
                    "findtime" => {
                        let val = args[2].as_str().unwrap_or("600");
                        if let Ok(num) = f2b_expr::str2seconds(val) {
                            jail.fail_manager.set_max_time(num.as_f64());
                        }
                        Ok(Value::Str(val.to_owned()))
                    }
                    "bantime" => {
                        let val = args[2].as_str().unwrap_or("600");
                        if let Ok(num) = f2b_expr::str2seconds(val) {
                            jail.actions
                                .ban_manager
                                .set_ban_time(num.as_i64().unwrap_or(600));
                        }
                        Ok(Value::Str(val.to_owned()))
                    }
                    "addignoreip" => {
                        for ip_val in &args[2..] {
                            if let Some(ip_str) = ip_val.as_str() {
                                let _ = jail.add_ignore_ip(ip_str);
                            }
                        }
                        Ok(Value::None)
                    }
                    "addfailregex" => {
                        let val = args[2].as_str().ok_or("failregex must be string")?;
                        jail.filter.add_fail_regex(val).map_err(|e| e.to_string())?;
                        Ok(Value::Str(val.to_owned()))
                    }
                    "addignoreregex" => {
                        let val = args[2].as_str().ok_or("ignoreregex must be string")?;
                        jail.filter
                            .add_ignore_regex(val)
                            .map_err(|e| e.to_string())?;
                        Ok(Value::Str(val.to_owned()))
                    }
                    "prefregex" => {
                        let val = args[2].as_str();
                        jail.filter.set_pref_regex(val).map_err(|e| e.to_string())?;
                        Ok(Value::Str(val.unwrap_or("").to_owned()))
                    }
                    "datepattern" => {
                        let val = args[2].as_str();
                        jail.filter
                            .set_date_pattern(val)
                            .map_err(|e| e.to_string())?;
                        Ok(Value::Str(val.unwrap_or("").to_owned()))
                    }
                    "addlogpath" => {
                        let path = args[2].as_str().ok_or("logpath must be string")?;
                        let tail = args.get(3).and_then(|v| v.as_str()) == Some("tail");
                        jail.backend
                            .add_log_path(path, tail)
                            .map_err(|e| e.to_string())?;
                        Ok(Value::Str(path.to_owned()))
                    }
                    "addaction" => {
                        let act_name = args[2].as_str().ok_or("action name must be string")?;
                        let act = f2b_action::CommandAction::new(jail_name, act_name);
                        jail.actions.add_action(act);
                        Ok(Value::Str(act_name.to_owned()))
                    }
                    "action" => {
                        // set <jail> action <actname> <key> <val>
                        if args.len() < 5 {
                            return Err("Usage: set <jail> action <actname> <key> <val>".to_owned());
                        }
                        let act_name = args[2].as_str().ok_or("action name must be string")?;
                        let prop_key = args[3].as_str().ok_or("prop key must be string")?;
                        let prop_val = args[4].clone().into_string();

                        let act = jail
                            .actions
                            .get_action_mut(act_name)
                            .ok_or_else(|| format!("Action {act_name} not found"))?;
                        act.set_property(prop_key, prop_val.clone());
                        Ok(Value::Str(prop_val))
                    }
                    _ => Ok(Value::None),
                }
            }
        }
    }

    fn handle_multi_set(&self, args: &[Value]) -> Result<Value, String> {
        if args.len() < 3 {
            return Err("Usage: multi-set <jail> <cmd> <values...>".to_owned());
        }

        let jail_name = args[0].as_str().ok_or("jail name must be string")?;
        let sub_cmd = args[1].as_str().ok_or("sub command must be string")?;

        match sub_cmd {
            "addfailregex" => {
                let mut s = self.server.lock().unwrap();
                let jail = s
                    .jails
                    .get_mut(jail_name)
                    .ok_or_else(|| format!("Jail {jail_name} not found"))?;
                if let Value::List(items) = &args[2] {
                    for item in items {
                        if let Some(r) = item.as_str() {
                            jail.filter.add_fail_regex(r).map_err(|e| e.to_string())?;
                        }
                    }
                }
                Ok(Value::None)
            }
            "action" => {
                // multi-set <jail> action <actname> [[key, val], ...]
                if args.len() < 4 {
                    return Err("Usage: multi-set <jail> action <actname> [[k, v], ...]".to_owned());
                }
                let act_name = args[2].as_str().ok_or("actname must be string")?;
                let mut s = self.server.lock().unwrap();
                let jail = s
                    .jails
                    .get_mut(jail_name)
                    .ok_or_else(|| format!("Jail {jail_name} not found"))?;
                let act = jail
                    .actions
                    .get_action_mut(act_name)
                    .ok_or_else(|| format!("Action {act_name} not found"))?;

                if let Value::List(pairs) = &args[3] {
                    for pair in pairs {
                        if let Value::List(kv) = pair {
                            if kv.len() == 2 {
                                let k = kv[0].clone().into_string();
                                let v = kv[1].clone().into_string();
                                act.set_property(k, v);
                            }
                        }
                    }
                }
                Ok(Value::None)
            }
            _ => Ok(Value::None),
        }
    }

    fn handle_get(&self, args: &[Value]) -> Result<Value, String> {
        if args.is_empty() {
            return Err("Empty get command".to_owned());
        }

        let key = args[0].as_str().ok_or("get key must be string")?;

        match key {
            "loglevel" => {
                let s = self.server.lock().unwrap();
                Ok(Value::Str(s.log_level.clone()))
            }
            "logtarget" => {
                let s = self.server.lock().unwrap();
                Ok(Value::Str(s.log_target.clone()))
            }
            "syslogsocket" => {
                let s = self.server.lock().unwrap();
                Ok(Value::Str(s.syslog_socket.clone()))
            }
            jail_name => {
                if args.len() < 2 {
                    return Err(format!("Usage: get {jail_name} <option>"));
                }
                let opt = args[1].as_str().ok_or("option must be string")?;
                let s = self.server.lock().unwrap();
                let jail = s
                    .jails
                    .get(jail_name)
                    .ok_or_else(|| format!("Jail {jail_name} not found"))?;

                match opt {
                    "maxretry" => Ok(Value::Int(jail.fail_manager.max_retry())),
                    "findtime" => Ok(Value::Int(jail.fail_manager.max_time() as i64)),
                    "bantime" => Ok(Value::Int(jail.actions.ban_manager.ban_time())),
                    "actions" => {
                        let names: Vec<Value> = jail
                            .actions
                            .actions
                            .keys()
                            .cloned()
                            .map(Value::Str)
                            .collect();
                        Ok(Value::List(names))
                    }
                    _ => Ok(Value::None),
                }
            }
        }
    }
}
