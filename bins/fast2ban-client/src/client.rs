//! CLI parsing, configuration streaming, and command execution for `fast2ban-client`.

use std::process::Command;
use std::rc::Rc;

use f2b_config::{Arg, RealFs, Val, read_config};
use f2b_proto::{Beautifier, Value};
use indexmap::IndexMap;

use crate::socket::ClientSocket;

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub conf_dir: String,
    pub socket_path: String,
    pub pid_file: String,
    pub dump: Option<u8>, // 1 for -d, 2 for --dp
    pub test_only: bool,
    pub quiet: bool,
    pub verbose: usize,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            conf_dir: "/etc/fail2ban".to_owned(),
            socket_path: "/var/run/fail2ban/fail2ban.sock".to_owned(),
            pid_file: "/var/run/fail2ban/fail2ban.pid".to_owned(),
            dump: None,
            test_only: false,
            quiet: false,
            verbose: 0,
        }
    }
}

pub fn run_client(args: Vec<String>) -> i32 {
    let mut config = ClientConfig::default();
    let mut positional: Vec<String> = Vec::new();
    let mut i = 1;

    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                return 0;
            }
            "-V" => {
                println!("1.1.2.1");
                return 0;
            }
            "--version" => {
                println!("Fail2Ban v{}", f2b_types::UPSTREAM_COMPAT_VERSION);
                return 0;
            }
            "-c" | "--conf" => {
                i += 1;
                if i < args.len() {
                    config.conf_dir = args[i].clone();
                }
            }
            "-s" | "--socket" => {
                i += 1;
                if i < args.len() {
                    config.socket_path = args[i].clone();
                }
            }
            "-p" | "--pidfile" => {
                i += 1;
                if i < args.len() {
                    config.pid_file = args[i].clone();
                }
            }
            "-d" => config.dump = Some(1),
            "--dp" | "--dump-pretty" => config.dump = Some(2),
            "-t" | "--test" => config.test_only = true,
            "-q" => config.quiet = true,
            "-v" => config.verbose += 1,
            "-b" | "-f" | "-i" => {
                // Daemon/foreground/interactive mode flags
            }
            "--str2sec" => {
                i += 1;
                if i < args.len() {
                    match f2b_expr::str2seconds(&args[i]) {
                        Ok(num) => {
                            println!("{}", num.as_i64().unwrap_or(0));
                            return 0;
                        }
                        Err(e) => {
                            eprintln!("Error converting to seconds: {e}");
                            return 255;
                        }
                    }
                } else {
                    eprintln!("Option --str2sec requires an argument");
                    return 255;
                }
            }
            other if other.starts_with('-') => {
                eprintln!("Unknown option: {other}");
                return 255;
            }
            _ => {
                positional.push(arg.clone());
            }
        }
        i += 1;
    }

    if let Some(dump_mode) = config.dump {
        return dump_configuration(&config, dump_mode == 2);
    }

    if config.test_only {
        return test_configuration(&config);
    }

    if positional.is_empty() {
        print_help();
        return 255;
    }

    execute_client_command(&config, &positional)
}

fn dump_configuration(config: &ClientConfig, _pretty: bool) -> i32 {
    let fs = Rc::new(RealFs);
    let mut cli_conf = IndexMap::new();
    cli_conf.insert("socket".to_owned(), Val::Str(config.socket_path.clone()));
    cli_conf.insert("pidfile".to_owned(), Val::Str(config.pid_file.clone()));

    let res = read_config(fs, &config.conf_dir, None, &cli_conf, true, true);
    if let Some(stream) = res.stream {
        for cmd in stream {
            let json_vals: Vec<serde_json::Value> = cmd.iter().map(arg_to_json).collect();
            println!("{}", serde_json::Value::Array(json_vals));
        }
        0
    } else {
        eprintln!("ERROR: The configuration stream failed because of the invalid syntax.");
        255
    }
}

fn test_configuration(config: &ClientConfig) -> i32 {
    let fs = Rc::new(RealFs);
    let res = read_config(fs, &config.conf_dir, None, &IndexMap::new(), false, true);
    if res.ret && res.stream.is_some() {
        println!("Configuration test successful");
        0
    } else {
        eprintln!("ERROR: test configuration failed");
        255
    }
}

fn arg_to_json(a: &Arg) -> serde_json::Value {
    match a {
        Arg::None => serde_json::Value::Null,
        Arg::Str(s) => serde_json::json!(s),
        Arg::Int(i) => serde_json::json!(i),
        Arg::Bool(b) => serde_json::json!(b),
        Arg::List(l) => serde_json::Value::Array(l.iter().map(arg_to_json).collect()),
        Arg::Map(m) => {
            serde_json::Value::Object(m.iter().map(|(k, v)| (k.clone(), arg_to_json(v))).collect())
        }
    }
}

fn execute_client_command(config: &ClientConfig, cmd: &[String]) -> i32 {
    let mut csock = ClientSocket::new(&config.socket_path);

    let first = cmd[0].as_str();
    if first == "start" {
        // If server is not alive, spawn server first
        if !csock.is_alive() {
            println!("Starting server...");
            let server_bin = "fast2ban-server";
            let _ = Command::new(server_bin)
                .arg("-c")
                .arg(&config.conf_dir)
                .arg("-s")
                .arg(&config.socket_path)
                .arg("-p")
                .arg(&config.pid_file)
                .spawn();

            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        // Stream configuration
        let fs = Rc::new(RealFs);
        let res = read_config(fs, &config.conf_dir, None, &IndexMap::new(), true, false);
        let Some(stream) = res.stream else {
            eprintln!("ERROR: Failed to read configuration stream");
            return 255;
        };

        let mut values_stream = Vec::new();
        for command in stream {
            let row: Vec<Value> = command.into_iter().map(arg_to_value).collect();
            values_stream.push(Value::List(row));
        }

        let send_res = csock.send(&[
            Value::Str("server-stream".to_owned()),
            Value::List(values_stream),
        ]);
        match send_res {
            Ok(_) => {
                println!("Server ready");
                0
            }
            Err(e) => {
                eprintln!("ERROR: {e}");
                255
            }
        }
    } else {
        let req: Vec<Value> = cmd.iter().map(|s| Value::Str(s.clone())).collect();
        match csock.send(&req) {
            Ok(resp) => {
                let beautified = Beautifier::beautify(cmd, &resp);
                if !beautified.is_empty() {
                    println!("{beautified}");
                }
                0
            }
            Err(e) => {
                eprintln!("{e}");
                255
            }
        }
    }
}

fn arg_to_value(a: Arg) -> Value {
    match a {
        Arg::None => Value::None,
        Arg::Str(s) => Value::Str(s),
        Arg::Int(i) => Value::Int(i),
        Arg::Bool(b) => Value::Bool(b),
        Arg::List(l) => Value::List(l.into_iter().map(arg_to_value).collect()),
        Arg::Map(m) => Value::Dict(
            m.into_iter()
                .map(|(k, v)| (Value::Str(k), arg_to_value(v)))
                .collect(),
        ),
    }
}

pub fn print_help() {
    println!(
        "Usage: fail2ban-client [OPTIONS] <COMMAND>\n\n\
         Fail2Ban v{}\n\n\
         Options:\n  \
           -c, --conf <DIR>        set alternate config directory\n  \
           -s, --socket <FILE>     set alternate socket file\n  \
           -p, --pidfile <FILE>    set alternate pid file\n  \
           -d                      dump configuration. For debugging\n  \
           --dp, --dump-pretty     dump the configuration using more human readable representation\n  \
           -t, --test              test configuration\n  \
           -v                      increase verbosity\n  \
           -q                      decrease verbosity\n  \
           -V                      get version in machine-readable format\n  \
           --version               show version and exit\n  \
           -h, --help              display this help message and exit\n  \
           --str2sec <EXPR>        convert duration string to seconds",
        f2b_types::UPSTREAM_COMPAT_VERSION
    );
}
