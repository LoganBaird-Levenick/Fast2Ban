use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use f2b_server::{AsyncServer, Server};

struct ServerArgs {
    conf_dir: String,
    socket_path: PathBuf,
    pid_file: PathBuf,
    foreground: bool,
}

impl Default for ServerArgs {
    fn default() -> Self {
        Self {
            conf_dir: "/etc/fail2ban".to_owned(),
            socket_path: PathBuf::from("/var/run/fail2ban/fail2ban.sock"),
            pid_file: PathBuf::from("/var/run/fail2ban/fail2ban.pid"),
            foreground: true,
        }
    }
}

fn parse_args() -> ServerArgs {
    let mut args = ServerArgs::default();
    let env_args: Vec<String> = std::env::args().collect();
    let mut i = 1;

    while i < env_args.len() {
        let arg = &env_args[i];
        match arg.as_str() {
            "-h" | "--help" => {
                println!(
                    "Usage: fail2ban-server [OPTIONS]\n\n\
                     Fail2Ban v{}\n\n\
                     Options:\n  \
                       -c, --conf <DIR>        set alternate config directory\n  \
                       -s, --socket <FILE>     set alternate socket file\n  \
                       -p, --pidfile <FILE>    set alternate pid file\n  \
                       -b                      start in background (fork)\n  \
                       -f                      start in foreground\n  \
                       -h, --help              display this help message and exit",
                    f2b_types::UPSTREAM_COMPAT_VERSION
                );
                std::process::exit(0);
            }
            "--version" | "-V" => {
                println!("Fail2Ban v{}", f2b_types::UPSTREAM_COMPAT_VERSION);
                std::process::exit(0);
            }
            "-c" | "--conf" => {
                i += 1;
                if i < env_args.len() {
                    args.conf_dir = env_args[i].clone();
                }
            }
            "-s" | "--socket" => {
                i += 1;
                if i < env_args.len() {
                    args.socket_path = PathBuf::from(&env_args[i]);
                }
            }
            "-p" | "--pidfile" => {
                i += 1;
                if i < env_args.len() {
                    args.pid_file = PathBuf::from(&env_args[i]);
                }
            }
            "-f" => args.foreground = true,
            "-b" => args.foreground = false,
            _ => {}
        }
        i += 1;
    }

    args
}

fn main() {
    let args = parse_args();

    // Ensure parent directories exist
    if let Some(parent) = args.socket_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Some(parent) = args.pid_file.parent() {
        let _ = fs::create_dir_all(parent);
    }

    // Write PID file
    let pid = std::process::id();
    if let Err(e) = fs::write(&args.pid_file, format!("{pid}\n")) {
        eprintln!("Warning: failed to write PID file {:?}: {e}", args.pid_file);
    }

    let server = Arc::new(Mutex::new(Server::new()));

    let async_server = match AsyncServer::bind(&args.socket_path, server.clone()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "Fatal error: failed to bind socket at {:?}: {e}",
                args.socket_path
            );
            let _ = fs::remove_file(&args.pid_file);
            std::process::exit(255);
        }
    };

    println!("Server ready, listening on {:?}", args.socket_path);

    let handle = match async_server.start_background() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Failed to start server thread: {e}");
            let _ = fs::remove_file(&args.pid_file);
            std::process::exit(255);
        }
    };

    // Serve until stopped
    loop {
        {
            let s = server.lock().unwrap();
            if !s.running {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    async_server.stop();
    let _ = handle.join();
    let _ = fs::remove_file(&args.pid_file);
    println!("Server shut down gracefully");
}
