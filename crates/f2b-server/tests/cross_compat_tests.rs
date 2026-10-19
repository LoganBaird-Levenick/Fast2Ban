use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tempfile::tempdir;

use f2b_server::{AsyncServer, Server};
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn prepare_test_config(dir: &Path) {
    let _ = fs::create_dir_all(dir);
    let root_dir = root();
    let src_cfg = root_dir.join("fail2ban/config");
    for entry in fs::read_dir(src_cfg).unwrap() {
        let entry = entry.unwrap();
        let dest = dir.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            let _ = fs::create_dir_all(&dest);
            for sub in fs::read_dir(entry.path()).unwrap() {
                let sub = sub.unwrap();
                let _ = fs::copy(sub.path(), dest.join(sub.file_name()));
            }
        } else {
            let _ = fs::copy(entry.path(), dest);
        }
    }
    fs::write(
        dir.join("fail2ban.local"),
        "[Definition]\nlogtarget = STDERR\ndbfile = None\n",
    )
    .unwrap();
}

#[test]
fn test_python_client_to_rust_server_matrix() {
    let tmp = tempdir().unwrap();
    let sock_path = tmp.path().join("f2b_rust_server.sock");
    let cfg_dir = tmp.path().join("config");
    prepare_test_config(&cfg_dir);

    let server = Arc::new(Mutex::new(Server::new()));
    let async_server = AsyncServer::bind(&sock_path, server.clone()).expect("bind server");
    let handle = async_server.start_background().expect("start server");

    thread::sleep(Duration::from_millis(50));

    let root_dir = root();
    let client_bin = root_dir.join("fail2ban/bin/fail2ban-client");
    let sock_str = sock_path.to_str().unwrap();
    let cfg_str = cfg_dir.to_str().unwrap();

    let run_py_client = |args: &[&str]| -> (bool, String, String) {
        let mut cmd = Command::new("python3");
        cmd.env("PYTHONPATH", root_dir.join("fail2ban"));
        cmd.arg(&client_bin);
        cmd.arg("-c").arg(cfg_str);
        cmd.arg("-s").arg(sock_str);
        cmd.args(args);

        let out = cmd.output().expect("failed to execute fail2ban-client");
        let stdout = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_owned();
        (out.status.success(), stdout, stderr)
    };

    // 1. ping
    let (ok, out, _) = run_py_client(&["ping"]);
    assert!(ok);
    assert_eq!(out, "Server replied: pong");

    // 2. version
    let (ok, out, _) = run_py_client(&["version"]);
    assert!(ok);
    assert_eq!(out, f2b_types::UPSTREAM_COMPAT_VERSION);

    // 3. echo
    let (ok, out, _) = run_py_client(&["echo", "cross", "compat", "test"]);
    assert!(ok);
    assert_eq!(out, "cross compat test");

    // 4. set & get loglevel
    let (ok, out, _) = run_py_client(&["set", "loglevel", "DEBUG"]);
    assert!(ok);
    assert!(out.contains("DEBUG"));
    let (ok, out, _) = run_py_client(&["get", "loglevel"]);
    assert!(ok);
    assert!(out.contains("DEBUG"));

    // 5. add jail
    let (ok, out, _) = run_py_client(&["add", "sshd", "polling"]);
    assert!(ok);
    assert_eq!(out, "Added jail sshd");

    // 6. set & get jail maxretry
    let (ok, out, _) = run_py_client(&["set", "sshd", "maxretry", "5"]);
    assert!(ok);
    assert_eq!(out, "5");

    let (ok, out, _) = run_py_client(&["get", "sshd", "maxretry"]);
    assert!(ok);
    assert_eq!(out, "5");

    // 7. status overall
    let (ok, out, _) = run_py_client(&["status"]);
    assert!(ok);
    assert!(out.contains("Number of jail:\t1"));
    assert!(out.contains("Jail list:\tsshd"));

    // 8. status jail
    let (ok, out, _) = run_py_client(&["status", "sshd"]);
    assert!(ok);
    assert!(out.contains("Status for the jail: sshd"));
    assert!(out.contains("Currently failed:\t0"));
    assert!(out.contains("Currently banned:\t0"));

    // 9. stop jail
    let (ok, out, _) = run_py_client(&["stop", "sshd"]);
    assert!(ok);
    assert_eq!(out, "Jail stopped");

    // 10. shutdown server
    let (ok, out, _) = run_py_client(&["stop"]);
    assert!(ok);
    assert_eq!(out, "Shutdown successful");

    let _ = handle.join();
}

#[test]
fn test_rust_client_to_python_server_matrix() {
    let tmp = tempdir().unwrap();
    let sock_path = tmp.path().join("f2b_py_server.sock");
    let pid_path = tmp.path().join("f2b_py_server.pid");
    let cfg_dir = tmp.path().join("config");
    prepare_test_config(&cfg_dir);

    let root_dir = root();
    let server_bin = root_dir.join("fail2ban/bin/fail2ban-server");

    let mut py_server_child = Command::new("python3")
        .env("PYTHONPATH", root_dir.join("fail2ban"))
        .arg(&server_bin)
        .arg("-f")
        .arg("-c")
        .arg(&cfg_dir)
        .arg("-s")
        .arg(&sock_path)
        .arg("-p")
        .arg(&pid_path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn python server");

    // Wait until socket file exists
    let start = std::time::Instant::now();
    while !sock_path.exists() {
        if start.elapsed() > Duration::from_secs(5) {
            let output = py_server_child.wait_with_output();
            panic!("timed out waiting for python server socket: {output:?}");
        }
        thread::sleep(Duration::from_millis(50));
    }

    // Small delay to let python server finish initialization
    thread::sleep(Duration::from_millis(100));

    // Now test Rust fast2ban-client communicating with Python server
    let mut csock = fast2ban_client::ClientSocket::new(&sock_path);

    // 1. ping
    let res = csock.send(&[f2b_proto::Value::Str("ping".into())]).unwrap();
    assert_eq!(res, f2b_proto::Value::Str("pong".into()));

    // 2. version
    let res = csock
        .send(&[f2b_proto::Value::Str("version".into())])
        .unwrap();
    assert_eq!(res, f2b_proto::Value::Str("1.1.2.dev1".into()));

    // 3. echo
    let res = csock
        .send(&[
            f2b_proto::Value::Str("echo".into()),
            f2b_proto::Value::Str("rust".into()),
            f2b_proto::Value::Str("to".into()),
            f2b_proto::Value::Str("python".into()),
        ])
        .unwrap();
    assert_eq!(
        res,
        f2b_proto::Value::List(vec![
            f2b_proto::Value::Str("rust".into()),
            f2b_proto::Value::Str("to".into()),
            f2b_proto::Value::Str("python".into()),
        ])
    );

    // 4. status
    let res = csock
        .send(&[f2b_proto::Value::Str("status".into())])
        .unwrap();
    let text = f2b_proto::Beautifier::beautify(&["status".into()], &res);
    assert!(text.contains("Number of jail:\t0"));

    // 5. shutdown python server
    let res = csock.send(&[f2b_proto::Value::Str("stop".into())]).unwrap();
    assert_eq!(res, f2b_proto::Value::None);

    let _ = py_server_child.wait();
}
