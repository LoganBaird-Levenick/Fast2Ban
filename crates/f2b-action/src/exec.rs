//! Shell command execution with timeout and process-group cleanup (`libc::setsid`).

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecResult {
    pub success: bool,
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Formats a shell command script with positional arguments, avoiding shell injection.
///
/// Upstream `Utils.buildShellCmd`:
/// `varsStat = "k=$0 k2=$1 ... \n" + script`
/// passed to `sh -c script val0 val1 ...`
pub fn build_shell_cmd(cmd: &str, vars: &[(String, String)]) -> (String, Vec<String>) {
    if vars.is_empty() {
        return (cmd.to_owned(), Vec::new());
    }

    let mut script = String::new();
    let mut args = Vec::with_capacity(vars.len());

    for (i, (k, v)) in vars.iter().enumerate() {
        script.push_str(&format!("{k}=${i} "));
        args.push(v.clone());
    }
    script.push('\n');
    script.push_str(cmd);

    (script, args)
}

/// Executes a shell command under `/bin/sh -c` with a timeout and process group termination.
pub fn execute_cmd(
    cmd: &str,
    timeout: Duration,
    vars: &[(String, String)],
) -> Result<ExecResult, String> {
    let (script, args) = build_shell_cmd(cmd, vars);

    let mut command = Command::new("sh");
    command.arg("-c").arg(&script);
    command.args(&args);
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            command.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }

    let mut child = command
        .spawn()
        .map_err(|e| format!("failed to spawn command '{cmd}': {e}"))?;

    let pid = child.id();
    let start = Instant::now();
    let mut timed_out = false;

    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if start.elapsed() >= timeout {
                    timed_out = true;
                    break std::process::ExitStatus::default();
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => return Err(format!("error waiting for command '{cmd}': {e}")),
        }
    };

    if timed_out {
        #[cfg(unix)]
        unsafe {
            let pgid = pid as i32;
            libc::killpg(pgid, libc::SIGTERM);
            std::thread::sleep(Duration::from_millis(50));
            libc::killpg(pgid, libc::SIGKILL);
        }
        #[cfg(not(unix))]
        {
            let _ = child.kill();
        }

        let _ = child.wait();
        return Err(format!("command '{cmd}' timed out after {timeout:?}"));
    }

    let mut stdout = String::new();
    let mut stderr = String::new();
    if let Some(mut out) = child.stdout.take() {
        let _ = out.read_to_string(&mut stdout);
    }
    if let Some(mut err) = child.stderr.take() {
        let _ = err.read_to_string(&mut stderr);
    }

    let code = status.code().unwrap_or(-1);
    Ok(ExecResult {
        success: status.success(),
        status: code,
        stdout,
        stderr,
    })
}
