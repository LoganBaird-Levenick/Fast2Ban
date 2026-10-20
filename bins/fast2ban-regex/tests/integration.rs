use std::path::{Path, PathBuf};
use std::process::Command;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn normalize(text: &str, root: &Path, bin_path: &str) -> String {
    let root_str = root.to_str().unwrap();
    let re = regex::Regex::new(r"\[processed in \d+\.\d+ sec\]").unwrap();
    let res = re.replace_all(text, "[processed in X.XX sec]");
    let res = res.replace(bin_path, "@ROOT@/fail2ban/bin/fail2ban-regex");
    let res = res.replace("fast2ban-regex", "fail2ban-regex");
    let res = res.replace(root_str, "@ROOT@");
    let re_trunc =
        regex::Regex::new(r"Use\s+single line : @ROOT@/fail2ban/tests[^\n]*\.\.\.").unwrap();
    re_trunc
        .replace_all(&res, "Use      single line : @ROOT@/fail2ban/tests/file...")
        .to_string()
}

#[test]
fn test_fast2ban_regex_oracle_fixtures() {
    let root_dir = root();
    let fixtures_path = root_dir.join("testdata/fast2ban-regex/fixtures.json");
    let content = std::fs::read_to_string(&fixtures_path).expect("failed to read fixtures.json");
    let fixtures: serde_json::Value =
        serde_json::from_str(&content).expect("invalid JSON fixtures");

    let bin_path = env!("CARGO_BIN_EXE_fast2ban-regex");

    for (i, fix) in fixtures.as_array().unwrap().iter().enumerate() {
        let args: Vec<String> = fix["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| {
                a.as_str()
                    .unwrap()
                    .replace("@ROOT@", root_dir.to_str().unwrap())
            })
            .collect();
        if args.iter().any(|a| a.contains("/fail2ban/"))
            && !root_dir.join("fail2ban/config").is_dir()
        {
            eprintln!("fail2ban/config missing; skipping case {i}");
            continue;
        }

        let output = Command::new(bin_path)
            .args(&args)
            .env("TZ", "UTC")
            .env("LC_ALL", "C.UTF-8")
            .output()
            .unwrap_or_else(|e| panic!("failed to execute fast2ban-regex for case {i}: {e}"));

        let code = output.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        let norm_stdout = normalize(&stdout, &root_dir, bin_path);
        let norm_stderr = normalize(&stderr, &root_dir, bin_path);

        let exp_code = fix["exit_code"].as_i64().unwrap() as i32;
        let exp_stdout = fix["stdout"].as_str().unwrap();
        let exp_stderr = fix["stderr"].as_str().unwrap();
        let norm_exp_stdout = normalize(exp_stdout, &root_dir, bin_path);
        let norm_exp_stderr = normalize(exp_stderr, &root_dir, bin_path);

        assert_eq!(
            code, exp_code,
            "Case {i} ({args:?}) exit code mismatch:\nGot: {code}\nExpected: {exp_code}\nStderr:\n{norm_stderr}"
        );

        assert_eq!(
            norm_stdout, norm_exp_stdout,
            "Case {i} ({args:?}) stdout mismatch:\n--- GOT ---\n{norm_stdout}\n--- EXPECTED ---\n{norm_exp_stdout}"
        );

        assert_eq!(
            norm_stderr, norm_exp_stderr,
            "Case {i} ({args:?}) stderr mismatch:\n--- GOT ---\n{norm_stderr}\n--- EXPECTED ---\n{norm_exp_stderr}"
        );
    }
}
