//! Golden-diff of the Rust config layer against upstream `fail2ban-client -d`
//! (fixtures from `tools/dump_oracle.py`, see PLAN.md Phase 1 gate).
//!
//! Every case recreates the oracle's input (config tree copy + generated
//! `jail.local`) and must reproduce the recorded command stream, exit status
//! and failure message exactly.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use f2b_config::{Arg, Fs, RealFs, read_config};
use indexmap::IndexMap;
use serde_json::{Value, json};

/// Real files below the config dir; elsewhere only `/dev/null` exists (the
/// only log path that existed in the oracle environment).
#[derive(Debug)]
struct OracleFs {
    conf_prefix: String,
}

impl OracleFs {
    fn inside(&self, p: &str) -> bool {
        p.starts_with(&self.conf_prefix)
    }
}

impl Fs for OracleFs {
    fn read_to_string(&self, path: &str) -> io::Result<String> {
        RealFs.read_to_string(path)
    }
    fn exists(&self, path: &str) -> bool {
        if self.inside(path) {
            RealFs.exists(path)
        } else {
            path == "/dev/null"
        }
    }
    fn is_file(&self, path: &str) -> bool {
        self.inside(path) && RealFs.is_file(path)
    }
    fn glob(&self, pattern: &str) -> Vec<String> {
        if self.inside(pattern) {
            RealFs.glob(pattern)
        } else if pattern == "/dev/null" {
            vec![pattern.to_owned()]
        } else {
            Vec::new()
        }
    }
}

fn to_json(a: &Arg) -> Value {
    match a {
        Arg::None => Value::Null,
        Arg::Str(s) => json!(s),
        Arg::Int(i) => json!(i),
        Arg::Bool(b) => json!(b),
        Arg::List(l) => Value::Array(l.iter().map(to_json).collect()),
        Arg::Map(m) => Value::Object(m.iter().map(|(k, v)| (k.clone(), to_json(v))).collect()),
    }
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for e in fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let dest = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &dest);
        } else {
            fs::copy(e.path(), dest).unwrap();
        }
    }
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn collect_cases(dir: &Path, prefix: &str, out: &mut Vec<String>) {
    let mut entries: Vec<_> = fs::read_dir(dir).unwrap().map(|e| e.unwrap()).collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let name = e.file_name().into_string().unwrap();
        if e.file_type().unwrap().is_dir() {
            collect_cases(&e.path(), &format!("{prefix}{name}/"), out);
        } else if let Some(stem) = name.strip_suffix(".json") {
            out.push(format!("{prefix}{stem}"));
        }
    }
}

fn run_tree(label: &str, tree: &Path, failures: &mut Vec<String>) -> usize {
    let oracle_dir = repo_root().join("testdata/config-oracle").join(label);
    assert!(tree.is_dir(), "config tree missing: {}", tree.display());
    let work = std::env::temp_dir().join(format!("f2b-golden-{}-{label}", std::process::id()));
    let _ = fs::remove_dir_all(&work);
    copy_dir(tree, &work);
    let conf = work.to_str().unwrap().to_owned();
    let fs: Rc<dyn Fs> = Rc::new(OracleFs {
        conf_prefix: conf.clone(),
    });

    let mut cases = Vec::new();
    collect_cases(&oracle_dir, "", &mut cases);
    for case in &cases {
        let expected: Value = serde_json::from_str(
            &fs::read_to_string(oracle_dir.join(format!("{case}.json"))).unwrap(),
        )
        .unwrap();
        // apply the case's overlay files (CRLF and BOM kept byte-exact)
        let mut written = Vec::new();
        for (rel, text) in expected["files"].as_object().unwrap() {
            let dest = work.join(rel);
            fs::create_dir_all(dest.parent().unwrap()).unwrap();
            let text = text
                .as_str()
                .unwrap()
                .replace("ABS_INCLUDE", &format!("{conf}/inc-abs.conf"));
            fs::write(&dest, text).unwrap();
            written.push(dest);
        }

        let res = read_config(fs.clone(), &conf, None, &IndexMap::new(), true, true);
        let scrub = |s: String| s.replace(&conf, "@CONF@");

        let rc = if res.ret { 0 } else { 255 };
        let got_cmds: Value = match &res.stream {
            Some(s) => {
                let v = Value::Array(
                    s.iter()
                        .map(|c| Value::Array(c.iter().map(to_json).collect()))
                        .collect(),
                );
                serde_json::from_str(&scrub(v.to_string())).unwrap()
            }
            None => json!([]),
        };

        for f in written {
            let _ = fs::remove_file(f);
        }
        let id = format!("{label}/{case}");
        if expected["rc"] != json!(rc) {
            failures.push(format!("{id}: rc {} != expected {}", rc, expected["rc"]));
        }
        if expected["commands"] != got_cmds {
            failures.push(format!(
                "{id}: command stream differs\n{}",
                first_diff(&expected["commands"], &got_cmds)
            ));
        }
        match (&res.error, &res.stream) {
            (Some(e), None) if res.init_failed => {
                let msg = scrub(format!("ERROR: {e}"));
                if expected["other"] != json!([msg]) {
                    failures.push(format!(
                        "{id}: init failure output {} != {msg:?}",
                        expected["other"]
                    ));
                }
            }
            (Some(e), None) => {
                let msg = scrub(format!("Failed during configuration: {e}"));
                let stderr = expected["stderr"].as_str().unwrap_or_default();
                if !stderr.contains(&msg) {
                    failures.push(format!("{id}: error message not found in oracle stderr\n  got: {msg}\n  stderr: {stderr}"));
                }
                if expected["other"]
                    != json!([
                        "ERROR: The configuration stream failed because of the invalid syntax."
                    ])
                {
                    failures.push(format!("{id}: expected failure output missing"));
                }
            }
            (None, Some(_)) => {
                if expected["other"] != json!([]) {
                    failures.push(format!(
                        "{id}: unexpected oracle output {}",
                        expected["other"]
                    ));
                }
            }
            _ => failures.push(format!("{id}: inconsistent result")),
        }
    }
    let _ = fs::remove_dir_all(&work);
    cases.len()
}

fn first_diff(want: &Value, got: &Value) -> String {
    let (w, g) = (want.as_array().unwrap(), got.as_array().unwrap());
    for i in 0..w.len().max(g.len()) {
        if w.get(i) != g.get(i) {
            let cut = |v: Option<&Value>| {
                let s = v.map_or("<missing>".to_owned(), Value::to_string);
                s.chars().take(300).collect::<String>()
            };
            return format!(
                "  first difference at command #{i} (want {} cmds, got {}):\n    want: {}\n    got:  {}",
                w.len(),
                g.len(),
                cut(w.get(i)),
                cut(g.get(i))
            );
        }
    }
    "  (identical)".to_owned()
}

#[test]
fn matches_upstream_command_stream_for_all_oracle_cases() {
    let up = repo_root().join("fail2ban");
    if !up.join("config").is_dir() {
        eprintln!("upstream checkout missing; skipping golden test");
        return;
    }
    let mut failures = Vec::new();
    let mut total = 0;
    total += run_tree("stock", &up.join("config"), &mut failures);
    total += run_tree(
        "tests-config",
        &up.join("fail2ban/tests/config"),
        &mut failures,
    );
    assert!(total >= 490, "expected the full oracle corpus, ran {total}");
    if !failures.is_empty() {
        let shown: Vec<_> = failures.iter().take(15).cloned().collect();
        panic!(
            "{} of {total} cases differ from upstream (showing {}):\n{}",
            failures.len(),
            shown.len(),
            shown.join("\n")
        );
    }
}
