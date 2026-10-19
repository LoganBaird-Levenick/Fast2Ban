//! Differential fuzz of the INI layer against upstream's
//! `SafeConfigParserWithIncludes` (fixtures: `tools/gen_f2b_config_fuzz.py`).
//!
//! For thousands of random, deliberately odd files the parse result (defaults,
//! sections, option order, or the error class) and the interpolated value (or
//! exact error class and message) of every `get`/`get_ex` must equal upstream.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use f2b_config::RealFs;
use f2b_config::ini::{Ini, Section};
use serde_json::Value;

fn map_of(v: &Value) -> BTreeMap<String, String> {
    v.as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_owned()))
        .collect()
}

fn rust_map(s: &Section) -> BTreeMap<String, String> {
    s.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
}

#[test]
fn ini_layer_matches_upstream_on_random_files() {
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/f2b-config/ini_fuzz.json");
    let cases: Vec<Value> = serde_json::from_str(&fs::read_to_string(fixture).unwrap()).unwrap();
    let dir = std::env::temp_dir().join(format!("f2b-ini-fuzz-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("case.conf");
    let path_str = path.to_str().unwrap().to_owned();

    let mut failures: Vec<String> = Vec::new();
    for (n, case) in cases.iter().enumerate() {
        let text = case["text"].as_str().unwrap();
        fs::write(&path, text).unwrap();
        let exp = &case["expect"];
        let mut ini = Ini::new();
        let res = ini.read(&RealFs, std::slice::from_ref(&path_str));
        let mut fail = |msg: String| failures.push(format!("case {n} {text:?}\n   {msg}"));

        match (exp["error"].as_str(), &res) {
            (Some(class), Err(e)) => {
                if e.py_class() != class {
                    fail(format!("error class {} != upstream {class}", e.py_class()));
                }
                continue;
            }
            (Some(class), Ok(_)) => {
                fail(format!("upstream raised {class}, Rust parsed fine"));
                continue;
            }
            (None, Err(e)) => {
                fail(format!("Rust failed ({e}) where upstream parsed"));
                continue;
            }
            (None, Ok(_)) => {}
        }

        if rust_map(ini.defaults()) != map_of(&exp["defaults"]) {
            fail(format!(
                "defaults differ: {:?} vs {}",
                ini.defaults(),
                exp["defaults"]
            ));
            continue;
        }
        let exp_sections = exp["sections"].as_object().unwrap();
        let got_names: Vec<&str> = ini.sections().collect();
        let exp_names: Vec<&str> = exp["order"][0]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        if got_names != exp_names {
            fail(format!("section order {got_names:?} vs {exp_names:?}"));
            continue;
        }
        let mut bad = false;
        for (i, name) in exp_names.iter().enumerate() {
            let sec = ini.section(name).unwrap();
            if rust_map(sec) != map_of(&exp_sections[*name]) {
                fail(format!(
                    "section [{name}] differs: {sec:?} vs {}",
                    exp_sections[*name]
                ));
                bad = true;
                break;
            }
            let order: Vec<&str> = sec.keys().map(String::as_str).collect();
            let want: Vec<&str> = exp["order"][i + 1]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect();
            if order != want {
                fail(format!("option order in [{name}] {order:?} vs {want:?}"));
                bad = true;
                break;
            }
        }
        if bad {
            continue;
        }
        for (key, want) in exp["gets"].as_object().unwrap() {
            let (sec, opt) = key.split_once('\0').unwrap();
            let got = if opt == "nosuch" || opt.contains('/') {
                ini.get_ex(sec, opt, false, &Section::new())
            } else {
                ini.get(sec, opt, false, &Section::new())
            };
            let ok = match (&got, want.get("v"), want.get("e")) {
                (Ok(v), Some(w), _) => w.as_str() == Some(v.as_str()),
                (Err(e), _, Some(class)) => {
                    let msg = e.to_string().replace(&path_str, "@FILE@");
                    class.as_str() == Some(e.py_class()) && want["m"].as_str() == Some(msg.as_str())
                }
                _ => false,
            };
            if !ok {
                fail(format!(
                    "get([{sec}], {opt:?}): Rust {got:?} vs upstream {want}"
                ));
                break;
            }
        }
    }
    let _ = fs::remove_dir_all(&dir);
    assert!(
        failures.is_empty(),
        "{} of {} fuzz cases differ from upstream; first {}:\n{}",
        failures.len(),
        cases.len(),
        failures.len().min(8),
        failures
            .iter()
            .take(8)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
