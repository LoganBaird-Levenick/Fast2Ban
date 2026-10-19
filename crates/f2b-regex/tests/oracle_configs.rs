//! Construction oracle: the 679 regexes of the 146 stock/test filter
//! configurations, built from their *unexpanded* config text.

mod common;

use common::{build_config, check_info, fixture};
use f2b_regex::EngineKind;
use serde_json::Value;

#[test]
fn stock_and_test_filter_regexes_expand_like_upstream() {
    let configs = fixture("configs.json");
    let expanded = serde_json::from_str::<Value>(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/expanded-regex.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let (mut n_linear, mut n_backtracking, mut n_total) = (0, 0, 0);
    for entry in configs.as_array().unwrap() {
        let id = entry["id"].as_str().unwrap();
        let usedns = entry["usedns"].as_str().unwrap();
        let cfg = build_config(entry, None).unwrap_or_else(|e| panic!("{id} ({usedns}): {e}"));
        // full text comparison against the shipped expanded dump (usedns=warn)
        let exp_full = (usedns == "warn").then(|| &expanded[id]);
        let mut checked = 0;
        if let Some(p) = &cfg.pref {
            let want = exp_full.and_then(|e| e["prefregex"].as_str());
            check_info(&format!("{id} pref"), p, &entry["pref"], want);
            checked += 1;
        }
        for (i, f) in cfg.fails.iter().enumerate() {
            let want = exp_full.and_then(|e| e["failregex"][i].as_str());
            check_info(&format!("{id} f{i} ({usedns})"), f, &entry["fail"][i], want);
            checked += 1;
        }
        for (i, r) in cfg.ignores.iter().enumerate() {
            let want = exp_full.and_then(|e| e["ignoreregex"][i].as_str());
            check_info(
                &format!("{id} i{i} ({usedns})"),
                r,
                &entry["ignore"][i],
                want,
            );
            checked += 1;
        }
        assert_eq!(entry["fail"].as_array().unwrap().len(), cfg.fails.len());
        if usedns == "warn" {
            n_total += checked;
            for k in cfg.engines() {
                match k {
                    EngineKind::Linear => n_linear += 1,
                    EngineKind::Backtracking => n_backtracking += 1,
                }
            }
        }
    }
    eprintln!(
        "regexes: {n_total} total, {n_linear} on the linear engine, {n_backtracking} on fancy-regex"
    );
    assert_eq!(n_total, 679);
}
