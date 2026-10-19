//! Phase 2 gate: every upstream sample record (`testdata/samples`, extracted
//! from `fail2ban/tests/files/logs/*` by `tools/extract_samples.py`) must
//! produce the same result as upstream's `FilterSamplesRegex` test:
//! match / no match, failure id, captured groups, attempts, users and the
//! parsed timestamp, under upstream's pinned clock and time zone.
//!
//! Mirrors `fail2ban/tests/samplestestcase.py`.

mod common;

use std::collections::HashMap;
use std::fs;
use std::io;
use std::sync::Arc;

use common::{build_filter, opt_to_string, root};
use f2b_date::LocalZone;
use f2b_filter::{FailEntry, FailVal, Filter};
use f2b_regex::{GroupValue, TupleLine};
use f2b_types::{DnsUtils, Resolver, fixed_clock};
use serde_json::Value;

/// `datetime.utcfromtimestamp(TEST_NOW).isoformat()`
const TEST_NOW_STR: &str = "2005-08-14T10:00:00";

#[derive(Debug)]
struct NoDns;

impl Resolver for NoDns {
    fn lookup(&self, _: &str, _: bool) -> io::Result<Vec<std::net::IpAddr>> {
        Err(io::Error::other("samples never resolve"))
    }
}

/// Upstream's `_readFilter`: raw hosts, check all regexes, no find-time check.
fn build_sample_filter(
    label: &str,
    name: &str,
    opts: &Value,
    meta: &Value,
) -> Result<Filter, String> {
    let now = meta["now"].as_f64().unwrap();
    let zone = LocalZone::posix(meta["tz"].as_str().unwrap()).map_err(|e| e.to_string())?;
    let dns = Arc::new(DnsUtils::new(Box::new(NoDns), fixed_clock(now)));
    let mut flt = build_filter(label, name, opts, fixed_clock(now), zone, dns, None)?;
    flt.return_raw_host = true;
    flt.check_all_regex = true;
    flt.check_find_time = false;
    Ok(flt)
}

fn users_sorted(v: &FailVal) -> Vec<String> {
    let mut out: Vec<String> = match v {
        FailVal::Set(s) => s
            .iter()
            .map(|g| match g {
                GroupValue::Str(s) => s.clone(),
                other => format!("{other:?}"),
            })
            .collect(),
        _ => Vec::new(),
    };
    out.sort();
    out
}

/// Compares one expected key with the failure, like the assertions of the
/// upstream test. Returns an error text on mismatch.
fn check_key(k: &str, want: &Value, e: &FailEntry) -> Result<(), String> {
    let got = e.fail.get(k);
    let present = got.is_some_and(|v| !v.is_none());
    if !present {
        // fallbacks: host -> failure id, attempts -> number of matched lines
        if k == "host" {
            let fid = e.fid.as_ref().ok_or("no fid")?;
            return match fid.eq_str(want.as_str().unwrap_or_default()) {
                Ok(true) => Ok(()),
                other => Err(format!("host {fid} != {want} ({other:?})")),
            };
        }
        if k == "attempts" {
            let n = match e.fail.get("matches") {
                Some(FailVal::Lines(l)) => l.len() as i64,
                _ => 0,
            };
            return if want.as_i64() == Some(n) {
                Ok(())
            } else {
                Err(format!("attempts {n} != {want}"))
            };
        }
    }
    match (got, want) {
        // `assertEqual(fail.get(k), None)`: absent or None
        (g, Value::Null) if g.is_none_or(FailVal::is_none) => Ok(()),
        (Some(FailVal::Str(s)), Value::String(w)) if s == w => Ok(()),
        (Some(v @ FailVal::Set(_)), Value::Array(w)) => {
            let mut w: Vec<String> = w.iter().map(opt_to_string).collect();
            w.sort();
            if users_sorted(v) == w {
                Ok(())
            } else {
                Err(format!("{k}: {:?} != {w:?}", users_sorted(v)))
            }
        }
        (g, w) => Err(format!("{k}: got {g:?}, want {w}")),
    }
}

/// Number of positive matches and timestamps actually verified.
#[derive(Default)]
struct Verified {
    matches: usize,
    times: usize,
}

fn check_record(flt: &mut Filter, r: &Value, v: &mut Verified) -> Result<(), String> {
    let line = r["line"].as_str().unwrap();
    let logtype = r["logtype"].as_str();
    let res = if logtype == Some("journal") {
        let l = match r["prefix_line"].as_str() {
            Some(p) => format!("{p}{line}"),
            None => line.to_owned(),
        };
        flt.process_line_with_date(
            TupleLine::new(String::new(), TEST_NOW_STR.to_owned(), l),
            1_124_013_600.0,
        )
    } else {
        flt.process_line(line)
    };
    let ret = res.map_err(|e| format!("error: {e}"))?;
    // bypass pending and nofail
    let found: Vec<&FailEntry> = ret
        .iter()
        .filter(|e| e.fid.is_some() && !e.fail.truthy("nofail"))
        .collect();
    let expect = &r["expect"];
    let want_match = expect["match"].as_bool().unwrap_or(false);
    if found.is_empty() {
        return if want_match {
            Err("Line not matched when should have".into())
        } else {
            Ok(())
        };
    }
    if !want_match {
        return Err("Line matched when shouldn't have".into());
    }
    if found.len() != 1 {
        return Err(format!(
            "Multiple regexs matched {:?}",
            found.iter().map(|e| e.regex_index).collect::<Vec<_>>()
        ));
    }
    let e = found[0];
    v.matches += 1;
    for (k, want) in expect.as_object().unwrap() {
        if k == "match" {
            continue;
        }
        check_key(k, want, e)?;
    }
    if let Some(t) = r.get("expect_time").and_then(Value::as_f64) {
        match e.date {
            Some(d) if d == t => v.times += 1,
            other => return Err(format!("time mismatch: got {other:?}, want {t}")),
        }
    }
    Ok(())
}

#[test]
fn all_sample_records_match_upstream() {
    let up = root().join("fail2ban");
    if !up.join("config").is_dir() {
        eprintln!("upstream checkout missing; skipping");
        return;
    }
    let dir = root().join("testdata/samples");
    let meta: Value =
        serde_json::from_str(&fs::read_to_string(dir.join("meta.json")).unwrap()).unwrap();

    let mut failures: Vec<String> = Vec::new();
    let mut total = 0usize;
    let mut verified = Verified::default();
    let mut built_fail: HashMap<String, usize> = HashMap::new();
    for label in ["stock", "tests-config"] {
        let mut files: Vec<_> = fs::read_dir(dir.join(label))
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        files.sort();
        for f in files {
            let data: Value = serde_json::from_str(&fs::read_to_string(&f).unwrap()).unwrap();
            let name = data["filter"].as_str().unwrap().to_owned();
            let mut filters: HashMap<String, Result<Filter, String>> = HashMap::new();
            for r in data["records"].as_array().unwrap() {
                total += 1;
                let key = r["flt_key"].as_str().unwrap().to_owned();
                let entry = filters.entry(key.clone()).or_insert_with(|| {
                    build_sample_filter(label, &name, &r["filter_options"], &meta)
                });
                let id = format!(
                    "{label}/{key}: {}:{}",
                    r["file"].as_str().unwrap(),
                    r["lineno"]
                );
                match entry {
                    Err(e) => {
                        *built_fail.entry(key).or_default() += 1;
                        failures.push(format!("{id}: filter build failed: {e}"));
                    }
                    Ok(b) => {
                        if let Err(e) = check_record(b, r, &mut verified) {
                            failures.push(format!("{id}: {e}\n    line: {}", r["line"]));
                        }
                    }
                }
            }
        }
    }
    assert!(
        total >= 1841,
        "expected the full sample corpus, got {total}"
    );
    if !failures.is_empty() {
        let shown: Vec<_> = failures.iter().take(25).cloned().collect();
        panic!(
            "{} of {total} sample records differ from upstream (build failures: {built_fail:?}); first {}:\n{}",
            failures.len(),
            shown.len(),
            shown.join("\n")
        );
    }
}
