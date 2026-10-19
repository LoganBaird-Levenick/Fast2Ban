//! Differential test of the `processLine` state machine against upstream:
//! find-time / in-operation handling, last-known-date fallback, DNS
//! expansion, check-all-regex and pending (id-less) multi-line failures.
//! Fixtures: `tools/gen_f2b_filter_fixtures.py` (real upstream `Filter`).

mod common;

use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use common::{build_filter, root};
use f2b_date::LocalZone;
use f2b_filter::{FailEntry, FailVal};
use f2b_types::{DnsUtils, FixedClock, Ipv6Policy, Resolver, SharedClock};
use serde_json::{Value, json};

#[derive(Debug)]
struct Table(HashMap<String, Vec<IpAddr>>);

impl Resolver for Table {
    fn lookup(&self, name: &str, ipv6: bool) -> io::Result<Vec<IpAddr>> {
        self.0
            .get(name)
            .map(|v| v.iter().copied().filter(|a| a.is_ipv6() == ipv6).collect())
            .ok_or_else(|| io::Error::other("nxdomain"))
    }
}

/// JSON numbers compared by value (Python renders `1.0` as `1.0` but its
/// int-valued epoch floats may be dumped as `1`).
fn norm(v: &Value) -> Value {
    match v {
        Value::Number(n) => json!(n.as_f64()),
        Value::Array(a) => Value::Array(a.iter().map(norm).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, v)| (k.clone(), norm(v))).collect()),
        other => other.clone(),
    }
}

/// `simple()` of the generator.
fn val_json(v: &FailVal) -> Value {
    match v {
        FailVal::None => Value::Null,
        FailVal::Str(s) => json!(s),
        FailVal::Int(i) => json!(i),
        FailVal::Tuple(t) => {
            json!({ "tuple": t.iter().map(|x| x.as_ref().map_or(Value::Null, |s| json!(s))).collect::<Vec<_>>() })
        }
        FailVal::Lines(l) => json!({
            "lines": l.iter().map(|t| format!("{}{}{}", t.pre, t.date, t.post)).collect::<Vec<_>>()
        }),
        FailVal::Set(s) => {
            let mut items: Vec<String> = s
                .iter()
                .map(|g| match g {
                    f2b_regex::GroupValue::Str(s) => s.clone(),
                    other => format!("{other:?}"),
                })
                .collect();
            items.sort();
            json!({ "set": items })
        }
        FailVal::Ip(ip) => json!({ "repr": ip.ntoa() }),
    }
}

fn entry_json(e: &FailEntry) -> Value {
    let fail: serde_json::Map<String, Value> = e
        .fail
        .iter()
        .map(|(k, v)| (k.clone(), val_json(v)))
        .collect();
    json!({
        "regex": e.regex_index,
        "fid": e.fid.as_ref().map(ToString::to_string),
        "date": e.date,
        "fail": fail,
    })
}

#[test]
fn process_line_matches_upstream_state_machine() {
    let up = root().join("fail2ban");
    if !up.join("config").is_dir() {
        eprintln!("upstream checkout missing; skipping");
        return;
    }
    let fx: Value = serde_json::from_str(
        &fs::read_to_string(root().join("testdata/f2b-filter/scenarios.json")).unwrap(),
    )
    .unwrap();
    let zone_text = fx["tz"].as_str().unwrap();
    let mut table = HashMap::new();
    for (name, ips) in fx["dns"].as_object().unwrap() {
        let v: Vec<IpAddr> = ips
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i.as_str().unwrap().parse().unwrap())
            .collect();
        table.insert(name.clone(), v);
    }

    let mut failures = Vec::new();
    let mut lines = 0usize;
    for case in fx["cases"].as_array().unwrap() {
        let scn = &case["scenario"];
        let name = scn["name"].as_str().unwrap();
        let now = scn
            .get("now")
            .and_then(Value::as_f64)
            .unwrap_or(fx["now"].as_f64().unwrap());
        let clock = Arc::new(FixedClock::new(now));
        let shared: SharedClock = clock.clone();
        let dns = Arc::new(DnsUtils::new(
            Box::new(Table(table.clone())),
            shared.clone(),
        ));
        dns.set_ipv6_policy(Ipv6Policy::Yes);
        let zone = LocalZone::posix(zone_text).unwrap();
        let opts = scn
            .get("filter_options")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let mut flt = match build_filter(
            "stock",
            scn["filter"].as_str().unwrap(),
            &opts,
            shared,
            zone,
            dns,
            scn["usedns"].as_str(),
        ) {
            Ok(f) => f,
            Err(e) => {
                failures.push(format!("{name}: build failed: {e}"));
                continue;
            }
        };
        flt.check_find_time = scn["check_find_time"].as_bool().unwrap();
        flt.in_operation = scn["in_operation"].as_bool().unwrap();
        flt.check_all_regex = scn
            .get("check_all")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        flt.return_raw_host = scn
            .get("raw_host")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        flt.ignore_pending = scn
            .get("ignore_pending")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        flt.set_find_time(scn["find_time"].as_f64().unwrap());

        let inputs = scn["lines"].as_array().unwrap();
        let expected = case["results"].as_array().unwrap();
        for (i, (input, want)) in inputs.iter().zip(expected).enumerate() {
            lines += 1;
            let line = input["line"].as_str().unwrap();
            let got = flt.process_line(line);
            let ok = match (&got, want.get("ok"), want.get("err")) {
                (Ok(entries), Some(rows), _) => {
                    let mut g: Vec<Value> = entries.iter().map(entry_json).collect();
                    g.sort_by_key(|r| (r["regex"].as_u64(), r["fid"].as_str().map(str::to_owned)));
                    norm(&Value::Array(g)) == norm(rows)
                }
                (Err(_), None, Some(_)) => true,
                _ => false,
            };
            if !ok {
                let g = match &got {
                    Ok(e) => Value::Array(e.iter().map(entry_json).collect()).to_string(),
                    Err(e) => format!("Err({e})"),
                };
                failures.push(format!(
                    "{name} #{i} {line:?}\n   got:  {g}\n   want: {want}"
                ));
            }
            if let Some(adv) = input.get("advance").and_then(Value::as_f64) {
                clock.set(f2b_types::Clock::time(clock.as_ref()) + adv);
            }
        }
    }
    assert!(lines >= 80, "expected all scenario lines, got {lines}");
    assert!(
        failures.is_empty(),
        "{} of {lines} lines differ from upstream; first:\n{}",
        failures.len(),
        failures
            .iter()
            .take(6)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
