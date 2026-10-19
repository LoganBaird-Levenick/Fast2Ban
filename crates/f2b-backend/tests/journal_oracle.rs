//! Golden tests against upstream `FilterSystemd` (fixtures from `tools/dump_journal_oracle.py`):
//! journalmatch bookkeeping, export parsing + python-systemd converters, `formatJournalEntry`
//! and `_getJournalArgs`.

use std::fs;
use std::io::Cursor;
use std::path::Path;

use f2b_backend::journal::{
    JournalEntry, JournalMatches, JournalOptions, JournalValue, SystemdPaths, TimestampStyle,
    format_journal_entry, format_journal_entry_with, parse_export, parse_flags,
};
use f2b_date::LocalZone;
use f2b_helpers::{as_bool, splitwords};
use serde_json::{Map, Value, json};

fn fixture(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e} (run tools/dump_journal_oracle.py)", path.display()));
    serde_json::from_str(&text).unwrap()
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn str_list(v: &Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_owned())
        .collect()
}

// --- matches -------------------------------------------------------------------------------

#[test]
fn journal_matches_follow_upstream() {
    let scenarios = fixture("journal_matches.json");
    let scenarios = scenarios.as_array().unwrap();
    assert!(scenarios.len() > 100);
    let mut steps = 0;
    for sc in scenarios {
        let id = sc["id"].as_str().unwrap();
        let mut matches = JournalMatches::new();
        let ops = sc["ops"].as_array().unwrap();
        let results = sc["results"].as_array().unwrap();
        for (i, (op, expect)) in ops.iter().zip(results).enumerate() {
            let kind = op[0].as_str().unwrap();
            let ctx = format!("{id} step {i} ({op})");
            let outcome = match kind {
                "add" => matches.add(&str_list(&op[1])),
                "del" => {
                    if op[1].is_null() {
                        matches.del::<String>(None)
                    } else {
                        matches.del(Some(str_list(&op[1]).as_slice()))
                    }
                }
                _ => Ok(()),
            };
            match (&outcome, expect.get("err")) {
                (Ok(()), None) => {}
                (Err(e), Some(msg)) => assert_eq!(e.to_string(), msg.as_str().unwrap(), "{ctx}"),
                (o, e) => panic!("{ctx}: rust {o:?} vs upstream {e:?}"),
            }
            let state: Vec<Vec<String>> = expect["state"]
                .as_array()
                .unwrap()
                .iter()
                .map(str_list)
                .collect();
            assert_eq!(matches.get(), state.as_slice(), "{ctx}: state");
            // journalctl expression == what upstream's reader holds: non-empty groups, `+`-joined
            let mut expr: Vec<String> = Vec::new();
            for g in expect["reader"].as_array().unwrap() {
                if !expr.is_empty() {
                    expr.push("+".into());
                }
                expr.extend(str_list(g));
            }
            assert_eq!(matches.to_journalctl_args(), expr, "{ctx}: journalctl args");
            steps += 1;
        }
    }
    assert!(steps > 800, "{steps}");
}

#[test]
fn journal_matches_text_helpers() {
    let mut m = JournalMatches::new();
    m.add(&["_SYSTEMD_UNIT=sshd.service", "_COMM=sshd", "+", "A=b"])
        .unwrap();
    assert_eq!(
        m.status_text(),
        "_SYSTEMD_UNIT=sshd.service _COMM=sshd + A=b"
    );
    assert_eq!(f2b_backend::journal::join_match(&["a=b", "c=d"]), "a=b c=d");
    assert!(!m.is_empty());
    m.del::<&str>(None).unwrap();
    assert!(m.is_empty());
    assert_eq!(m.status_text(), "");
}

// --- entries -------------------------------------------------------------------------------

fn dump_value(v: &JournalValue) -> Value {
    match v {
        JournalValue::Text(s) => json!({ "t": s }),
        JournalValue::Bytes(b) => json!({ "b": hex_encode(b) }),
        JournalValue::Int(i) => json!({ "i": i.to_string() }),
        JournalValue::BigInt(s) => json!({ "i": s }),
        JournalValue::Uuid(u) => json!({ "u": format!("{u:032x}") }),
        JournalValue::Timestamp(us) => json!({ "dt": us }),
        JournalValue::Duration(us) => json!({ "td": us }),
        JournalValue::Monotonic { micros, boot_id } => {
            json!({ "mono": [micros, format!("{:032x}", boot_id.expect("boot id"))] })
        }
        JournalValue::List(l) => json!({ "l": l.iter().map(dump_value).collect::<Vec<_>>() }),
    }
}

fn dump_entry(e: &JournalEntry) -> Value {
    let mut m = Map::new();
    for (k, v) in e.iter() {
        m.insert(k.to_owned(), dump_value(v));
    }
    Value::Object(m)
}

fn parse_one(hex: &str) -> JournalEntry {
    let bytes = hex_decode(hex);
    let mut it = parse_export(Cursor::new(bytes));
    let e = it.next().expect("one entry").expect("parses");
    assert!(it.next().is_none(), "exactly one entry");
    e
}

#[test]
fn export_parsing_and_converters_match_python_systemd() {
    let fx = fixture("journal_entries.json");
    let entries = fx["entries"].as_array().unwrap();
    assert!(entries.len() > 250);
    for e in entries {
        let id = e["id"].as_str().unwrap();
        let got = dump_entry(&parse_one(e["export_hex"].as_str().unwrap()));
        assert_eq!(got, e["typed"], "{id}");
    }
}

fn zone_for(tz: &str) -> LocalZone {
    LocalZone::named(tz).unwrap_or_else(|e| panic!("{e}"))
}

#[test]
fn format_journal_entry_matches_upstream() {
    let fx = fixture("journal_entries.json");
    let entries = fx["entries"].as_array().unwrap();
    let styles = fx["styles"].as_array().unwrap();
    let encs = fx["encs"].as_array().unwrap();
    let formats = fx["formats"].as_array().unwrap();
    assert!(formats.len() > 2500);
    let parsed: Vec<JournalEntry> = entries
        .iter()
        .map(|e| parse_one(e["export_hex"].as_str().unwrap()))
        .collect();
    let (mut ok, mut err) = (0, 0);
    for f in formats {
        let (ei, si, ci) = (
            f[0].as_u64().unwrap() as usize,
            f[1].as_u64().unwrap() as usize,
            f[2].as_u64().unwrap() as usize,
        );
        let enc = encs[ci].as_str().unwrap();
        let style = &styles[si];
        let ctx = format!("{} {style} {enc}", entries[ei]["id"]);
        let entry = &parsed[ei];
        let got = match style["kind"].as_str().unwrap() {
            "naive" => {
                let zone = zone_for(style["tz"].as_str().unwrap());
                // the plain entry point is the naive-local style
                let a = format_journal_entry(entry, enc, &zone);
                let b = format_journal_entry_with(entry, enc, TimestampStyle::NaiveLocal(&zone));
                assert_eq!(a, b, "{ctx}");
                a
            }
            "fixed" => {
                let off = style["offset"].as_i64().unwrap() as i32;
                format_journal_entry_with(entry, enc, TimestampStyle::FixedOffset(off))
            }
            k => panic!("{k}"),
        };
        let expect = &f[3];
        if let Some(exp) = expect.get("ok") {
            let got = got.unwrap_or_else(|e| panic!("{ctx}: {e}"));
            assert_eq!(got.pre, exp["pre"].as_str().unwrap(), "{ctx}: pre");
            assert_eq!(got.date, exp["date"].as_str().unwrap(), "{ctx}: date");
            assert_eq!(got.post, exp["post"].as_str().unwrap(), "{ctx}: post");
            assert_eq!(
                got.time.to_bits(),
                exp["time_bits"].as_u64().unwrap(),
                "{ctx}: time {} vs {}",
                got.time,
                exp["time"]
            );
            ok += 1;
        } else {
            assert!(got.is_err(), "{ctx}: upstream raises {}", expect["err"]);
            err += 1;
        }
    }
    assert!(ok > 2500 && err > 5, "{ok} {err}");
}

#[test]
fn unsupported_encoding_is_an_error() {
    let fx = fixture("journal_entries.json");
    let e = parse_one(fx["entries"][0]["export_hex"].as_str().unwrap());
    assert!(format_journal_entry(&e, "shift_jis", &LocalZone::utc()).is_err());
    // `auto` is the locale encoding, taken as UTF-8
    assert!(format_journal_entry(&e, "auto", &LocalZone::utc()).is_ok());
}

// --- _getJournalArgs -----------------------------------------------------------------------

#[test]
fn journal_args_match_upstream() {
    let fx = fixture("journal_args.json");
    let uid = f2b_backend::journal::effective_uid().to_string();
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_str().unwrap().to_owned();
    for rel in fx["tree"].as_array().unwrap() {
        let rel = rel
            .as_str()
            .unwrap()
            .replace("user-@UID@", &format!("user-{uid}"));
        // the generator's own uid was substituted already; fixtures hold "user-@UID@" only for it
        let p = tmp.path().join(&rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, "").unwrap();
    }
    let paths = SystemdPaths {
        system_state_logs: root.clone(),
        system_runtime_logs: format!("{root}/run"),
    };
    let sub = |s: &str| s.replace("@T@", &root);
    let unsub = |s: &str| {
        s.replace(&root, "@T@")
            .replace(&format!("user-{uid}."), "user-@UID@.")
            .replace(&format!("user-{uid}@"), "user-@UID@@")
    };
    let mut checked = 0;
    for case in fx["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        let kw = case["kwargs"].as_object().unwrap();
        let mut opts = JournalOptions::default();
        let mut parse_err = false;
        for (k, v) in kw {
            match k.as_str() {
                "journalpath" => opts.journalpath = Some(sub(v.as_str().unwrap())),
                "journalfiles" => {
                    opts.journalfiles = Some(match v {
                        Value::String(s) => splitwords(&sub(s), false),
                        Value::Array(a) => a.iter().map(|s| sub(s.as_str().unwrap())).collect(),
                        _ => panic!(),
                    });
                }
                "journalflags" => {
                    let r = match v {
                        Value::String(s) => parse_flags(s),
                        Value::Number(n) => Ok(n.as_i64().unwrap()),
                        _ => panic!(),
                    };
                    match r {
                        Ok(f) => opts.journalflags = Some(f),
                        Err(_) => parse_err = true,
                    }
                }
                "namespace" => opts.namespace = Some(v.as_str().unwrap().to_owned()),
                "rotated" => {
                    opts.rotated = match v {
                        Value::String(s) => as_bool(s),
                        Value::Number(n) => n.as_i64().unwrap() != 0,
                        _ => panic!(),
                    };
                }
                k => panic!("{k}"),
            }
        }
        let env = case["env_default_flags"].as_str();
        let resolved = if parse_err {
            None
        } else {
            opts.resolve_with(env, &paths).ok()
        };
        match case.get("ok") {
            None => assert!(resolved.is_none(), "{id}: upstream raises {}", case["err"]),
            Some(ok) => {
                let r = resolved.unwrap_or_else(|| panic!("{id}: rust failed, upstream ok"));
                assert_eq!(
                    r.effective_flags(),
                    ok["flags"].as_i64().unwrap(),
                    "{id}: flags"
                );
                assert_eq!(
                    r.path.as_deref().map(unsub),
                    ok["path"].as_str().map(str::to_owned),
                    "{id}: path"
                );
                let mut files = r
                    .files
                    .as_ref()
                    .map(|f| f.iter().map(|s| unsub(s)).collect::<Vec<_>>());
                if let Some(f) = files.as_mut() {
                    f.sort();
                }
                let mut want = ok["files"].as_array().map(|a| {
                    a.iter()
                        .map(|s| s.as_str().unwrap().to_owned())
                        .collect::<Vec<_>>()
                });
                if let Some(f) = want.as_mut() {
                    f.sort();
                }
                assert_eq!(files, want, "{id}: files");
                assert_eq!(
                    r.namespace.as_deref(),
                    ok["namespace"].as_str(),
                    "{id}: namespace"
                );
                // python-systemd rejects path+files at Reader(); the journalctl mapping must too
                let reader_ok = ok["reader_ok"].as_bool().unwrap();
                assert_eq!(
                    !matches!(
                        r.to_journalctl_args(),
                        Err(f2b_backend::journal::JournalError::PathAndFiles)
                    ),
                    reader_ok,
                    "{id}: path+files"
                );
            }
        }
        checked += 1;
    }
    assert!(checked > 90);
}
