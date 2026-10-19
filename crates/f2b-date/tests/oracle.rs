//! Oracle tests: every expected value comes from upstream Python
//! (`tools/gen_f2b_date_fixtures.py` -> `testdata/f2b-date/`).

use std::path::PathBuf;
use std::sync::Arc;

use f2b_date::{DateDetector, DateEnv, DateError, LocalZone, validate_time_zone};
use f2b_types::{FixedClock, SharedClock};
use serde_json::Value;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/f2b-date")
}

fn load(name: &str) -> Value {
    let path = fixture_dir().join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn strs(v: &Value) -> Vec<String> {
    v.as_array()
        .expect("array")
        .iter()
        .map(|s| s.as_str().expect("string").to_string())
        .collect()
}

struct Tables {
    strings: Vec<String>,
    lines: Vec<String>,
}

fn category(e: &DateError) -> &'static str {
    match e {
        DateError::Pattern { .. } => "pattern",
        DateError::DuplicateTemplate(_) => "duplicate",
        DateError::TimeZone(_) => "timezone",
        DateError::Time(_) => "time",
    }
}

struct Scn {
    id: String,
    zone: LocalZone,
    now: f64,
    wall_year: i64,
    alt: Option<f64>,
    skip: Option<String>,
}

fn scenarios() -> Vec<Scn> {
    let meta = load("meta.json");
    meta["scenarios"]
        .as_array()
        .expect("scenarios")
        .iter()
        .map(|s| {
            let tz = s["tz"].as_str().expect("tz");
            let (zone, skip) = match LocalZone::from_tz_value(tz) {
                Ok(z) => (z, None),
                Err(e) => (LocalZone::utc(), Some(e)),
            };
            Scn {
                id: s["id"].as_str().expect("id").to_string(),
                zone,
                now: s["now"].as_f64().expect("now"),
                wall_year: s["wall_year"].as_i64().expect("wall_year"),
                alt: s["alt"].as_f64(),
                skip,
            }
        })
        .collect()
}

fn env_for(s: &Scn) -> (DateEnv, Arc<FixedClock>) {
    let clock = Arc::new(FixedClock::new(s.now));
    let shared: SharedClock = clock.clone();
    let env = DateEnv::new(shared, s.zone.clone())
        .with_year_window_now(s.alt)
        .with_wall_clock_year(s.wall_year);
    (env, clock)
}

fn build(cfg: &Value, env: DateEnv) -> Result<DateDetector, DateError> {
    let tz = cfg["tz"].as_str();
    match cfg["kind"].as_str().expect("kind") {
        "default" => {
            let mut dd = DateDetector::new(env);
            dd.set_default_tz(tz)?;
            Ok(dd)
        }
        "default_now" => {
            let mut dd = DateDetector::new(env);
            dd.set_default_tz(tz)?;
            dd.add_default_template(None, None, true)?;
            Ok(dd)
        }
        "multi" => {
            DateDetector::from_date_pattern(cfg["pattern"].as_str().expect("pattern"), tz, env)
        }
        "list" => DateDetector::from_date_patterns(&strs(&cfg["patterns"]), tz, env),
        k => panic!("unknown kind {k}"),
    }
}

fn parse_f(v: &str) -> f64 {
    v.parse().unwrap_or_else(|e| panic!("float {v}: {e}"))
}

fn check_run(t: &Tables, s: &Scn, run: &Value) -> usize {
    let tag = run["tag"].as_str().unwrap_or("");
    let (env, clock) = env_for(s);
    let built = build(&run["cfg"], env);
    let ctx = format!("[{}:{}] cfg {}", s.id, tag, run["cfg"]);
    if let Some(expected) = run["error"].as_str() {
        match built {
            Ok(_) => panic!("{ctx}: upstream rejects ({expected}), we accepted"),
            Err(got) => assert_eq!(category(&got), expected, "{ctx}: {got}"),
        }
        return 0;
    }
    let proto = match built {
        Ok(d) => d,
        Err(e) => panic!("{ctx}: upstream accepts, we reject: {e}"),
    };
    // introspection right after construction
    let init = run["init"].as_array().expect("init");
    let got: Vec<_> = proto.templates().collect();
    assert_eq!(got.len(), init.len(), "{ctx}: template count");
    for (g, e) in got.iter().zip(init) {
        assert_eq!(
            g.name,
            t.strings[e[0].as_u64().unwrap() as usize],
            "{ctx}: name"
        );
        assert_eq!(
            g.pattern,
            e[1].as_u64().map(|i| t.strings[i as usize].as_str()),
            "{ctx}: pattern of {}",
            g.name
        );
        assert_eq!(
            g.regex,
            t.strings[e[2].as_u64().unwrap() as usize],
            "{ctx}: regex of {}",
            g.name
        );
        assert_eq!(
            u64::from(g.flags),
            e[3].as_u64().unwrap(),
            "{ctx}: flags of {}",
            g.name
        );
        assert_eq!(
            g.template_weight,
            e[4].as_f64().unwrap(),
            "{ctx}: weight of {}",
            g.name
        );
    }
    let dp = |v: &Value| -> (Option<String>, String) {
        (
            v[0].as_u64().map(|i| t.strings[i as usize].clone()),
            t.strings[v[1].as_u64().unwrap() as usize].clone(),
        )
    };
    let (p, n) = proto.get_date_pattern();
    assert_eq!(
        (p.map(str::to_string), n.to_string()),
        dp(&run["init_dp"]),
        "{ctx}: getDatePattern"
    );

    let fresh = run["fresh"].as_bool().unwrap_or(false);
    let orders = run["orders"].as_bool().unwrap_or(false);
    let times = run["times"].as_array();
    let ids = run["ids"].as_array().expect("ids");
    let res = run["res"].as_array().expect("res");
    let mut dd = proto.clone();
    for (n, rec) in res.iter().enumerate() {
        let line = &t.lines[ids[n].as_u64().unwrap() as usize];
        if let Some(times) = times {
            clock.set(times[n].as_f64().unwrap());
        }
        if fresh {
            dd = proto.clone();
        }
        let sctx = format!("{ctx}\n  step {n} line {line:?}");
        let tm = dd.match_time(line);
        if rec.is_null() {
            assert!(
                !tm.is_match(),
                "{sctx}: expected no match, got {:?} tpl {:?}",
                tm.match_span(),
                tm.template_index()
            );
        } else {
            let r = rec.as_array().unwrap();
            if r.len() == 1 {
                // upstream raised inside matchTime: the run ends there
                assert!(run["trunc"].as_bool().unwrap_or(false));
                return res.len();
            }
            assert!(tm.is_match(), "{sctx}: expected a match {r:?}");
            assert_eq!(
                tm.match_span(),
                Some((
                    r[0].as_u64().unwrap() as usize,
                    r[1].as_u64().unwrap() as usize
                )),
                "{sctx}: whole-match span"
            );
            match (&r[2], &r[3]) {
                (Value::Number(a), Value::Number(b)) => assert_eq!(
                    tm.span(),
                    Some((a.as_u64().unwrap() as usize, b.as_u64().unwrap() as usize)),
                    "{sctx}: group 1 span"
                ),
                _ => assert_eq!(tm.span(), None, "{sctx}: group 1 should be absent"),
            }
            let idx = tm.template_index().expect("template index");
            let name = dd.templates().nth(idx).expect("template").name.to_string();
            assert_eq!(
                name,
                t.strings[r[4].as_u64().unwrap() as usize],
                "{sctx}: template (index {idx})"
            );
            let got = dd.try_get_time(tm.date_text().unwrap_or(""), &tm);
            match r[5].as_str() {
                None => assert_eq!(got, Ok(None), "{sctx}: expected no time"),
                Some(e) if e.starts_with('!') => match got {
                    Err(DateError::Time(k)) => {
                        assert_eq!(format!("!{}", k.python_name()), e, "{sctx}")
                    }
                    other => panic!("{sctx}: expected exception {e}, got {other:?}"),
                },
                Some(e) => match got {
                    Ok(Some(v)) => {
                        assert_eq!(v.to_bits(), parse_f(e).to_bits(), "{sctx}: time {v} vs {e}")
                    }
                    other => panic!("{sctx}: expected time {e}, got {other:?}"),
                },
            }
        }
        if orders {
            let want: Vec<&str> = run["orders_list"][n]
                .as_array()
                .unwrap()
                .iter()
                .map(|i| t.strings[i.as_u64().unwrap() as usize].as_str())
                .collect();
            let got: Vec<&str> = dd.templates().map(|i| i.name).collect();
            assert_eq!(got, want, "{sctx}: template order");
        }
    }
    if !fresh {
        let fin = &run["final"];
        let want: Vec<&str> = fin["order"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| t.strings[i.as_u64().unwrap() as usize].as_str())
            .collect();
        let got: Vec<&str> = dd.templates().map(|i| i.name).collect();
        assert_eq!(got, want, "{ctx}: final order");
        let hits: Vec<u64> = dd.templates().map(|i| i.hits).collect();
        let want_hits: Vec<u64> = fin["hits"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h.as_u64().unwrap())
            .collect();
        assert_eq!(hits, want_hits, "{ctx}: final hits");
        let (p, n) = dd.get_date_pattern();
        assert_eq!(
            (p.map(str::to_string), n.to_string()),
            dp(&fin["dp"]),
            "{ctx}: final getDatePattern"
        );
    }
    res.len()
}

/// Runs `part` of `parts` (round-robin over runs) of scenario `id`.
fn run_scenario(id: &str, part: usize, parts: usize) {
    let t = Tables {
        strings: strs(&load("strings.json")),
        lines: strs(&load("lines.json")),
    };
    let s = scenarios()
        .into_iter()
        .find(|s| s.id == id)
        .unwrap_or_else(|| panic!("scenario {id}"));
    if let Some(why) = &s.skip {
        eprintln!("SKIPPED scenario {}: {why}", s.id);
        return;
    }
    let data = load(&format!("scn_{}.json", s.id));
    let mut steps = 0;
    for (n, run) in data.as_array().expect("runs").iter().enumerate() {
        if n % parts == part {
            steps += check_run(&t, &s, run);
        }
    }
    eprintln!("{id} part {part}/{parts}: {steps} steps compared");
    assert!(steps > 100);
}

macro_rules! scenario_tests {
    ($($name:ident: $id:literal $part:literal / $parts:literal;)*) => {
        $(#[test] fn $name() { run_scenario($id, $part, $parts); })*
    };
}

scenario_tests! {
    pinned_0: "pinned" 0 / 4;
    pinned_1: "pinned" 1 / 4;
    pinned_2: "pinned" 2 / 4;
    pinned_3: "pinned" 3 / 4;
    ny_iana: "ny_iana" 0 / 1;
    lord_howe: "lord_howe" 0 / 1;
    window_alt1: "window_alt1" 0 / 1;
    window_alt0: "window_alt0" 0 / 1;
    tokyo_alt_old: "tokyo_alt_old" 0 / 1;
}

#[test]
fn time_zone_validation_matches_upstream() {
    for rec in load("tz.json").as_array().expect("tz") {
        let input = rec["in"].as_str().unwrap();
        match rec.get("ok").and_then(Value::as_i64) {
            Some(v) => assert_eq!(validate_time_zone(input), Ok(v), "validate {input:?}"),
            None => assert!(
                validate_time_zone(input).is_err(),
                "validate {input:?} should fail"
            ),
        }
        let env = DateEnv::new(Arc::new(FixedClock::new(0.0)), LocalZone::utc());
        let mut dd = DateDetector::new(env);
        let r = dd.set_default_tz(Some(input));
        match rec.get("setter").and_then(Value::as_i64) {
            Some(v) => {
                assert!(r.is_ok(), "setter {input:?}");
                assert_eq!(dd.default_tz(), Some(v), "setter {input:?}");
            }
            None => assert!(r.is_err(), "setter {input:?} should fail"),
        }
    }
}
