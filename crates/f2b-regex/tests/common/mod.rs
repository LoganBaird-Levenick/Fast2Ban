//! Helpers shared by the oracle tests.
#![allow(dead_code)]

use std::path::PathBuf;

use f2b_regex::{GroupValue, Groups, Match, MatchError, Regex, RegexError, TupleLine, UseDns};
use serde_json::Value;

pub fn fixture(name: &str) -> Value {
    // F2B_REGEX_FIXTURES: exploratory fixtures from a scaled generator run
    let dir = std::env::var("F2B_REGEX_FIXTURES").unwrap_or_else(|_| {
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/f2b-regex").to_owned()
    });
    let path: PathBuf = [dir.as_str(), name].iter().collect();
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("cannot parse {}: {e}", path.display()))
}

pub fn use_dns(s: &str) -> UseDns {
    UseDns::from_setting(s)
}

/// FNV-1a 64 as written by the generator.
pub fn fnv64(s: &str) -> String {
    let mut h: u64 = 0xCBF2_9CE4_8422_2325;
    for b in s.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01B3);
    }
    format!("{h:016x}")
}

/// Python str index (code points) of byte offset `b`.
pub fn char_index(s: &str, b: usize) -> usize {
    s[..b].chars().count()
}

pub fn tuple_line(v: &Value) -> TupleLine<String> {
    let a = v.as_array().expect("tuple line array");
    TupleLine::new(
        a[0].as_str().unwrap().to_owned(),
        a[1].as_str().unwrap().to_owned(),
        a[2].as_str().unwrap().to_owned(),
    )
}

/// JSON encoding of a group value as written by the generator.
pub fn encode(v: &GroupValue<&str>) -> Value {
    match v {
        GroupValue::None => Value::Null,
        GroupValue::Str(s) => Value::String((*s).to_owned()),
        GroupValue::Tuple(t) => {
            let items: Vec<Value> = t
                .iter()
                .map(|o| o.map_or(Value::Null, |s| Value::String(s.to_owned())))
                .collect();
            serde_json::json!({ "t": items })
        }
    }
}

pub fn groups_record(g: &Groups<'_>, names: &[(String, usize)]) -> (Option<Value>, Value) {
    let keys: Vec<&str> = g.iter().map(|(k, _)| k).collect();
    let standard: Vec<&str> = names.iter().map(|(n, _)| n.as_str()).collect();
    if keys == standard {
        let vals: Vec<Value> = g.iter().map(|(_, v)| encode(v)).collect();
        (Some(Value::Array(vals)), Value::Null)
    } else {
        let pairs: Vec<Value> = g
            .iter()
            .map(|(k, v)| serde_json::json!([k, encode(v)]))
            .collect();
        (None, Value::Array(pairs))
    }
}

/// Compares a Rust match (or its absence) with the generator's record.
/// Returns an error text describing the first difference.
pub fn compare_match(
    m: Result<Option<Match<'_>>, MatchError>,
    expected: Option<&Value>,
    with_lines: bool,
    check_ids: bool,
) -> Result<(), String> {
    let m = match m {
        Ok(m) => m,
        Err(e) => return Err(format!("search error: {e}")),
    };
    let (m, exp) = match (m, expected) {
        (None, None) => return Ok(()),
        (Some(m), None) => {
            return Err(format!(
                "unexpected match span={:?} groups={:?}",
                m.span(),
                m.groups()
            ));
        }
        (None, Some(e)) => return Err(format!("missing match, expected {e}")),
        (Some(m), Some(e)) => (m, e),
    };
    let hay = m.haystack();
    let (s, e) = m.span();
    let got_span = (char_index(hay, s), char_index(hay, e));
    let exp_span = (
        exp["s"].as_u64().unwrap() as usize,
        exp["e"].as_u64().unwrap() as usize,
    );
    if got_span != exp_span {
        return Err(format!("span {got_span:?} != {exp_span:?}"));
    }
    let (gv, g) = groups_record(&m.groups(), m.regex().group_names());
    if let Some(gv) = gv {
        if exp.get("gv") != Some(&gv) {
            return Err(format!("gv {gv} != {:?}", exp.get("gv")));
        }
    } else if exp.get("g") != Some(&g) {
        return Err(format!(
            "g {g} != {:?} (gv {:?})",
            exp.get("g"),
            exp.get("gv")
        ));
    }
    let sk: Vec<String> = m.skipped_lines().iter().map(|c| c.to_string()).collect();
    let exp_sk: Vec<String> = exp
        .get("sk")
        .map(|v| {
            v.as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().to_owned())
                .collect()
        })
        .unwrap_or_default();
    if sk != exp_sk {
        return Err(format!("skipped {sk:?} != {exp_sk:?}"));
    }
    if with_lines {
        let idx = |k: &str, default: Vec<usize>| -> Vec<usize> {
            exp.get(k).map_or(default, |v| {
                v.as_array()
                    .unwrap()
                    .iter()
                    .map(|x| x.as_u64().unwrap() as usize)
                    .collect()
            })
        };
        // single-line searches record no m/u: matched is the one line.
        let (dm, du) = (vec![0], vec![]);
        if m.matched_lines() != idx("m", dm).as_slice() {
            return Err(format!(
                "matched lines {:?} != {:?}",
                m.matched_lines(),
                exp.get("m")
            ));
        }
        if m.unmatched_lines() != idx("u", du).as_slice() {
            return Err(format!(
                "unmatched lines {:?} != {:?}",
                m.unmatched_lines(),
                exp.get("u")
            ));
        }
    }
    if check_ids && let Some(id) = exp.get("id") {
        let want_str = |k: &str| id.get(k).and_then(|v| v.as_str());
        for (key, got) in [("fid", m.fail_id()), ("host", m.host())] {
            match (got, want_str(key)) {
                (Ok(g), Some(w)) if g == w => {}
                (Err(MatchError::NoFailId { buf, .. }), None) if buf == hay => {}
                (g, w) => return Err(format!("{key}: {g:?} != {w:?}")),
            }
        }
        match (m.ip(), id.get("ip")) {
            (Ok(ip), Some(Value::Array(a))) => {
                let got = serde_json::json!([
                    ip.ntoa().into_owned(),
                    ip.plen(),
                    ip.family_str(),
                    ip.is_valid()
                ]);
                // prefix lengths beyond u32 saturate (documented deviation)
                let mut want = a.clone();
                if want[1].as_u64().is_some_and(|p| p > u64::from(u32::MAX)) {
                    want[1] = Value::from(u32::MAX);
                }
                if got != Value::Array(want) {
                    return Err(format!("ip {got} != {a:?}"));
                }
            }
            (Err(MatchError::NoFailId { .. }), Some(Value::Null)) => {}
            (Err(MatchError::Ip(_) | MatchError::BadCidr), Some(Value::String(s)))
                if s.starts_with("exc:") => {}
            (g, w) => return Err(format!("ip: {g:?} != {w:?}")),
        }
    }
    Ok(())
}

use f2b_regex::{EngineKind, FailRegex, RegexOptions};

pub struct Config {
    pub id: String,
    pub pref: Option<Regex>,
    pub fails: Vec<FailRegex>,
    pub ignores: Vec<Regex>,
}

impl Config {
    /// Regexes with their ids (`pref`, `f0`.., `i0`..) and whether they are failregexes.
    pub fn all(&mut self) -> Vec<(String, &mut Regex)> {
        let mut out: Vec<(String, &mut Regex)> = Vec::new();
        if let Some(p) = self.pref.as_mut() {
            out.push(("pref".to_owned(), p));
        }
        for (i, f) in self.fails.iter_mut().enumerate() {
            out.push((format!("f{i}"), &mut **f));
        }
        for (i, r) in self.ignores.iter_mut().enumerate() {
            out.push((format!("i{i}"), r));
        }
        out
    }

    pub fn engines(&self) -> Vec<EngineKind> {
        let mut v = Vec::new();
        v.extend(self.pref.iter().map(Regex::engine));
        v.extend(self.fails.iter().map(|f| f.engine()));
        v.extend(self.ignores.iter().map(Regex::engine));
        v
    }
}

/// Builds the regexes of a `configs.json` entry like upstream's `Filter` does.
/// `multiline_fail` overrides the failregex multiline flag.
pub fn build_config(entry: &Value, multiline_fail: Option<bool>) -> Result<Config, String> {
    let usedns = use_dns(entry["usedns"].as_str().unwrap());
    let maxlines = entry["maxlines"].as_u64().unwrap();
    let opts = RegexOptions {
        multiline: false,
        use_dns: usedns,
        ..RegexOptions::default()
    };
    let pref = match entry["pref_src"].as_str() {
        Some(src) => Some(Regex::with_options(src, &opts).map_err(|e| e.to_string())?),
        None => None,
    };
    let fopts = RegexOptions {
        multiline: multiline_fail.unwrap_or(maxlines > 1),
        ..opts
    };
    let mut fails = Vec::new();
    for src in entry["fail_src"].as_array().unwrap() {
        fails.push(
            FailRegex::new(src.as_str().unwrap(), pref.as_ref(), &fopts)
                .map_err(|e| e.to_string())?,
        );
    }
    let mut ignores = Vec::new();
    for src in entry["ignore_src"].as_array().unwrap() {
        ignores.push(Regex::with_options(src.as_str().unwrap(), &opts).map_err(|e| e.to_string())?);
    }
    Ok(Config {
        id: entry["id"].as_str().unwrap().to_owned(),
        pref,
        fails,
        ignores,
    })
}

/// Checks a construction result against the generator's expectation.
pub fn check_construct<T: AsRegex>(
    p: &str,
    r: &Result<T, RegexError>,
    c: &Value,
) -> Result<(), String> {
    if c["ok"].as_bool().unwrap() {
        let re: &Regex = r
            .as_ref()
            .map_err(|e| format!("construction failed: {e}"))?
            .as_regex();
        let want_regex = c.get("regex").map_or(p, |v| v.as_str().unwrap());
        if re.regex() != want_regex {
            return Err(format!("regex text {:?} != {want_regex:?}", re.regex()));
        }
        let names: Vec<Value> = re
            .group_names()
            .iter()
            .map(|(n, i)| serde_json::json!([n, i]))
            .collect();
        if Value::Array(names.clone()) != c["names"] {
            return Err(format!("names {names:?} != {}", c["names"]));
        }
        let (alt, tup) = re.merge_tables();
        let pairs = |t: &[(String, String)]| -> Value {
            Value::Array(t.iter().map(|(k, n)| serde_json::json!([k, n])).collect())
        };
        if pairs(alt) != c["alt"] || pairs(tup) != c["tuple"] {
            return Err(format!(
                "alt/tuple tables {:?} {:?} != {} {}",
                alt, tup, c["alt"], c["tuple"]
            ));
        }
        if let Some(repr) = c.get("repr")
            && re.pattern_repr() != repr.as_str().unwrap()
        {
            return Err(format!("repr {:?} != {repr}", re.pattern_repr()));
        }
        Ok(())
    } else {
        let msg = c["msg"].as_str().unwrap();
        match r {
            Ok(_) => Err(format!("accepted, Python raised {}: {msg}", c["type"])),
            Err(e @ RegexError::Compile { error, .. }) => {
                let want_full = c["type"] == "RegexException";
                let got = if want_full {
                    e.to_string()
                } else {
                    error.to_string()
                };
                if got == msg {
                    Ok(())
                } else {
                    Err(format!("error text {got:?} != {msg:?}"))
                }
            }
            Err(e) => {
                if c["type"] == "RegexException" && e.to_string() == msg {
                    Ok(())
                } else {
                    Err(format!("error {e:?} != {} {msg:?}", c["type"]))
                }
            }
        }
    }
}

/// Lets `check_construct` take both `Regex` and `FailRegex` results.
pub trait AsRegex {
    fn as_regex(&self) -> &Regex;
}

impl AsRegex for Regex {
    fn as_regex(&self) -> &Regex {
        self
    }
}

impl AsRegex for FailRegex {
    fn as_regex(&self) -> &Regex {
        self
    }
}

pub fn check_info(ctx: &str, re: &Regex, exp: &Value, expanded: Option<&str>) {
    assert_eq!(
        re.regex().chars().count() as u64,
        exp["regex_len"].as_u64().unwrap(),
        "{ctx}: length"
    );
    assert_eq!(
        fnv64(re.regex()),
        exp["regex_fnv"].as_str().unwrap(),
        "{ctx}: text hash"
    );
    if let Some(expanded) = expanded {
        assert_eq!(re.regex(), expanded, "{ctx}: getRegex()");
    }
    let names: Vec<Value> = re
        .group_names()
        .iter()
        .map(|(n, i)| serde_json::json!([n, i]))
        .collect();
    assert_eq!(Value::Array(names), exp["names"], "{ctx}: groupindex");
    let (alt, tup) = re.merge_tables();
    let pairs = |t: &[(String, String)]| -> Value {
        Value::Array(t.iter().map(|(k, n)| serde_json::json!([k, n])).collect())
    };
    assert_eq!(pairs(alt), exp["alt"], "{ctx}: alt tables");
    assert_eq!(pairs(tup), exp["tuple"], "{ctx}: tuple tables");
}
