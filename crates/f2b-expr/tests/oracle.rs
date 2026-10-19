//! Oracle tests: expected values were produced by upstream Python
//! (`tools/gen_f2b_expr_fixtures.py`). Outcome kinds in the fixtures:
//! `i`/`f` exact number, `E` upstream raised (must be `Err` here), `B` upstream
//! succeeded but needed an integer beyond i64 somewhere (must be
//! `Err(Overflow)`), `X`/`b`/`U` upstream succeeded with a non-number, a bool
//! (`str2seconds`) or a construct this crate rejects by design (must be `Err`).

use f2b_expr::{BanTimeIncrement, BanTimeOptions, ExprError, Num, seconds2str, str2seconds};
use std::collections::BTreeMap;

// ------------------------------------------------------------ mini JSON ----

#[derive(Debug)]
enum Json {
    Null,
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(BTreeMap<String, Json>),
}

impl Json {
    fn str(&self) -> &str {
        match self {
            Json::Str(s) => s,
            other => panic!("expected string, got {other:?}"),
        }
    }
    fn arr(&self) -> &[Json] {
        match self {
            Json::Arr(a) => a,
            other => panic!("expected array, got {other:?}"),
        }
    }
    fn get(&self, k: &str) -> &Json {
        match self {
            Json::Obj(o) => o.get(k).unwrap_or_else(|| panic!("missing key {k}")),
            other => panic!("expected object, got {other:?}"),
        }
    }
    fn opt_str(&self) -> Option<&str> {
        match self {
            Json::Null => None,
            Json::Str(s) => Some(s),
            other => panic!("expected string or null, got {other:?}"),
        }
    }
    fn num(&self) -> f64 {
        match self {
            Json::Num(n) => *n,
            other => panic!("expected number, got {other:?}"),
        }
    }
}

struct P<'a> {
    b: &'a [u8],
    i: usize,
}

impl P<'_> {
    fn ws(&mut self) {
        while self.b[self.i].is_ascii_whitespace() {
            self.i += 1;
        }
    }
    fn lit(&mut self, s: &str) {
        assert!(self.b[self.i..].starts_with(s.as_bytes()));
        self.i += s.len();
    }
    fn hex4(&mut self) -> u32 {
        let h = std::str::from_utf8(&self.b[self.i..self.i + 4]).unwrap();
        self.i += 4;
        u32::from_str_radix(h, 16).unwrap()
    }
    fn string(&mut self) -> String {
        self.i += 1;
        let mut out = String::new();
        loop {
            let c = self.b[self.i];
            self.i += 1;
            match c {
                b'"' => return out,
                b'\\' => {
                    let e = self.b[self.i];
                    self.i += 1;
                    match e {
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'b' => out.push('\x08'),
                        b'f' => out.push('\x0c'),
                        b'"' | b'\\' | b'/' => out.push(char::from(e)),
                        b'u' => {
                            let mut cp = self.hex4();
                            if (0xd800..0xdc00).contains(&cp) {
                                self.lit("\\u");
                                let lo = self.hex4();
                                cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                            }
                            out.push(char::from_u32(cp).unwrap());
                        }
                        _ => panic!("bad escape"),
                    }
                }
                c => out.push(char::from(c)), // fixtures are ASCII
            }
        }
    }
    fn value(&mut self) -> Json {
        self.ws();
        match self.b[self.i] {
            b'{' => {
                self.i += 1;
                let mut m = BTreeMap::new();
                loop {
                    self.ws();
                    if self.b[self.i] == b'}' {
                        self.i += 1;
                        return Json::Obj(m);
                    }
                    if self.b[self.i] == b',' {
                        self.i += 1;
                        self.ws();
                    }
                    let k = self.string();
                    self.ws();
                    self.lit(":");
                    let v = self.value();
                    m.insert(k, v);
                }
            }
            b'[' => {
                self.i += 1;
                let mut v = Vec::new();
                loop {
                    self.ws();
                    if self.b[self.i] == b']' {
                        self.i += 1;
                        return Json::Arr(v);
                    }
                    if self.b[self.i] == b',' {
                        self.i += 1;
                    }
                    v.push(self.value());
                }
            }
            b'"' => Json::Str(self.string()),
            b'n' => {
                self.lit("null");
                Json::Null
            }
            _ => {
                let s = self.i;
                while matches!(
                    self.b[self.i],
                    b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E'
                ) {
                    self.i += 1;
                }
                Json::Num(
                    std::str::from_utf8(&self.b[s..self.i])
                        .unwrap()
                        .parse()
                        .unwrap(),
                )
            }
        }
    }
}

fn load(name: &str) -> Json {
    let path = format!(
        "{}/../../testdata/f2b-expr/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    P {
        b: text.as_bytes(),
        i: 0,
    }
    .value()
}

fn parse_num(kind: &str, repr: &str) -> Num {
    match kind {
        "i" => Num::Int(repr.parse().unwrap()),
        "f" => Num::Float(repr.parse().unwrap()),
        k => panic!("bad kind {k}"),
    }
}

/// `"i:123"` / `"f:1.5"`, the fixtures' notation for a [`Num`].
fn tagged(n: Num) -> String {
    match n {
        Num::Int(i) => format!("i:{i}"),
        Num::Float(_) => format!("f:{n}"),
    }
}

// ---------------------------------------------------------------- tests ----

#[test]
fn str2seconds_matches_upstream() {
    let doc = load("str2seconds.json");
    let mut failures = Vec::new();
    for c in doc.get("cases").arr() {
        let (input, kind, repr) = (c.arr()[0].str(), c.arr()[1].str(), c.arr()[2].str());
        let got = str2seconds(input);
        let ok = match kind {
            "i" | "f" => got
                .clone()
                .is_ok_and(|n| tagged(n) == format!("{kind}:{repr}")),
            "B" => matches!(got, Err(ExprError::Overflow(_))),
            _ => got.is_err(),
        };
        if !ok {
            failures.push(format!("{input:?}: upstream {kind}:{repr}, got {got:?}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} mismatches, first: {:#?}",
        failures.len(),
        &failures[..failures.len().min(25)]
    );
}

#[test]
fn seconds2str_matches_upstream() {
    let doc = load("seconds2str.json");
    let mut failures = Vec::new();
    for c in doc.get("cases").arr() {
        let a = c.arr();
        let n = parse_num(a[0].str(), a[1].str());
        let got = seconds2str(n);
        let ok = match a[2].str() {
            "ok" => got.as_deref() == Ok(a[3].str()),
            "bignum" => matches!(got, Err(ExprError::Overflow(_))),
            _ => got.is_err(), // OverflowError upstream
        };
        if !ok {
            failures.push(format!(
                "{n:?}: upstream {} {:?}, got {got:?}",
                a[2].str(),
                a[3].str()
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} mismatches, first: {:#?}",
        failures.len(),
        &failures[..failures.len().min(25)]
    );
}

/// Compare one Python outcome tag with a Rust result.
fn outcome_matches(expected: &str, got: &Result<Num, ExprError>) -> bool {
    match expected.split_once(':') {
        Some(("i" | "f", _)) => got.as_ref().is_ok_and(|n| tagged(*n) == expected),
        Some(("b", v)) => got
            .as_ref()
            .is_ok_and(|n| *n == Num::Int(i64::from(v == "True"))),
        None if expected == "B" => matches!(got, Err(ExprError::Overflow(_))),
        // "E", "X:<type>", "U": must not succeed
        _ => got.is_err(),
    }
}

#[test]
fn factor_expressions_match_upstream() {
    let doc = load("expr.json");
    let mut failures = Vec::new();
    for c in doc.get("cases").arr() {
        let (expr, kind, repr) = (c.arr()[0].str(), c.arr()[1].str(), c.arr()[2].str());
        let expected = if kind == "i" || kind == "f" {
            format!("{kind}:{repr}")
        } else {
            kind.to_string()
        };
        let got = BanTimeIncrement::new(&BanTimeOptions {
            factor: Some(expr),
            multipliers: Some("1"),
            ..BanTimeOptions::default()
        })
        .and_then(|b| b.calc(Num::Int(1), 0, || 0.0));
        if !outcome_matches(&expected, &got) {
            failures.push(format!("{expr:?}: upstream {expected}, got {got:?}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} mismatches, first: {:#?}",
        failures.len(),
        &failures[..failures.len().min(40)]
    );
}

#[test]
fn ban_time_increment_matches_upstream() {
    let doc = load("bantime.json");
    let mut failures = Vec::new();
    let mut compared = 0usize;
    for set in doc.get("sets").arr() {
        let o = set.get("opts");
        let opts = BanTimeOptions {
            factor: o.get("factor").opt_str(),
            formula: o.get("formula").opt_str(),
            multipliers: o.get("multipliers").opt_str(),
            maxtime: o.get("maxtime").opt_str(),
            rndtime: o.get("rndtime").opt_str(),
        };
        let label = format!("{opts:?}");
        let built = BanTimeIncrement::new(&opts);
        let expected: Vec<&str> = set.get("results").arr().iter().map(Json::str).collect();
        match set.get("setup").str() {
            "error" => {
                if built.is_ok() {
                    failures.push(format!(
                        "{label}: upstream failed to configure, we accepted"
                    ));
                }
                continue;
            }
            "unsupported" => {
                if built.is_ok() {
                    failures.push(format!("{label}: documented-unsupported option accepted"));
                }
                continue;
            }
            "big" => {
                if !matches!(built, Err(ExprError::Overflow(_))) {
                    failures.push(format!(
                        "{label}: option needs a bignum upstream, got {built:?}"
                    ));
                }
                continue;
            }
            _ => {}
        }
        let Ok(inc) = built else {
            // Rust rejects at construction what Python only rejects on use:
            // allowed only if no evaluation succeeds upstream.
            if expected.iter().any(|e| e.starts_with(['i', 'f', 'b'])) {
                failures.push(format!(
                    "{label}: rejected at construction ({:?}) but upstream computes values",
                    built.err()
                ));
            }
            continue;
        };
        let times: Vec<Num> = set
            .get("times")
            .arr()
            .iter()
            .map(|t| parse_num(t.arr()[0].str(), t.arr()[1].str()))
            .collect();
        let counts: Vec<i64> = set
            .get("counts")
            .arr()
            .iter()
            .map(|c| c.num() as i64)
            .collect();
        let rands: Vec<f64> = set.get("rands").arr().iter().map(Json::num).collect();
        let uses_rnd = o.get("rndtime").opt_str().is_some_and(|s| !s.is_empty());
        let mut idx = 0;
        for rv in if uses_rnd { &rands[..] } else { &rands[..1] } {
            for t in &times {
                for c in &counts {
                    let got = inc.calc(*t, *c, || *rv);
                    compared += 1;
                    if !outcome_matches(expected[idx], &got) {
                        failures.push(format!(
                            "{label} time={t:?} count={c} rand={rv}: upstream {}, got {got:?}",
                            expected[idx]
                        ));
                    }
                    idx += 1;
                }
            }
        }
        assert_eq!(idx, expected.len(), "{label}: result count");
    }
    assert!(compared > 50_000, "fixture unexpectedly small: {compared}");
    assert!(
        failures.is_empty(),
        "{} mismatches, first: {:#?}",
        failures.len(),
        &failures[..failures.len().min(40)]
    );
}

#[test]
fn float_display_is_python_repr() {
    let doc = load("floats.json");
    for r in doc.get("reprs").arr() {
        let r = r.str();
        let f: f64 = r.parse().unwrap();
        assert_eq!(Num::Float(f).to_string(), r);
    }
}
