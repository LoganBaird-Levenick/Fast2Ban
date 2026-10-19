//! Tag expansion, failure ids, `\d \s \w` definitions and upstream's unit-test
//! regexes over the test-suite's log files.

mod common;

use common::{check_construct, compare_match, fixture, tuple_line, use_dns};
use f2b_regex::{
    FailRegex, Regex, RegexOptions, TupleLine, global_to_local_flags, resolve_host_tag,
    tuple_lines_buf,
};
use regex_syntax::hir::{Class, HirKind};

#[test]
fn tag_expansion_and_global_flags() {
    let data = fixture("tags.json");
    let mut n = 0;
    for e in data["resolve"].as_array().unwrap() {
        let src = e["src"].as_str().unwrap();
        let dns = use_dns(e["usedns"].as_str().unwrap());
        let got = resolve_host_tag(src, dns);
        assert_eq!(
            got,
            e["tag"].as_str().unwrap(),
            "resolve_host_tag({src:?}, {dns:?})"
        );
        assert_eq!(
            global_to_local_flags(&got),
            e["glob"].as_str().unwrap(),
            "global_to_local_flags({got:?})"
        );
        n += 1;
    }
    for e in data["construct"].as_array().unwrap() {
        let src = e["src"].as_str().unwrap();
        let ml = e["ml"].as_bool().unwrap();
        let opts = RegexOptions {
            multiline: ml,
            ..RegexOptions::default()
        };
        let c = &e["c"];
        if e.get("kind").is_some() {
            let r = FailRegex::new(src, None, &opts);
            check_construct(src, &r, c).unwrap_or_else(|m| panic!("FailRegex({src:?}): {m}"));
        } else {
            let r = Regex::with_options(src, &opts);
            check_construct(src, &r, c).unwrap_or_else(|m| panic!("Regex({src:?}): {m}"));
        }
        n += 1;
    }
    eprintln!("tags: {n} cases");
}

#[test]
fn failure_ids_hosts_and_ips() {
    let data = fixture("fail.json");
    let subjects: Vec<&str> = data["subjects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    let (mut n, mut matches) = (0, 0);
    for e in data["entries"].as_array().unwrap() {
        let p = e["p"].as_str().unwrap();
        let usedns = e["usedns"].as_str().unwrap();
        let opts = RegexOptions {
            use_dns: use_dns(usedns),
            ..RegexOptions::default()
        };
        let r = FailRegex::new(p, None, &opts);
        check_construct(p, &r, &e["c"]).unwrap_or_else(|m| panic!("FailRegex({p:?}): {m}"));
        let Ok(mut re) = r else { continue };
        for (i, s) in subjects.iter().enumerate() {
            let exp = e["r"].get(i.to_string());
            let m = if let Some(line) = s.strip_suffix('\n') {
                let org = [TupleLine::new(
                    String::new(),
                    String::new(),
                    line.to_owned(),
                )];
                re.search_buf(s, &org)
            } else {
                re.search_str(s)
            };
            matches += usize::from(matches!(m, Ok(Some(_))));
            compare_match(m, exp, s.ends_with('\n'), true)
                .unwrap_or_else(|m| panic!("{p:?} ({usedns}) on {s:?}: {m}"));
            n += 1;
        }
    }
    for e in data["pref_combos"].as_array().unwrap() {
        let pref = Regex::new(e["pref"].as_str().unwrap()).unwrap();
        let p = e["p"].as_str().unwrap();
        let r = FailRegex::new(p, Some(&pref), &RegexOptions::default());
        check_construct(p, &r, &e["c"])
            .unwrap_or_else(|m| panic!("FailRegex({p:?}, pref {}): {m}", e["pref"]));
    }
    eprintln!("fail ids: {n} searches, {matches} matches");
}

fn ranges_of_class(pattern: &str) -> Vec<(u32, u32)> {
    let hir = regex_syntax::Parser::new().parse(pattern).unwrap();
    match hir.kind() {
        HirKind::Class(Class::Unicode(c)) => char_ranges(
            &c.iter()
                .map(|r| (u32::from(r.start()), u32::from(r.end())))
                .collect::<Vec<_>>(),
        ),
        other => panic!("{pattern}: not a class: {other:?}"),
    }
}

/// Python code point ranges as `char` ranges: no surrogates, and the ranges on
/// both sides of the gap are adjacent.
fn char_ranges(r: &[(u32, u32)]) -> Vec<(u32, u32)> {
    let mut cut = Vec::new();
    for &(lo, hi) in r {
        if hi < 0xD800 || lo > 0xDFFF {
            cut.push((lo, hi));
        } else {
            if lo < 0xD800 {
                cut.push((lo, 0xD7FF));
            }
            if hi > 0xDFFF {
                cut.push((0xE000, hi));
            }
        }
    }
    let mut out: Vec<(u32, u32)> = Vec::new();
    for (lo, hi) in cut {
        match out.last_mut() {
            Some(last) if lo == last.1 + 1 || (last.1 == 0xD7FF && lo == 0xE000) => last.1 = hi,
            _ => out.push((lo, hi)),
        }
    }
    out
}

fn complement(r: &[(u32, u32)]) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    let mut next = 0u32;
    for &(lo, hi) in r {
        if lo > next {
            out.push((next, lo - 1));
        }
        next = hi + 1;
    }
    if next <= 0x10FFFF {
        out.push((next, 0x10FFFF));
    }
    char_ranges(&out)
}

/// The emitted classes for `\d \s \w` (plain, negated, inside a set) equal
/// Python's definitions over all of Unicode.
#[test]
fn character_classes_match_python_definitions() {
    let data = fixture("charclasses.json");
    for (name, upper) in [("d", "D"), ("s", "S"), ("w", "W")] {
        let py: Vec<(u32, u32)> = data[name]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (r[0].as_u64().unwrap() as u32, r[1].as_u64().unwrap() as u32))
            .collect();
        let py = char_ranges(&py);
        let neg = complement(&py);
        for (pat, want) in [
            (format!(r"\{name}"), &py),
            (format!(r"[\{name}]"), &py),
            (format!(r"\{upper}"), &neg),
            (format!(r"[^\{name}]"), &neg),
            (format!(r"[\{upper}]"), &neg),
            (format!(r"[^\{upper}]"), &py),
        ] {
            let t = f2b_regex::translate::translate(&pat, false).unwrap();
            assert_eq!(&ranges_of_class(&t.primary), want, "{pat} -> {}", t.primary);
        }
        // mixed with literals takes the explicit-range path for negated categories
        let t = f2b_regex::translate::translate(&format!(r"[\{upper}x]"), false).unwrap();
        // `x` is already in the complement of \d and \s, in \W it is not
        let got = ranges_of_class(&t.primary);
        assert!(
            got.windows(2).all(|w| w[0].1 + 1 < w[1].0),
            "unmerged ranges: {t:?}"
        );
        for &(lo, hi) in &neg {
            assert!(
                got.iter().any(|&(l, h)| l <= lo && hi <= h),
                "{upper}: lost {lo:x}-{hi:x}"
            );
        }
        assert!(
            got.iter()
                .any(|&(l, h)| l <= u32::from(b'x') && u32::from(b'x') <= h)
        );
    }
}

#[test]
fn upstream_unit_test_regexes_over_test_logs() {
    let data = fixture("unit.json");
    let (mut n, mut matches) = (0, 0);
    let mut scratch = String::new();
    for case in data.as_array().unwrap() {
        let p = case["p"].as_str().unwrap();
        let ml = case["ml"].as_bool().unwrap();
        let opts = RegexOptions {
            multiline: ml,
            ..RegexOptions::default()
        };
        let (mut fail, mut plain);
        let re: &mut Regex = if case["kind"] == "fail" {
            fail = FailRegex::new(p, None, &opts).unwrap();
            &mut fail
        } else {
            plain = Regex::with_options(p, &opts).unwrap();
            &mut plain
        };
        let tuples: Vec<TupleLine> = case["tuples"]
            .as_array()
            .unwrap()
            .iter()
            .map(tuple_line)
            .collect();
        for (wi, w) in case["wins"].as_array().unwrap().iter().enumerate() {
            let (start, size) = (
                w[0].as_u64().unwrap() as usize,
                w[1].as_u64().unwrap() as usize,
            );
            let win = &tuples[start..start + size];
            tuple_lines_buf(win, &mut scratch);
            let buf = scratch.clone();
            let m = re.search_buf(&buf, win);
            matches += usize::from(matches!(m, Ok(Some(_))));
            compare_match(m, case["res"].get(wi.to_string()), true, false)
                .unwrap_or_else(|m| panic!("{} {p:?} window {w}: {m}", case["file"]));
            n += 1;
        }
    }
    eprintln!("unit: {n} searches, {matches} matches");
}
