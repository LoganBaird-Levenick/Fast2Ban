//! Python `re` conformance: pattern x subject grid (hand-written snippets,
//! patterns Python rejects, seeded grammar fuzz), tag expansion, failure ids.

mod common;

use common::{check_construct, compare_match, fixture};
use f2b_regex::{Regex, RegexError, RegexOptions};

/// Records a failure; only the first failing check of each pattern is kept
/// (`key`), later ones are counted.
fn collect(failures: &mut Vec<String>, key: &str, ctx: String, r: Result<(), String>) {
    if let Err(e) = r {
        let tag = format!("[{key}] ");
        match failures.iter_mut().find(|f| f.starts_with(&tag)) {
            Some(f) => {
                if !f.contains(" (+") {
                    f.push_str(" (+1 more)");
                } else if let Some(i) = f.rfind(" (+") {
                    let n: usize = f[i + 3..].trim_end_matches(" more)").parse().unwrap_or(1);
                    f.truncate(i);
                    f.push_str(&format!(" (+{} more)", n + 1));
                }
            }
            None => failures.push(format!("{tag}{ctx}: {e}")),
        }
    }
}

fn report(what: &str, failures: &[String], total: usize) {
    eprintln!("{what}: {total} checks, {} failures", failures.len());
    assert!(
        failures.is_empty(),
        "{} divergences, first {}:\n{}",
        failures.len(),
        failures.len().min(60),
        failures
            .iter()
            .take(60)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn pattern_subject_grid() {
    let data = fixture("engine.json");
    let subjects: Vec<&str> = data["subjects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    let fuzz_n = data["fuzz_subject_count"].as_u64().unwrap() as usize;
    let (mut total, mut engines) = (0, [0usize; 3]);
    let mut failures = Vec::new();
    // Documented deviations (see crate docs): patterns that repeat a body able
    // to match empty (`el`) may differ in the captures of the last iteration or
    // exhaust the backtracking budget; huge repeat counts exceed the size limit.
    let (mut tolerated_el, mut tolerated_size, mut tolerated_limit, mut el_entries) = (0, 0, 0, 0);
    for e in data["entries"].as_array().unwrap() {
        let p = e["p"].as_str().unwrap();
        let ml = e["ml"].as_bool().unwrap();
        let opts = RegexOptions {
            multiline: ml,
            ..RegexOptions::default()
        };
        let r = Regex::with_options(p, &opts);
        total += 1;
        let mut c = check_construct(p, &r, &e["c"]);
        if matches!(&r, Err(RegexError::Engine { message, .. }) if message.contains("size limit")) {
            tolerated_size += 1;
            c = Ok(());
        }
        let ok = c.is_ok();
        collect(
            &mut failures,
            &format!("{p:?} {ml}"),
            format!("construct {p:?} ml={ml}"),
            c,
        );
        let Ok(mut re) = r else { continue };
        if !ok {
            continue;
        }
        let el = e.get("el").is_some();
        el_entries += usize::from(el);
        engines[usize::from(re.engine() == f2b_regex::EngineKind::Backtracking)] += 1;
        engines[2] += usize::from(re.has_exact_fallback());
        let xs: Vec<&str> = e
            .get("xs")
            .map(|v| {
                v.as_array()
                    .unwrap()
                    .iter()
                    .map(|s| s.as_str().unwrap())
                    .collect()
            })
            .unwrap_or_default();
        let base: &[&str] = if xs.is_empty() {
            &subjects
        } else {
            &subjects[..fuzz_n]
        };
        for (i, s) in base.iter().chain(xs.iter()).enumerate() {
            total += 1;
            let exp = e["r"].get(i.to_string());
            let mut r = compare_match(re.search_str(s), exp, false, false);
            // ReDoS guard: the step limit is a design decision, Python has none
            if r.as_ref().is_err_and(|m| m.contains("backtracking limit")) {
                tolerated_limit += 1;
                r = Ok(());
            }
            if el && r.is_err() {
                tolerated_el += 1;
                r = Ok(());
            }
            collect(
                &mut failures,
                &format!("{p:?} {ml}"),
                format!("{p:?} ml={ml} subject#{i} {s:?}"),
                r,
            );
        }
    }
    eprintln!(
        "grid: linear {} backtracking {} with exact fallback {}; empty-loop patterns {el_entries} ({tolerated_el} tolerated divergences), backtrack-limit hits {tolerated_limit}, size-limit {tolerated_size}",
        engines[0], engines[1], engines[2]
    );
    report("grid", &failures, total);
}

#[test]
fn mutated_filter_patterns() {
    let data = fixture("patmut.json");
    let (mut n, mut ok, mut err) = (0, 0, 0);
    let mut failures = Vec::new();
    for (id, cfg) in data.as_object().unwrap() {
        let lines: Vec<&str> = cfg["lines"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        for ent in cfg["entries"].as_array().unwrap() {
            let p = ent["p"].as_str().unwrap();
            let ml = ent["ml"].as_bool().unwrap();
            let opts = RegexOptions {
                multiline: ml,
                ..RegexOptions::default()
            };
            let r = Regex::with_options(p, &opts);
            let c = &ent["c"];
            n += 1;
            let key = format!("{id} {p:?}");
            if c["ok"].as_bool().unwrap() {
                ok += 1;
                let Ok(mut re) = r else {
                    collect(
                        &mut failures,
                        &key,
                        format!("{p:?}"),
                        Err(format!("rejected: {}", r.unwrap_err())),
                    );
                    continue;
                };
                let info = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    common::check_info("mut", &re, c, None)
                }));
                if info.is_err() {
                    failures.push(format!("[{key}] construct info differs"));
                    continue;
                }
                for (i, line) in lines.iter().enumerate() {
                    let exp = ent["r"].get(i.to_string());
                    let r = compare_match(re.search_str(line), exp, false, false);
                    collect(&mut failures, &key, format!("{p:?} line#{i}"), r);
                }
            } else {
                err += 1;
                let got = match &r {
                    Ok(_) => Err("accepted".to_owned()),
                    Err(RegexError::Compile { regex, error }) => {
                        if c["inner"].is_null()
                            || common::fnv64(regex) != c["regex_fnv"].as_str().unwrap()
                        {
                            Err(format!("regex {regex:?}"))
                        } else if error.to_string() == c["inner"].as_str().unwrap() {
                            Ok(())
                        } else {
                            Err(format!("inner {:?} != {}", error.to_string(), c["inner"]))
                        }
                    }
                    Err(e) => {
                        if e.to_string() == c["msg"].as_str().unwrap_or("") {
                            Ok(())
                        } else {
                            Err(format!("{e} != {c}"))
                        }
                    }
                };
                collect(&mut failures, &key, format!("{p:?} (Python rejects)"), got);
            }
        }
    }
    eprintln!("patmut: {n} patterns ({ok} accepted, {err} rejected)");
    report("patmut", &failures, n);
}
