//! `search()` oracle over the sample corpus: raw lines, tuple lines as the
//! filter sees them, multi-line windows, usedns=no and mutation fuzz.

mod common;

use std::collections::BTreeMap;

use common::{Config, build_config, compare_match, fixture, tuple_line};
use f2b_regex::{TupleLine, tuple_lines_buf};

fn configs_by_id(multiline_fail: Option<bool>, usedns: &str) -> BTreeMap<String, Config> {
    let configs = fixture("configs.json");
    configs
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["usedns"] == usedns)
        .map(|e| {
            let id = e["id"].as_str().unwrap().to_owned();
            (
                id.clone(),
                build_config(e, multiline_fail).unwrap_or_else(|m| panic!("{id}: {m}")),
            )
        })
        .collect()
}

struct Stats {
    searches: usize,
    matches: usize,
    failures: Vec<String>,
}

impl Stats {
    fn new() -> Stats {
        Stats {
            searches: 0,
            matches: 0,
            failures: Vec::new(),
        }
    }

    fn note(&mut self, ctx: String, buf: &str, r: Result<(), String>, matched: bool) {
        self.searches += 1;
        self.matches += usize::from(matched);
        if let Err(e) = r {
            if self.failures.len() < 40 {
                self.failures.push(format!("{ctx}: {e}\n    buf={buf:?}"));
            } else if self.failures.len() == 40 {
                self.failures.push("... more".into());
            }
        }
    }

    fn finish(self, what: &str) {
        eprintln!(
            "{what}: {} searches, {} matches",
            self.searches, self.matches
        );
        assert!(
            self.failures.is_empty(),
            "{} failing:\n{}",
            what,
            self.failures.join("\n")
        );
    }
}

/// `search.json`, `fuzz.json`: single-line searches (raw str and tuple form).
fn run_single(file: &str) {
    let data = fixture(file);
    let mut configs = configs_by_id(None, "warn");
    let mut st = Stats::new();
    let mut scratch = String::new();
    for (id, entry) in data.as_object().unwrap() {
        let cfg = configs
            .get_mut(id)
            .unwrap_or_else(|| panic!("no config {id}"));
        let journal = entry["journal"].as_bool().unwrap();
        let tuples: Vec<TupleLine> = entry["tuples"]
            .as_array()
            .unwrap()
            .iter()
            .map(tuple_line)
            .collect();
        let res = entry["res"].as_object().unwrap();
        for (rid, re) in cfg.all() {
            let per = &res[&rid];
            for (i, t) in tuples.iter().enumerate() {
                let raw = if journal {
                    t.post.clone()
                } else {
                    format!("{}{}{}", t.pre, t.date, t.post)
                };
                let exp_owned = per.get(format!("r{i}")).map(|r| {
                    let mut r = r.clone();
                    if r.get("same").is_some() {
                        // group values equal those of the tuple-line search
                        let t = &per[&format!("t{i}")];
                        for k in ["gv", "g"] {
                            if let Some(v) = t.get(k) {
                                r[k] = v.clone();
                            }
                        }
                    }
                    r
                });
                let exp = exp_owned.as_ref();
                let m = re.search_str(&raw);
                let matched = matches!(m, Ok(Some(_)));
                let r = compare_match(m, exp, false, false);
                st.note(format!("{file} {id} {rid} raw#{i}"), &raw, r, matched);

                let exp = per.get(format!("t{i}"));
                let m = re.search_lines(std::slice::from_ref(t), &mut scratch);
                let matched = matches!(m, Ok(Some(_)));
                let r = compare_match(m, exp, true, true);
                let buf = format!("{t:?}");
                st.note(format!("{file} {id} {rid} tuple#{i}"), &buf, r, matched);
            }
        }
    }
    st.finish(file);
}

#[test]
fn sample_lines() {
    run_single("search.json");
}

#[test]
fn mutated_sample_lines() {
    run_single("fuzz.json");
}

#[test]
fn sample_lines_usedns_no() {
    let data = fixture("search_nodns.json");
    let base = fixture("search.json");
    let mut configs = configs_by_id(None, "no");
    let mut st = Stats::new();
    let mut scratch = String::new();
    for (id, res) in data.as_object().unwrap() {
        let cfg = configs.get_mut(id).unwrap();
        let tuples: Vec<TupleLine> = base[id]["tuples"]
            .as_array()
            .unwrap()
            .iter()
            .map(tuple_line)
            .collect();
        for (rid, re) in cfg.all() {
            // the generator covers the first lines of each configuration only
            for (i, t) in tuples.iter().enumerate().take(14) {
                let exp = res[&rid].get(format!("t{i}"));
                let m = re.search_lines(std::slice::from_ref(t), &mut scratch);
                let matched = matches!(m, Ok(Some(_)));
                let r = compare_match(m, exp, true, true);
                st.note(
                    format!("nodns {id} {rid} #{i}"),
                    &format!("{t:?}"),
                    r,
                    matched,
                );
            }
        }
    }
    st.finish("search_nodns.json");
}

#[test]
fn multi_line_windows() {
    let data = fixture("multi.json");
    let mut configs = configs_by_id(Some(true), "warn");
    let mut st = Stats::new();
    let mut scratch = String::new();
    for (id, entry) in data.as_object().unwrap() {
        let cfg = configs.get_mut(id).unwrap();
        let tuples: Vec<TupleLine> = entry["tuples"]
            .as_array()
            .unwrap()
            .iter()
            .map(tuple_line)
            .collect();
        let res = entry["res"].as_object().unwrap();
        for (rid, re) in cfg.all() {
            for (wi, w) in entry["wins"].as_array().unwrap().iter().enumerate() {
                let (start, size) = (
                    w[0].as_u64().unwrap() as usize,
                    w[1].as_u64().unwrap() as usize,
                );
                let win = &tuples[start..start + size];
                tuple_lines_buf(win, &mut scratch);
                let buf = scratch.clone();
                let exp = res[&rid].get(wi.to_string());
                let m = re.search_buf(&buf, win);
                let matched = matches!(m, Ok(Some(_)));
                let r = compare_match(m, exp, true, true);
                st.note(format!("multi {id} {rid} win#{wi}"), &buf, r, matched);
            }
        }
    }
    st.finish("multi.json");
}
