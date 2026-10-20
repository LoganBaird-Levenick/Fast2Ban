//! Benchmark Fast2Ban filter throughput on identical corpora to Phase 0.

use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Instant;

use f2b_config::{Arg, RealFs, read_filter_stream};
use f2b_date::LocalZone;
use f2b_filter::Filter;
use f2b_types::{DnsUtils, FixedClock, SharedClock};
use indexmap::IndexMap;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn corpus(logs_dir: &Path, name: &str) -> Vec<String> {
    let content = fs::read_to_string(logs_dir.join(name)).unwrap();
    content
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_owned)
        .collect()
}

fn peak_rss_kib() -> usize {
    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("VmHWM:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(n) = parts.get(1).and_then(|p| p.parse::<usize>().ok()) {
                    return n;
                }
            }
        }
    }
    0
}

fn arg_str(arg: &Arg) -> Option<&str> {
    match arg {
        Arg::Str(s) => Some(s.as_str()),
        _ => None,
    }
}

fn main() {
    let root = repo_root();
    let config_dir = root.join("fail2ban/config");
    let logs_dir = root.join("fail2ban/fail2ban/tests/files/logs");

    let clock: SharedClock = Arc::new(FixedClock::new(1124013600.0));
    let zone = LocalZone::utc();
    let fs = Rc::new(RealFs);

    let filters = ["sshd", "apache-auth", "nginx-http-auth", "postfix"];
    let repeat = 20;
    let rounds = 5;

    let mut results = serde_json::Map::new();

    for name in filters {
        let dns = Arc::new(DnsUtils::system(clock.clone()));
        let mut flt = Filter::new(clock.clone(), dns, zone.clone());
        flt.return_raw_host = true;
        flt.check_find_time = false;

        let stream_opt = read_filter_stream(
            fs.clone(),
            config_dir.to_str().unwrap(),
            name,
            "jail",
            IndexMap::new(),
            None,
        )
        .unwrap();

        if let Some(stream) = stream_opt {
            for cmd in stream {
                let target = cmd.get(2).and_then(arg_str).unwrap_or("");
                let vals: Vec<&Arg> = match cmd.first().and_then(arg_str) {
                    Some("multi-set") => match cmd.get(3) {
                        Some(Arg::List(l)) => l.iter().collect(),
                        _ => Vec::new(),
                    },
                    Some("set") => cmd[3..].iter().collect(),
                    _ => Vec::new(),
                };
                for v in vals {
                    match target {
                        "prefregex" => {
                            if let Some(s) = arg_str(v) {
                                let _ = flt.set_pref_regex(Some(s));
                            }
                        }
                        "addfailregex" => {
                            if let Some(s) = arg_str(v) {
                                let _ = flt.add_fail_regex(s);
                            }
                        }
                        "addignoreregex" => {
                            if let Some(s) = arg_str(v) {
                                let _ = flt.add_ignore_regex(s);
                            }
                        }
                        "maxlines" => {
                            let n = match v {
                                Arg::Int(n) => Some(*n),
                                Arg::Str(s) => s.parse::<i64>().ok(),
                                _ => None,
                            };
                            if let Some(n) = n {
                                let _ = flt.set_max_lines(n);
                            }
                        }
                        "datepattern" => {
                            if let Some(s) = arg_str(v) {
                                let _ = flt.set_date_pattern(Some(s));
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        let base_lines = corpus(&logs_dir, name);
        let mut lines = Vec::with_capacity(base_lines.len() * repeat);
        for _ in 0..repeat {
            lines.extend(base_lines.clone());
        }

        let mut best_lines_per_sec = 0.0;
        let mut matched = 0;

        for _ in 0..rounds {
            let t0 = Instant::now();
            let mut round_matched = 0;
            for ln in &lines {
                if let Ok(entries) = flt.process_line(ln) {
                    if !entries.is_empty() {
                        round_matched += 1;
                    }
                }
            }
            let dt = t0.elapsed().as_secs_f64();
            let lps = (lines.len() as f64) / dt;
            if lps > best_lines_per_sec {
                best_lines_per_sec = lps;
            }
            matched = round_matched;
        }

        let mut res = serde_json::Map::new();
        res.insert("lines".into(), lines.len().into());
        res.insert("matched".into(), matched.into());
        res.insert(
            "lines_per_sec".into(),
            (best_lines_per_sec.round() as u64).into(),
        );
        results.insert(name.into(), serde_json::Value::Object(res));
    }

    results.insert("_peak_rss_kib".into(), peak_rss_kib().into());
    results.insert("_fast2ban_version".into(), "0.1.0".into());

    println!("{}", serde_json::to_string_pretty(&results).unwrap());
}
