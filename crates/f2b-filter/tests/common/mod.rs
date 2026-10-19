//! Shared test helpers: building a `Filter` from a stock/test filter config.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;

use f2b_config::{Arg, RealFs, read_filter_stream};
use f2b_date::LocalZone;
use f2b_filter::Filter;
use f2b_types::{DnsUtils, SharedClock};
use indexmap::IndexMap;
use serde_json::Value;

pub fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

pub fn opt_to_string(v: &Value) -> String {
    v.as_str().map_or_else(|| v.to_string(), str::to_owned)
}

/// Builds the filter `name` of `label` ("stock" / "tests-config") with the
/// init options `opts` the way upstream's sample test does: reader output
/// applied to a fresh `Filter`, no backend-derived options.
pub fn build_filter(
    label: &str,
    name: &str,
    opts: &Value,
    clock: SharedClock,
    zone: LocalZone,
    dns: Arc<DnsUtils>,
    use_dns: Option<&str>,
) -> Result<Filter, String> {
    let up = root().join("fail2ban");
    let basedir = match label {
        "stock" => up.join("config"),
        _ => up.join("fail2ban/tests/config"),
    };
    let init: IndexMap<String, String> = opts
        .as_object()
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.clone(), opt_to_string(v)))
                .collect()
        })
        .unwrap_or_default();
    let stream = read_filter_stream(
        Rc::new(RealFs),
        basedir.to_str().unwrap(),
        name,
        "jail",
        init,
        None,
    )
    .map_err(|e| format!("reading filter: {e}"))?
    .ok_or("filter not found")?;

    let mut flt = Filter::new(clock, dns, zone);
    // like upstream, before any regex is added (`<HOST>` expansion depends on it)
    if let Some(u) = use_dns {
        flt.set_use_dns(u);
    }
    for cmd in &stream {
        let (Some(Arg::Str(kind)), Some(Arg::Str(opt))) = (cmd.first(), cmd.get(2)) else {
            return Err(format!("unexpected token in stream: {cmd:?}"));
        };
        let vals: Vec<&Arg> = match kind.as_str() {
            "multi-set" => match cmd.get(3) {
                Some(Arg::List(l)) => l.iter().collect(),
                _ => return Err("bad multi-set".into()),
            },
            "set" => cmd[3..].iter().collect(),
            other => return Err(format!("unexpected command {other}")),
        };
        for v in vals {
            let text = match v {
                Arg::Str(s) => s.as_str(),
                Arg::Int(_) => "",
                _ => continue,
            };
            match opt.as_str() {
                "prefregex" => flt.set_pref_regex(Some(text)).map_err(|e| e.to_string())?,
                "addfailregex" => flt.add_fail_regex(text).map_err(|e| e.to_string())?,
                "addignoreregex" => flt.add_ignore_regex(text).map_err(|e| e.to_string())?,
                "maxlines" => {
                    if let Arg::Int(n) = v {
                        flt.set_max_lines(*n).map_err(|e| e.to_string())?;
                    }
                }
                "datepattern" => flt
                    .set_date_pattern(Some(text))
                    .map_err(|e| e.to_string())?,
                _ => {}
            }
        }
    }
    Ok(flt)
}
