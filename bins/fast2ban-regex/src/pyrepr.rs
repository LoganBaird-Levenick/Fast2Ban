//! Python `repr()` / `str()` renderings of the values the tool prints
//! (`%r` of option dicts, failure dictionaries, tuples, floats).

use f2b_config::Val;
use f2b_filter::{FailData, FailVal};
use f2b_helpers::pychar::repr_str;
use f2b_regex::{GroupValue, TupleLine};
use indexmap::IndexMap;

/// `repr(str)`.
pub fn repr(s: &str) -> String {
    repr_str(s)
}

/// `repr(float)` for the magnitudes timestamps have.
pub fn float_repr(v: f64) -> String {
    if v.is_nan() {
        return "nan".to_owned();
    }
    if v.is_infinite() {
        return if v < 0.0 { "-inf" } else { "inf" }.to_owned();
    }
    let dbg = format!("{v:?}");
    // Rust: `1e16`, `1.5e-5`; Python: `1e+16`, `1.5e-05`
    match dbg.split_once('e') {
        Some((m, e)) => {
            let (sign, digits) = match e.strip_prefix('-') {
                Some(d) => ('-', d),
                None => ('+', e),
            };
            format!("{m}e{sign}{digits:0>2}")
        }
        None => dbg,
    }
}

/// `repr` of a config value (`Val`).
pub fn val_repr(v: &Val) -> String {
    match v {
        Val::Str(s) => repr(s),
        Val::Int(i) => i.to_string(),
        Val::Bool(true) => "True".to_owned(),
        Val::Bool(false) => "False".to_owned(),
        Val::None => "None".to_owned(),
    }
}

/// `repr(dict)` of string keys with already rendered values.
pub fn dict_repr<'a>(items: impl IntoIterator<Item = (&'a str, String)>) -> String {
    let body: Vec<String> = items
        .into_iter()
        .map(|(k, v)| format!("{}: {v}", repr(k)))
        .collect();
    format!("{{{}}}", body.join(", "))
}

/// `repr` of an option dictionary (`{'mode': 'aggressive'}`).
pub fn str_map_repr(m: &IndexMap<String, String>) -> String {
    dict_repr(m.iter().map(|(k, v)| (k.as_str(), repr(v))))
}

fn tuple_repr(items: &[String]) -> String {
    match items {
        [one] => format!("({one},)"),
        _ => format!("({})", items.join(", ")),
    }
}

fn opt_str_repr(s: &Option<String>) -> String {
    s.as_ref().map_or_else(|| "None".to_owned(), |s| repr(s))
}

fn tuple_line_repr(l: &TupleLine<String>) -> String {
    tuple_repr(&[repr(&l.pre), repr(&l.date), repr(&l.post)])
}

fn group_value_repr(v: &GroupValue<String>) -> String {
    match v {
        GroupValue::None => "None".to_owned(),
        GroupValue::Str(s) => repr(s),
        GroupValue::Tuple(t) => tuple_repr(&t.iter().map(opt_str_repr).collect::<Vec<_>>()),
    }
}

/// `repr(value)` of a failure dictionary value.
pub fn fail_val_repr(v: &FailVal) -> String {
    match v {
        FailVal::None => "None".to_owned(),
        FailVal::Str(s) => repr(s),
        FailVal::Tuple(t) => tuple_repr(&t.iter().map(opt_str_repr).collect::<Vec<_>>()),
        FailVal::Int(i) => i.to_string(),
        FailVal::Lines(l) => {
            let items: Vec<String> = l.iter().map(tuple_line_repr).collect();
            format!("[{}]", items.join(", "))
        }
        FailVal::Set(s) => {
            if s.is_empty() {
                "set()".to_owned()
            } else {
                let items: Vec<String> = s.iter().map(group_value_repr).collect();
                format!("{{{}}}", items.join(", "))
            }
        }
        FailVal::Ip(ip) => repr(&ip.ntoa()),
    }
}

/// `str(value)` of a failure dictionary value.
pub fn fail_val_str(v: &FailVal) -> String {
    match v {
        FailVal::Str(s) => s.clone(),
        FailVal::Ip(ip) => ip.ntoa().into_owned(),
        other => fail_val_repr(other),
    }
}

/// `repr(dict)` of a failure dictionary, skipping the keys in `skip`.
pub fn fail_data_repr(d: &FailData, skip: &[&str]) -> String {
    dict_repr(
        d.iter()
            .filter(|(k, _)| !skip.contains(&k.as_str()))
            .map(|(k, v)| (k.as_str(), fail_val_repr(v))),
    )
}
