//! Every function is compared with the upstream Python result recorded in
//! `testdata/f2b-helpers/*.json` (see `tools/gen_f2b_helpers_fixtures.py`).

mod common;

use common::{Value, load};
use f2b_helpers::{
    AddRepl, as_bool, extract_options, merge_dicts, remove_comments, shlex_split,
    split_with_options, splitwords, substitute_recursive_tags,
};
use indexmap::IndexMap;
use std::collections::{HashMap, HashSet};

fn to_map(p: Vec<(String, String)>) -> IndexMap<String, String> {
    p.into_iter().collect()
}

fn pairs_of(m: &IndexMap<String, String>) -> Vec<(String, String)> {
    m.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
}

#[test]
fn as_bool_matches_upstream() {
    let cases = load("as_bool.json");
    assert!(cases.arr().len() > 50);
    for c in cases.arr() {
        let (input, want) = (c.arr()[0].str(), c.arr()[1].bool());
        assert_eq!(as_bool(input), want, "input {input:?}");
    }
}

#[test]
fn splitwords_matches_upstream() {
    let cases = load("splitwords.json");
    assert!(cases.arr().len() > 10_000);
    for c in cases.arr() {
        let (input, ic, want) = (c.arr()[0].str(), c.arr()[1].bool(), c.arr()[2].strings());
        assert_eq!(
            splitwords(input, ic),
            want,
            "input {input:?} ignore_comments={ic}"
        );
    }
}

#[test]
fn remove_comments_matches_upstream() {
    let cases = load("remove_comments.json");
    assert!(cases.arr().len() > 5_000);
    for c in cases.arr() {
        let (input, want) = (c.arr()[0].str(), c.arr()[1].str());
        assert_eq!(remove_comments(input), want, "input {input:?}");
    }
}

fn check_extract(c: &Value) {
    let input = c.field("in").str();
    match (c.get("ok"), c.get("err")) {
        (Some(ok), None) => {
            let want_name = ok.arr()[0].str();
            let want_opts = ok.arr()[1].pairs();
            let (name, opts) = extract_options(input)
                .unwrap_or_else(|e| panic!("input {input:?}: unexpected error {e}"));
            assert_eq!(name, want_name, "input {input:?}");
            assert_eq!(pairs_of(&opts), want_opts, "input {input:?}");
        }
        (None, Some(err)) => {
            let got = extract_options(input)
                .expect_err(&format!("input {input:?}: upstream rejects, we accepted"));
            assert_eq!(got.to_string(), err.str(), "input {input:?}");
        }
        _ => panic!("bad fixture"),
    }
}

#[test]
fn extract_options_matches_upstream() {
    let cases = load("extract_options.json");
    assert!(cases.arr().len() > 20_000);
    cases.arr().iter().for_each(check_extract);
}

#[test]
fn split_with_options_matches_upstream() {
    let cases = load("split_with_options.json");
    assert!(cases.arr().len() > 10_000);
    for c in cases.arr() {
        let (input, want) = (c.arr()[0].str(), c.arr()[1].strings());
        assert_eq!(split_with_options(input), want, "input {input:?}");
    }
}

fn check_tags(c: &Value) {
    let tags = to_map(c.field("tags").pairs());
    let conditional = c.field("conditional").str();
    let ignore: HashSet<String> = c.field("ignore").strings().into_iter().collect();
    let repl: Option<HashMap<String, String>> = match c.field("addrepl") {
        Value::Null => None,
        v => Some(v.pairs().into_iter().collect()),
    };
    let lookup = |name: &str| repl.as_ref().and_then(|m| m.get(name).cloned());
    let addrepl: Option<AddRepl<'_>> = repl.as_ref().map(|_| &lookup as AddRepl<'_>);
    let got = substitute_recursive_tags(&tags, conditional, &ignore, addrepl);
    let ctx = || {
        format!(
            "tags {:?} conditional {conditional:?} ignore {ignore:?}",
            c.field("tags").pairs()
        )
    };
    match (c.get("ok"), c.get("err")) {
        (Some(ok), None) => {
            let got = got.unwrap_or_else(|e| panic!("{}: unexpected error {e}", ctx()));
            assert_eq!(pairs_of(&got), ok.pairs(), "{}", ctx());
        }
        (None, Some(err)) => {
            let e = got.expect_err(&format!("{}: upstream rejects, we accepted", ctx()));
            assert_eq!(e.to_string(), err.str(), "{}", ctx());
        }
        _ => panic!("bad fixture"),
    }
}

#[test]
fn substitute_recursive_tags_matches_upstream() {
    let cases = load("substitute_tags.json");
    assert!(cases.arr().len() > 3_000);
    cases.arr().iter().for_each(check_tags);
}

#[test]
fn shlex_split_matches_upstream() {
    let cases = load("shlex_split.json");
    assert!(cases.arr().len() > 10_000);
    for c in cases.arr() {
        let input = c.field("in").str();
        match (c.get("ok"), c.get("err")) {
            (Some(ok), None) => assert_eq!(
                shlex_split(input).unwrap_or_else(|e| panic!("input {input:?}: {e}")),
                ok.strings(),
                "input {input:?}"
            ),
            (None, Some(err)) => {
                let e = shlex_split(input).expect_err(&format!("input {input:?}"));
                assert_eq!(e.to_string(), err.str(), "input {input:?}");
            }
            _ => panic!("bad fixture"),
        }
    }
}

/// Boundary code points of Python's `\w` and `isprintable()` classes, through the public API.
#[test]
fn unicode_classes_match_upstream() {
    let cases = load("unicode_class.json");
    assert!(cases.field("extract").arr().len() > 5_000);
    cases.field("extract").arr().iter().for_each(check_extract);
    assert!(cases.field("tags").arr().len() > 1_000);
    cases.field("tags").arr().iter().for_each(check_tags);
}

#[test]
fn merge_dicts_matches_upstream() {
    for c in load("merge_dicts.json").arr() {
        let (x, y) = (to_map(c.arr()[0].pairs()), to_map(c.arr()[1].pairs()));
        let merged = merge_dicts(&x, &y);
        assert_eq!(pairs_of(&merged), c.arr()[2].pairs(), "x {x:?} y {y:?}");
        // Upstream returns `x` itself (no copy) when `y` is empty.
        assert_eq!(
            matches!(merged, std::borrow::Cow::Borrowed(_)),
            y.is_empty()
        );
    }
}
