//! `MyTime.str2seconds` and `MyTime.seconds2str` (fail2ban/server/mytime.py).

use crate::error::ExprError;
use crate::expr::{Env, Scope, Value, parse};
use crate::num::{Num, f64_to_i64};
use std::cmp::Ordering;

/// Seconds in the average (Julian) year: `(365*3+366)*24*60*60/4`.
const YEAR: &str = "*31557600.0";
/// Seconds in a twelfth of that year: `(365*3+366)*24*60*60/4/12`.
const MONTH: &str = "*2629800.0";

/// `(alternatives in regex preference order, replacement)`, in upstream
/// `_str2sec_parts` order. Each alternative list is the expansion of the
/// upstream pattern, e.g. `days?|da|dd?` -> days, day, da, dd, d.
const PARTS: [(&[&str], &str); 7] = [
    (&["days", "day", "da", "dd", "d"], "*86400"),
    (&["weeks", "week", "wee", "we", "ww", "w"], "*604800"),
    (&["months", "month", "mon", "mo"], MONTH),
    (&["years", "year", "yea", "ye", "yy", "y"], YEAR),
    (&["seconds", "second", "sec", "se", "ss", "s"], "*1"),
    (&["minutes", "minute", "min", "mi", "mm", "m"], "*60"),
    (&["hours", "hour", "hou", "ho", "hh", "h"], "*3600"),
];

/// Python `str.isspace()` (= `\s` in `re` for `str` patterns).
pub(crate) fn py_isspace(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\x0b' | '\x0c' | '\r' | '\x1c'..='\x1f' | ' ' | '\u{85}' | '\u{a0}'
            | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}'
            | '\u{205f}' | '\u{3000}'
    )
}

/// Case folding of `re.IGNORECASE` restricted to what can match an ASCII
/// letter: besides ASCII case, `ſ`~`s`, `ı`/`İ`~`i`, `K` (Kelvin sign)~`k`.
fn fold(c: char) -> char {
    match c {
        '\u{17f}' => 's',
        '\u{131}' | '\u{130}' => 'i',
        '\u{212a}' => 'k',
        c => c.to_ascii_lowercase(),
    }
}

/// `\w` (Unicode): alphanumeric or underscore.
fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// `(?i)(?<=[a-z])(\d)` -> ` \1`
fn prep(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    let mut prev: Option<char> = None;
    for c in s.chars() {
        if c.is_ascii_digit() && prev.is_some_and(|p| fold(p).is_ascii_lowercase()) {
            out.push(' ');
        }
        out.push(c);
        prev = Some(c);
    }
    out
}

fn match_unit(ch: &[char], i: usize, alts: &[&str]) -> Option<usize> {
    for lit in alts {
        let n = lit.len();
        if i + n <= ch.len()
            && lit.chars().zip(&ch[i..]).all(|(l, &c)| fold(c) == l)
            && ch.get(i + n).is_none_or(|&c| !is_word(c))
        {
            return Some(n);
        }
    }
    None
}

/// `(?i)(?<=[\d\s])(alts)\b` -> replacement
fn replace_unit(s: &str, alts: &[&str], rpl: &str) -> String {
    let ch: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len() + 8);
    let mut i = 0;
    while i < ch.len() {
        if i > 0 && (ch[i - 1].is_ascii_digit() || py_isspace(ch[i - 1])) {
            if let Some(n) = match_unit(&ch, i, alts) {
                out.push_str(rpl);
                i += n;
                continue;
            }
        }
        out.push(ch[i]);
        i += 1;
    }
    out
}

/// `(\d)\s+(\d)` -> `\1+\2` (non-overlapping, left to right)
fn fini(s: &str) -> String {
    let ch: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < ch.len() {
        if ch[i].is_ascii_digit() {
            let mut j = i + 1;
            while j < ch.len() && py_isspace(ch[j]) {
                j += 1;
            }
            if j > i + 1 && j < ch.len() && ch[j].is_ascii_digit() {
                out.push(ch[i]);
                out.push('+');
                out.push(ch[j]);
                i = j + 1;
                continue;
            }
        }
        out.push(ch[i]);
        i += 1;
    }
    out
}

/// Port of `MyTime.str2seconds` for string input.
///
/// Rewrites time-unit abbreviations into arithmetic exactly like upstream's
/// regex pipeline and evaluates the result: `"1h 30m"` -> `Int(5400)`,
/// `"1month"` -> `Float(2629800.0)`, `"600"` -> `Int(600)`, `"-1"` -> `Int(-1)`.
/// (Upstream returns already-numeric inputs unchanged; callers holding a
/// number just use [`Num`] directly.)
///
/// # Errors
/// Whenever Python's `eval` of the rewritten text raises, and also for
/// everything outside the pure-arithmetic subset documented in the crate
/// docs (names, calls, strings, tuples, results that are not numbers) and
/// integers beyond `i64`.
pub fn str2seconds(val: &str) -> Result<Num, ExprError> {
    let mut s = prep(val);
    for (alts, rpl) in PARTS {
        s = replace_unit(&s, alts, rpl);
    }
    let s = fini(&s);
    match parse(&s, Scope::Pure, true)?.eval(&Env::EMPTY)? {
        Value::Bool(_) => Err(ExprError::Type("expression result is not a number".into())),
        v => Ok(v.num()),
    }
}

/// Port of `str(MyTime.seconds2str(secs))`: `86400*390` -> `"1y 3w 4d"`.
///
/// # Errors
/// Infinite values and values whose rounded unit count does not fit `i64`
/// (Python raises `OverflowError` for infinity and prints a bignum for huge
/// finite floats; the latter is unsupported here).
pub fn seconds2str(sec: Num) -> Result<String, ExprError> {
    let ge = |n: i64| {
        matches!(
            sec.py_cmp(Num::Int(n)),
            Some(Ordering::Greater | Ordering::Equal)
        )
    };
    let rounded = |unit: f64| f64_to_i64((sec.as_f64() / unit).round_ties_even());
    if ge(31_536_000) {
        let mut s = rounded(86400.0)?;
        let mut r = format!("{}y ", s / 365);
        s %= 365;
        if s >= 7 {
            r += &format!("{}w ", s / 7);
            s %= 7;
        }
        if s != 0 {
            r += &format!("{s}d ");
        }
        r.pop();
        return Ok(r);
    }
    if ge(604_800) {
        let mut s = rounded(3600.0)?;
        let mut r = format!("{}w ", s / 168);
        s %= 168;
        if s >= 24 {
            r += &format!("{}d ", s / 24);
            s %= 24;
        }
        if s != 0 {
            r += &format!("{s}h ");
        }
        r.pop();
        return Ok(r);
    }
    if ge(86400) {
        let mut s = rounded(60.0)?;
        let mut r = format!("{}d ", s / 1440);
        s %= 1440;
        if s >= 60 {
            r += &format!("{}h ", s / 60);
            s %= 60;
        }
        if s != 0 {
            r += &format!("{s}m ");
        }
        r.pop();
        return Ok(r);
    }
    if ge(3595) {
        let mut s = rounded(10.0)?;
        let mut r = format!("{}h ", s / 360);
        s %= 360;
        if s >= 6 {
            r += &format!("{}m ", s / 6);
        }
        r.pop();
        return Ok(r);
    }
    let mut r = String::new();
    let mut s = sec;
    if ge(60) {
        r += &format!("{}m ", s.floordiv(Num::Int(60))?);
        s = s.modulo(Num::Int(60))?;
    }
    if s.is_truthy() {
        r += &format!("{s}s ");
    } else if !sec.is_truthy() {
        r = "0 ".into();
    }
    r.pop();
    Ok(r)
}
