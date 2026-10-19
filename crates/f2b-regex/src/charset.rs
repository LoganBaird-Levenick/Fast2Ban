//! Code point sets: Python's `\d \s \w` definitions and class emission for the
//! Rust engines.

use std::borrow::Cow;
use std::fmt::Write;
use std::sync::LazyLock;

use f2b_helpers::pychar::is_word;

use crate::pyast::{Cat, SetItem};

pub(crate) type Ranges = Vec<(u32, u32)>;

const MAX_CP: u32 = 0x10_FFFF;
const SURROGATES: (u32, u32) = (0xD800, 0xDFFF);

/// Sort, merge and drop surrogates (no Rust `str` can contain them).
pub(crate) fn normalize(ranges: &mut Ranges) {
    let mut cut: Ranges = Vec::with_capacity(ranges.len());
    for &(lo, hi) in ranges.iter() {
        if hi < SURROGATES.0 || lo > SURROGATES.1 {
            cut.push((lo, hi));
        } else {
            if lo < SURROGATES.0 {
                cut.push((lo, SURROGATES.0 - 1));
            }
            if hi > SURROGATES.1 {
                cut.push((SURROGATES.1 + 1, hi));
            }
        }
    }
    cut.sort_unstable();
    let mut merged: Ranges = Vec::with_capacity(cut.len());
    for (lo, hi) in cut {
        match merged.last_mut() {
            Some(last) if lo <= last.1.saturating_add(1) => last.1 = last.1.max(hi),
            _ => merged.push((lo, hi)),
        }
    }
    *ranges = merged;
}

/// Complement within the valid scalar values (normalised input).
pub(crate) fn complement(ranges: &[(u32, u32)]) -> Ranges {
    let mut out: Ranges = Vec::with_capacity(ranges.len() + 1);
    let mut next = 0u32;
    for &(lo, hi) in ranges {
        if lo > next {
            out.push((next, lo - 1));
        }
        next = hi + 1;
    }
    if next <= MAX_CP {
        out.push((next, MAX_CP));
    }
    normalize(&mut out);
    out
}

fn from_pred(pred: impl Fn(char) -> bool) -> Ranges {
    let mut out: Ranges = Vec::new();
    let mut start: Option<u32> = None;
    for cp in 0..=MAX_CP {
        let inside = char::from_u32(cp).is_some_and(&pred);
        match (inside, start) {
            (true, None) => start = Some(cp),
            (false, Some(s)) => {
                out.push((s, cp - 1));
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        out.push((s, MAX_CP));
    }
    out
}

/// `\s` (`str.isspace()`); checked against `pychar::is_space` in tests.
const SPACE: &[(u32, u32)] = &[
    (0x9, 0xd),
    (0x1c, 0x20),
    (0x85, 0x85),
    (0xa0, 0xa0),
    (0x1680, 0x1680),
    (0x2000, 0x200a),
    (0x2028, 0x2029),
    (0x202f, 0x202f),
    (0x205f, 0x205f),
    (0x3000, 0x3000),
];

static WORD: LazyLock<Ranges> = LazyLock::new(|| from_pred(is_word));
static DIGIT: LazyLock<Ranges> = LazyLock::new(unicode_nd);

/// `\p{Nd}` of the `regex` crate (Python's `\d` is `str.isdecimal()`).
fn unicode_nd() -> Ranges {
    use regex_syntax::hir::{Class, HirKind};
    let hir = regex_syntax::Parser::new()
        .parse(r"\p{Nd}")
        .expect("\\p{Nd} is a valid pattern");
    match hir.kind() {
        HirKind::Class(Class::Unicode(cls)) => cls
            .iter()
            .map(|r| (u32::from(r.start()), u32::from(r.end())))
            .collect(),
        other => unreachable!("\\p{{Nd}} parsed to {other:?}"),
    }
}

const ASCII_DIGIT: &[(u32, u32)] = &[(0x30, 0x39)];
const ASCII_NOT_DIGIT: &[(u32, u32)] = &[(0, 0x2f), (0x3a, MAX_CP)];
const ASCII_SPACE: &[(u32, u32)] = &[(9, 13), (32, 32)];
const ASCII_NOT_SPACE: &[(u32, u32)] = &[(0, 8), (14, 31), (33, MAX_CP)];
const ASCII_WORD: &[(u32, u32)] = &[(0x30, 0x39), (0x41, 0x5a), (0x5f, 0x5f), (0x61, 0x7a)];
const ASCII_NOT_WORD: &[(u32, u32)] = &[
    (0, 0x2f),
    (0x3a, 0x40),
    (0x5b, 0x5e),
    (0x60, 0x60),
    (0x7b, MAX_CP),
];

/// Ranges of a category, Unicode or (`(?a)`) ASCII definition.
pub(crate) fn category(cat: Cat, ascii: bool) -> Cow<'static, [(u32, u32)]> {
    if ascii {
        return Cow::Borrowed(match cat {
            Cat::Digit => ASCII_DIGIT,
            Cat::NotDigit => ASCII_NOT_DIGIT,
            Cat::Space => ASCII_SPACE,
            Cat::NotSpace => ASCII_NOT_SPACE,
            Cat::Word => ASCII_WORD,
            Cat::NotWord => ASCII_NOT_WORD,
        });
    }
    match cat {
        Cat::Digit => Cow::Borrowed(&DIGIT),
        Cat::NotDigit => Cow::Owned(complement(&DIGIT)),
        Cat::Space => Cow::Borrowed(SPACE),
        Cat::NotSpace => Cow::Owned(complement(SPACE)),
        Cat::Word => Cow::Borrowed(&WORD),
        Cat::NotWord => Cow::Owned(complement(&WORD)),
    }
}

/// Union of the members of a set (normalised).
pub(crate) fn set_ranges(items: &[SetItem], ascii: bool) -> Ranges {
    let mut out: Ranges = Vec::new();
    for item in items {
        match *item {
            SetItem::Lit(c) => out.push((c, c)),
            SetItem::Range(lo, hi) => out.push((lo, hi)),
            SetItem::Cat(cat) => out.extend_from_slice(&category(cat, ascii)),
        }
    }
    normalize(&mut out);
    out
}

/// Python's `(?i)` also equates `i`, `I`, `ı` (U+0131) and `İ` (U+0130)
/// (`_casefix`), which Rust's simple case folding does not: close a set of
/// literal members over that class.
pub(crate) fn turkic_close(ranges: &mut Ranges) {
    const CLASS: [u32; 4] = [0x49, 0x69, 0x130, 0x131];
    if ranges
        .iter()
        .any(|&(lo, hi)| CLASS.iter().any(|c| (lo..=hi).contains(c)))
    {
        ranges.extend(CLASS.iter().map(|&c| (c, c)));
        normalize(ranges);
    }
}

/// Appends the class for a Python set `[items]` / `[^items]`.
///
/// `\w` and `\d` are emitted as Unicode properties (`\p{L}\p{N}_` and `\p{Nd}`
/// are exactly Python's `str.isalnum() or '_'` and `str.isdecimal()` in Unicode
/// 16; checked by the test-suite), everything else as explicit ranges.
pub(crate) fn push_set(out: &mut String, items: &[SetItem], negate: bool, ascii: bool) {
    let mut items = items;
    let single;
    let mut negate = negate;
    // `[\W]` is `[^\w]`, `[^\D]` is `[\d]`...
    if let [SetItem::Cat(cat)] = items {
        let (positive, flipped) = match cat {
            Cat::NotDigit => (Cat::Digit, true),
            Cat::NotSpace => (Cat::Space, true),
            Cat::NotWord => (Cat::Word, true),
            other => (*other, false),
        };
        if flipped {
            single = [SetItem::Cat(positive)];
            items = &single;
            negate = !negate;
        }
    }
    let negative_cat = items.iter().any(|i| {
        matches!(
            i,
            SetItem::Cat(Cat::NotDigit | Cat::NotSpace | Cat::NotWord)
        )
    });
    if ascii || negative_cat {
        let ranges = set_ranges(items, ascii);
        push_class(out, &ranges, negate);
        return;
    }
    let mut ranges: Ranges = Vec::new();
    let mut props = String::new();
    for item in items {
        match *item {
            SetItem::Lit(c) => ranges.push((c, c)),
            SetItem::Range(lo, hi) => ranges.push((lo, hi)),
            SetItem::Cat(Cat::Digit) => props.push_str(r"\p{Nd}"),
            SetItem::Cat(Cat::Word) => props.push_str(r"\p{L}\p{N}_"),
            SetItem::Cat(Cat::Space) => ranges.extend_from_slice(SPACE),
            SetItem::Cat(_) => unreachable!("negative categories handled above"),
        }
    }
    normalize(&mut ranges);
    if ranges.is_empty() && props.is_empty() {
        out.push_str(if negate { ANY_CHAR } else { NEVER });
        return;
    }
    out.push('[');
    if negate {
        out.push('^');
    }
    push_ranges(out, &ranges);
    out.push_str(&props);
    out.push(']');
}

/// Adds the other case of every ASCII letter in `ranges` (`(?ai)` folding).
pub(crate) fn ascii_fold(ranges: &mut Ranges) {
    let mut extra: Ranges = Vec::new();
    for &(lo, hi) in ranges.iter() {
        let (l, h) = (lo.max(0x41), hi.min(0x5a));
        if l <= h {
            extra.push((l + 0x20, h + 0x20));
        }
        let (l, h) = (lo.max(0x61), hi.min(0x7a));
        if l <= h {
            extra.push((l - 0x20, h - 0x20));
        }
    }
    ranges.extend(extra);
    normalize(ranges);
}

/// Simple case folding closure (`regex-syntax`), the semantics of Rust's `(?i)`.
fn fold_simple(ranges: &Ranges) -> Ranges {
    use regex_syntax::hir::{ClassUnicode, ClassUnicodeRange};
    let chars: Vec<ClassUnicodeRange> = ranges
        .iter()
        .filter_map(|&(lo, hi)| {
            Some(ClassUnicodeRange::new(
                char::from_u32(lo)?,
                char::from_u32(hi)?,
            ))
        })
        .collect();
    let mut class = ClassUnicode::new(chars);
    class.case_fold_simple();
    class
        .iter()
        .map(|r| (u32::from(r.start()), u32::from(r.end())))
        .collect()
}

/// `(?i)[...]` / `(?i)[^...]` with Python semantics: the literal members are
/// closed under case folding, category members (`\w`...) are not, then the
/// set is negated. Emitted under `(?-i:...)` so the engine folds nothing more
/// (Rust would fold the categories too, e.g. `\w` gains U+0345).
pub(crate) fn push_set_icase(out: &mut String, items: &[SetItem], negate: bool) {
    let mut lits: Ranges = items
        .iter()
        .filter_map(|i| match *i {
            SetItem::Lit(c) => Some((c, c)),
            SetItem::Range(lo, hi) => Some((lo, hi)),
            SetItem::Cat(_) => None,
        })
        .collect();
    normalize(&mut lits);
    turkic_close(&mut lits);
    let mut ranges = fold_simple(&lits);
    for item in items {
        if let SetItem::Cat(cat) = item {
            ranges.extend_from_slice(&category(*cat, false));
        }
    }
    normalize(&mut ranges);
    out.push_str("(?-i:");
    push_class(out, &ranges, negate);
    out.push(')');
}

/// A pattern that can never match.
pub(crate) const NEVER: &str = r"[^\x{0}-\x{10FFFF}]";
/// A pattern matching any one character.
pub(crate) const ANY_CHAR: &str = r"(?s:.)";

fn class_safe(cp: u32) -> bool {
    char::from_u32(cp).is_some_and(|c| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                ' ' | '!' | '"' | '%' | '\'' | ',' | '/' | ':' | ';' | '<' | '=' | '>' | '@' | '_'
            )
    })
}

fn push_class_cp(out: &mut String, cp: u32) {
    if class_safe(cp) {
        out.push(char::from_u32(cp).unwrap_or('?'));
    } else {
        let _ = write!(out, "\\x{{{cp:X}}}");
    }
}

fn push_ranges(out: &mut String, ranges: &[(u32, u32)]) {
    for &(lo, hi) in ranges {
        push_class_cp(out, lo);
        if hi != lo {
            if hi != lo + 1 {
                out.push('-');
            }
            push_class_cp(out, hi);
        }
    }
}

/// Appends `[...]` for `ranges` (normalised); empty sets map to
/// [`NEVER`] / [`ANY_CHAR`].
pub(crate) fn push_class(out: &mut String, ranges: &[(u32, u32)], negate: bool) {
    if ranges.is_empty() {
        out.push_str(if negate { ANY_CHAR } else { NEVER });
        return;
    }
    out.push('[');
    if negate {
        out.push('^');
    }
    push_ranges(out, ranges);
    out.push(']');
}

/// Appends one literal code point (outside of a class).
pub(crate) fn push_literal(out: &mut String, cp: u32) {
    let Some(c) = char::from_u32(cp) else {
        out.push_str(NEVER);
        return;
    };
    match c {
        '\\' | '.' | '+' | '*' | '?' | '(' | ')' | '|' | '[' | ']' | '{' | '}' | '^' | '$'
        | '#' | '&' | '-' | '~' => {
            out.push('\\');
            out.push(c);
        }
        c if c.is_ascii_alphanumeric() || class_safe(cp) => out.push(c),
        c if !c.is_ascii() && c.is_alphanumeric() => out.push(c),
        _ => {
            let _ = write!(out, "\\x{{{cp:X}}}");
        }
    }
}

/// Value of a decimal digit (`unicodedata.decimal`): each `Nd` range starts at
/// a zero and holds whole runs of ten digits.
fn decimal_value(c: char) -> Option<u32> {
    let cp = u32::from(c);
    let digits = &*DIGIT;
    let i = digits.partition_point(|&(_, hi)| hi < cp);
    let &(lo, hi) = digits.get(i)?;
    (lo <= cp && cp <= hi).then(|| (cp - lo) % 10)
}

/// `int(s)` for a `str`, saturating at the `i64` range: surrounding
/// whitespace, one sign, Unicode decimal digits with single `_` between them.
/// `None` where Python raises `ValueError`.
pub(crate) fn py_int(s: &str) -> Option<i64> {
    let s = f2b_helpers::pychar::strip(s);
    let (negative, digits) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    let mut value: i64 = 0;
    let mut previous_digit = false;
    for c in digits.chars() {
        if c == '_' {
            if !previous_digit {
                return None;
            }
            previous_digit = false;
            continue;
        }
        let d = decimal_value(c)?;
        value = value.saturating_mul(10).saturating_add(i64::from(d));
        previous_digit = true;
    }
    if !previous_digit {
        return None;
    }
    Some(if negative { -value } else { value })
}
