//! `extractOptions` / `splitWithOptions` (option syntax `name[k=v, k2="v2"][k3='v3']`).
//!
//! The upstream regular expressions (`OPTION_CRE`, `OPTION_EXTRACT_CRE`,
//! `OPTION_SPLIT_CRE`) are executed by Python's backtracking engine; the matchers here
//! are hand-written equivalents that follow the same priority order, so they pick the
//! same match (and report the same error offsets) on every input.

use crate::pychar::{is_space, is_word, repr_str, strip};
use indexmap::IndexMap;
use std::fmt;

/// Error of [`extract_options`]; `Display` is upstream's `ValueError` message.
///
/// Offsets are character (code point) offsets into the text between the outer
/// brackets, as in Python.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OptionError {
    /// `unexpected option syntax`: the whole value does not look like `name[...]`.
    UnexpectedOptionSyntax,
    /// `unexpected syntax at N after option 'X': ...`
    UnexpectedSyntaxAfterOption {
        /// Offset of the offending text.
        pos: usize,
        /// Name of the option preceding the offending text.
        option: String,
        /// Up to 25 characters of the offending text.
        excerpt: String,
    },
    /// `expected option, wrong syntax at N: ...`
    ExpectedOption {
        /// Offset of the offending text.
        pos: usize,
        /// Up to 25 characters of the offending text.
        excerpt: String,
    },
}

impl fmt::Display for OptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedOptionSyntax => f.write_str("unexpected option syntax"),
            Self::UnexpectedSyntaxAfterOption {
                pos,
                option,
                excerpt,
            } => write!(
                f,
                "unexpected syntax at {pos} after option {}: {excerpt}",
                repr_str(option)
            ),
            Self::ExpectedOption { pos, excerpt } => {
                write!(f, "expected option, wrong syntax at {pos}: {excerpt}")
            }
        }
    }
}

impl std::error::Error for OptionError {}

/// Character of an option name: `[\w\-_\.]`.
fn is_name_char(c: char) -> bool {
    is_word(c) || c == '-' || c == '.'
}

/// First 25 characters (Python `s[0:25]`).
fn excerpt(s: &str) -> String {
    s.chars().take(25).collect()
}

/// Length in bytes of the leading run of characters satisfying `pred`.
fn run_len(s: &str, pred: impl Fn(char) -> bool) -> usize {
    s.find(|c| !pred(c)).unwrap_or(s.len())
}

/// `OPTION_CRE`: `^([^\[]+)(?:\[(.*)\])?\s*$` (DOTALL) as `(name, option string)`.
fn split_name(option: &str) -> Option<(&str, &str)> {
    let Some(open) = option.find('[') else {
        return (!option.is_empty()).then_some((option, ""));
    };
    if open == 0 {
        return None;
    }
    // `.*` is greedy, so the closing bracket is the last non-space character.
    let trimmed = option.trim_end_matches(is_space);
    let close = trimmed.len().checked_sub(1)?;
    (trimmed.ends_with(']') && close > open).then(|| (&option[..open], &option[open + 1..close]))
}

/// One successful `OPTION_EXTRACT_CRE` first alternative.
struct Parsed<'a> {
    name: &'a str,
    value: &'a str,
    /// Byte offset (relative to the input of `parse_option`) where the match ends.
    end: usize,
}

/// First alternative of `OPTION_EXTRACT_CRE` at the start of `rest`:
/// `\s*(NAME)=(?:"([^"]*)"|'([^']*)'|([^,\]]*))(?:,|\]\s*\[|$|(?P<wrngA>.+))`.
///
/// `Ok(None)` means the alternative does not match at all; `Err` carries the
/// `wrngA` case (`pos_base` is the character offset of `rest` in the option string).
fn parse_option(rest: &str, pos_base: usize) -> Result<Option<Parsed<'_>>, OptionError> {
    let lead = run_len(rest, is_space);
    let t = &rest[lead..];
    // NAME = [\w\-_\.]+(?:\?[\w\-_\.]+=[\w\-_\.]+)?, followed by '='. The name
    // characters exclude '?' and '=', so the greedy runs cannot backtrack usefully.
    let first = run_len(t, is_name_char);
    if first == 0 {
        return Ok(None);
    }
    let mut name_end = first;
    if t[first..].starts_with('?') {
        let second = run_len(&t[first + 1..], is_name_char);
        let eq = first + 1 + second;
        if second == 0 || !t[eq..].starts_with('=') {
            return Ok(None);
        }
        let third = run_len(&t[eq + 1..], is_name_char);
        if third == 0 {
            return Ok(None);
        }
        name_end = eq + 1 + third;
    }
    if !t[name_end..].starts_with('=') {
        return Ok(None);
    }
    let name = &t[..name_end];
    let vstart = name_end + 1;
    let v = &t[vstart..];
    // Value alternatives in order: "...", '...', [^,\]]*. A quoted alternative only
    // applies when closed; the last one always matches.
    let quoted = ['"', '\''].into_iter().find_map(|q| {
        let inner = v.strip_prefix(q)?;
        let len = inner.find(q)?;
        Some((&inner[..len], 1 + len + 1))
    });
    let (value, vlen) = quoted.unwrap_or_else(|| {
        let len = run_len(v, |c| c != ',' && c != ']');
        (&v[..len], len)
    });
    let after = vstart + vlen;
    let tail = &t[after..];
    // (?:,|\]\s*\[|$|(?P<wrngA>.+)); `$` also matches just before a final newline.
    let sep = if tail.starts_with(',') {
        1
    } else if let Some(r) = tail.strip_prefix(']')
        && r.trim_start_matches(is_space).starts_with('[')
    {
        tail.len() - r.trim_start_matches(is_space).len() + 1
    } else if tail.is_empty() || tail == "\n" {
        0
    } else {
        let pos = pos_base + rest[..lead + after].chars().count();
        return Err(OptionError::UnexpectedSyntaxAfterOption {
            pos,
            option: name.to_owned(),
            excerpt: excerpt(tail),
        });
    };
    Ok(Some(Parsed {
        name,
        value,
        end: lead + after + sep,
    }))
}

/// `helpers.extractOptions`: splits `name[k1=v1, k2="v2"][k3='v3']` into the name and
/// the options in order of first appearance (a repeated key keeps its first position
/// and takes the last value).
///
/// The name is returned verbatim (not stripped), values are stripped of surrounding
/// whitespace and of their quotes.
///
/// # Errors
/// The three `ValueError` cases of upstream; see [`OptionError`].
pub fn extract_options(option: &str) -> Result<(String, IndexMap<String, String>), OptionError> {
    let (name, optstr) = split_name(option).ok_or(OptionError::UnexpectedOptionSyntax)?;
    let mut opts = IndexMap::new();
    let mut pos = 0;
    let mut char_pos = 0;
    while pos < optstr.len() {
        let rest = &optstr[pos..];
        if let Some(m) = parse_option(rest, char_pos)? {
            opts.insert(strip(m.name).to_owned(), strip(m.value).to_owned());
            char_pos += rest[..m.end].chars().count();
            pos += m.end;
            continue;
        }
        // `,?\s*$`: only an optional comma and whitespace left.
        let tail = rest.strip_prefix(',').unwrap_or(rest);
        if tail.chars().all(is_space) {
            break;
        }
        return Err(OptionError::ExpectedOption {
            pos: char_pos,
            excerpt: excerpt(rest),
        });
    }
    Ok((name.to_owned(), opts))
}

/// Continuation of the backtracking matcher: receives a candidate end position and
/// reports whether the rest of the pattern matches from there.
type Cont<'k> = &'k mut dyn FnMut(usize) -> bool;

/// Backtracking matcher for `OPTION_SPLIT_CRE`:
///
/// ```text
/// (?: [^\[\s]+ (?: \s*\[\s* (?: NAME=(?:"[^"]*"|'[^']*'|[^,\]]*) \s*(?:,|\]\s*\[)?\s* )* \] )? \s*
///   | \S+ )
/// (?= \n\s* | \s+ | $ )
/// ```
///
/// Every greedy construct tries its candidates longest first, exactly as the
/// regular expression engine does, so the first complete match is the same.
struct Splitter<'a> {
    s: &'a str,
}

impl Splitter<'_> {
    fn ch(&self, p: usize) -> Option<char> {
        self.s[p..].chars().next()
    }

    /// Start of the character preceding byte offset `p` (`p > 0`).
    fn prev(&self, p: usize) -> usize {
        p - self.s[..p].chars().next_back().map_or(1, char::len_utf8)
    }

    /// `(?=\n\s*|\s+|$)`: end of input or any whitespace character.
    fn lookahead(&self, p: usize) -> bool {
        self.ch(p).is_none_or(is_space)
    }

    /// Greedy `X*` over characters satisfying `pred`, trying the longest run first.
    fn star(&self, p: usize, pred: impl Fn(char) -> bool, k: Cont<'_>) -> bool {
        let mut e = p + run_len(&self.s[p..], pred);
        loop {
            if k(e) {
                return true;
            }
            if e == p {
                return false;
            }
            e = self.prev(e);
        }
    }

    fn ws_star(&self, p: usize, k: Cont<'_>) -> bool {
        self.star(p, is_space, k)
    }

    /// Match of `NAME=` at `p` (see `parse_option` for why this is deterministic):
    /// the end offset after the `=`.
    fn name_eq(&self, p: usize) -> Option<usize> {
        let t = &self.s[p..];
        let first = run_len(t, is_name_char);
        if first == 0 {
            return None;
        }
        let mut end = first;
        if t[first..].starts_with('?') {
            let second = run_len(&t[first + 1..], is_name_char);
            let eq = first + 1 + second;
            if second == 0 || !t[eq..].starts_with('=') {
                return None;
            }
            let third = run_len(&t[eq + 1..], is_name_char);
            if third == 0 {
                return None;
            }
            end = eq + 1 + third;
        }
        t[end..].starts_with('=').then_some(p + end + 1)
    }

    /// `\s*(?:,|\]\s*\[)?\s*` followed by `k`.
    fn separator(&self, p: usize, k: Cont<'_>) -> bool {
        self.ws_star(p, &mut |a| {
            match self.ch(a) {
                Some(',') if self.ws_star(a + 1, k) => return true,
                Some(']')
                    if self.ws_star(a + 1, &mut |b| {
                        self.ch(b) == Some('[') && self.ws_star(b + 1, k)
                    }) =>
                {
                    return true;
                }
                _ => {}
            }
            self.ws_star(a, k)
        })
    }

    /// One option: `NAME=(?:"[^"]*"|'[^']*'|[^,\]]*)` and its separator.
    fn item(&self, p: usize, k: Cont<'_>) -> bool {
        let Some(v) = self.name_eq(p) else {
            return false;
        };
        for q in ['"', '\''] {
            if let Some(inner) = self.s[v..].strip_prefix(q)
                && let Some(len) = inner.find(q)
                && self.separator(v + 1 + len + 1, k)
            {
                return true;
            }
        }
        self.star(v, |c| c != ',' && c != ']', &mut |e| self.separator(e, k))
    }

    /// All ends of one `ITEM` at `p`, in the engine's priority order.
    fn item_ends(&self, p: usize) -> Vec<usize> {
        let mut ends = Vec::new();
        self.item(p, &mut |q| {
            ends.push(q);
            false
        });
        ends
    }

    /// `(?:ITEM)*` (greedy), then `k`.
    ///
    /// Depth-first over "take another ITEM, else stop here", exactly the engine's order,
    /// but with an explicit stack (an entry can hold thousands of options) and with
    /// positions that already failed remembered: what follows the star depends only on
    /// the position, so a failed position fails again.
    fn items(&self, p: usize, k: Cont<'_>) -> bool {
        struct Frame {
            pos: usize,
            ends: Vec<usize>,
            next: usize,
        }
        let mut failed = std::collections::HashSet::new();
        let mut stack = vec![Frame {
            pos: p,
            ends: self.item_ends(p),
            next: 0,
        }];
        while let Some(top) = stack.last_mut() {
            if let Some(&q) = top.ends.get(top.next) {
                top.next += 1;
                if !failed.contains(&q) {
                    stack.push(Frame {
                        pos: q,
                        ends: self.item_ends(q),
                        next: 0,
                    });
                }
            } else if k(top.pos) {
                return true;
            } else {
                failed.insert(top.pos);
                stack.pop();
            }
        }
        false
    }

    /// `\s*\[\s*(?:ITEM)*\]`, then `k`.
    fn options(&self, p: usize, k: Cont<'_>) -> bool {
        self.ws_star(p, &mut |a| {
            self.ch(a) == Some('[')
                && self.ws_star(a + 1, &mut |b| {
                    self.items(b, &mut |c| self.ch(c) == Some(']') && k(c + 1))
                })
        })
    }

    /// End of the match starting exactly at `i`, if any.
    fn match_at(&self, i: usize) -> Option<usize> {
        let end = std::cell::Cell::new(None);
        let mut finish = |r: usize| {
            let ok = self.lookahead(r);
            if ok {
                end.set(Some(r));
            }
            ok
        };
        // First alternative: `[^\[\s]+` tried from the longest run down to one char.
        let run = i + run_len(&self.s[i..], |c| c != '[' && !is_space(c));
        let mut e = run;
        while e > i {
            if self.options(e, &mut |q| self.ws_star(q, &mut finish)) {
                return end.get();
            }
            if self.ws_star(e, &mut finish) {
                return end.get();
            }
            e = self.prev(e);
        }
        // Second alternative: `\S+`.
        let mut e = i + run_len(&self.s[i..], |c| !is_space(c));
        while e > i {
            if finish(e) {
                return end.get();
            }
            e = self.prev(e);
        }
        None
    }
}

/// `helpers.splitWithOptions`: splits a (possibly multi-line) list of
/// `name[options]` entries on whitespace/newlines, keeping whitespace and newlines
/// inside the option brackets and quotes. Mirrors `OPTION_SPLIT_CRE.findall`,
/// including its quirk that an entry may carry trailing whitespace when several
/// whitespace characters separate it from the next one.
#[must_use]
pub fn split_with_options(option: &str) -> Vec<String> {
    let sp = Splitter { s: option };
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some(c) = sp.ch(pos) {
        if !is_space(c)
            && let Some(end) = sp.match_at(pos)
        {
            out.push(option[pos..end].to_owned());
            pos = end;
        } else {
            pos += c.len_utf8();
        }
    }
    out
}
