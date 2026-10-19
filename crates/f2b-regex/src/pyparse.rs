//! Port of CPython 3.14 `re/_parser.py` (plus the error conditions of
//! `re/_compiler.py`) for `str` patterns.
//!
//! The parser accepts and rejects exactly what `re.compile` does, with the same
//! error messages and positions, so that construction errors of
//! [`crate::Regex`] equal upstream's. Pieces of CPython that only optimise
//! (common-prefix hoisting, set merging, unpacking of plain groups) are not
//! ported: they do not change what matches.
//!
//! Deliberate differences:
//! * `\N{NAME}` uses the `unicode_names2` database (a newer Unicode version
//!   than Python 3.14's 16.0 may know more names).
//! * Nesting deeper than [`MAX_NESTING`] is rejected (CPython raises
//!   `RecursionError` at a comparable depth).

use std::collections::HashMap;

use f2b_helpers::pychar::repr_str;

use crate::pyast::{
    At, Cat, Flags, GroupWidths, MAXREPEAT, Node, RepeatKind, SetItem, Width, check_lookbehind,
    width,
};

/// Maximum group/lookaround nesting accepted by the parser.
pub(crate) const MAX_NESTING: usize = 200;

/// `_sre.MAXGROUPS`.
const MAXGROUPS: usize = 1_073_741_823;

/// An error raised while parsing / compiling a Python pattern.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PyReError {
    /// `re.error.msg`.
    pub msg: String,
    /// `re.error.pos` (character index into the pattern), if any.
    pub pos: Option<i64>,
    /// `str(exception)`: message with position and line/column.
    pub text: String,
}

impl PyReError {
    fn plain(msg: impl Into<String>) -> PyReError {
        let msg = msg.into();
        PyReError {
            text: msg.clone(),
            msg,
            pos: None,
        }
    }

    /// `re.error(msg, pattern, pos)`.
    fn at(msg: impl Into<String>, pattern: &[char], pos: i64) -> PyReError {
        let msg = msg.into();
        let mut text = format!("{msg} at position {pos}");
        if pattern.contains(&'\n') {
            // `pattern.count("\n", 0, pos) + 1` and `pos - pattern.rfind("\n", 0, pos)`.
            let end = clamp_index(pos, pattern.len());
            let lineno = pattern[..end].iter().filter(|&&c| c == '\n').count() + 1;
            let rfind = pattern[..end]
                .iter()
                .rposition(|&c| c == '\n')
                .map_or(-1, |i| i64::try_from(i).unwrap_or(-1));
            let colno = pos - rfind;
            text = format!("{text} (line {lineno}, column {colno})");
        }
        PyReError {
            msg,
            pos: Some(pos),
            text,
        }
    }
}

impl std::fmt::Display for PyReError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

impl std::error::Error for PyReError {}

/// Python slice-end normalisation (`s[:pos]` for a possibly negative `pos`).
fn clamp_index(pos: i64, len: usize) -> usize {
    let len_i = i64::try_from(len).unwrap_or(i64::MAX);
    let p = if pos < 0 { pos + len_i } else { pos };
    usize::try_from(p.clamp(0, len_i)).unwrap_or(len)
}

/// One token of `Tokenizer`: a plain character or a backslash escape pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Tok {
    ch: char,
    escaped: bool,
}

impl Tok {
    /// Length in characters (`len(token)`).
    fn len(self) -> i64 {
        if self.escaped { 2 } else { 1 }
    }

    fn text(self) -> String {
        if self.escaped {
            format!("\\{}", self.ch)
        } else {
            self.ch.to_string()
        }
    }

    fn is(self, c: char) -> bool {
        !self.escaped && self.ch == c
    }
}

struct Source<'p> {
    chars: &'p [char],
    index: usize,
    next: Option<Tok>,
}

type R<T> = Result<T, PyReError>;

impl<'p> Source<'p> {
    fn new(chars: &'p [char]) -> R<Source<'p>> {
        let mut s = Source {
            chars,
            index: 0,
            next: None,
        };
        s.advance()?;
        Ok(s)
    }

    /// `Tokenizer.__next`.
    fn advance(&mut self) -> R<()> {
        let Some(&c) = self.chars.get(self.index) else {
            self.next = None;
            return Ok(());
        };
        if c == '\\' {
            let Some(&e) = self.chars.get(self.index + 1) else {
                return Err(PyReError::at(
                    "bad escape (end of pattern)",
                    self.chars,
                    i64::try_from(self.chars.len()).unwrap_or(0) - 1,
                ));
            };
            self.index += 2;
            self.next = Some(Tok {
                ch: e,
                escaped: true,
            });
        } else {
            self.index += 1;
            self.next = Some(Tok {
                ch: c,
                escaped: false,
            });
        }
        Ok(())
    }

    fn matches(&mut self, c: char) -> R<bool> {
        if self.next.is_some_and(|t| t.is(c)) {
            self.advance()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn get(&mut self) -> R<Option<Tok>> {
        let this = self.next;
        self.advance()?;
        Ok(this)
    }

    /// `getwhile(n, charset)`: up to `n` plain characters satisfying `pred`.
    fn getwhile(&mut self, n: usize, pred: impl Fn(char) -> bool) -> R<String> {
        let mut result = String::new();
        for _ in 0..n {
            match self.next {
                Some(t) if !t.escaped && pred(t.ch) => {
                    result.push(t.ch);
                    self.advance()?;
                }
                _ => break,
            }
        }
        Ok(result)
    }

    fn getuntil(&mut self, terminator: char, name: &str) -> R<String> {
        let mut result = String::new();
        loop {
            let c = self.next;
            self.advance()?;
            let Some(c) = c else {
                if result.is_empty() {
                    return Err(self.error(format!("missing {name}"), 0));
                }
                return Err(self.error(
                    format!("missing {terminator}, unterminated name"),
                    result.chars().count() as i64,
                ));
            };
            if c.is(terminator) {
                if result.is_empty() {
                    return Err(self.error(format!("missing {name}"), 1));
                }
                break;
            }
            result.push_str(&c.text());
        }
        Ok(result)
    }

    /// `Tokenizer.tell()`.
    fn tell(&self) -> i64 {
        i64::try_from(self.index).unwrap_or(0) - self.next.map_or(0, Tok::len)
    }

    fn seek(&mut self, index: usize) -> R<()> {
        self.index = index;
        self.advance()
    }

    /// `Tokenizer.error(msg, offset)`.
    fn error(&self, msg: impl Into<String>, offset: i64) -> PyReError {
        PyReError::at(msg, self.chars, self.tell() - offset)
    }

    fn checkgroupname(&self, name: &str, offset: i64) -> R<()> {
        if !is_identifier(name) {
            let msg = format!("bad character in group name {}", repr_str(name));
            return Err(self.error(msg, name.chars().count() as i64 + offset));
        }
        Ok(())
    }
}

/// `str.isidentifier()`.
fn is_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c == '_' || unicode_ident::is_xid_start(c) => {}
        _ => return false,
    }
    chars.all(unicode_ident::is_xid_continue)
}

struct State {
    flags: Flags,
    groupdict: HashMap<String, usize>,
    /// `(name, group number)` in definition order.
    names: Vec<(String, usize)>,
    /// `groupwidths` (index 0 is group 0, always `None` here).
    groupwidths: Vec<Option<Width>>,
    lookbehindgroups: Option<usize>,
    grouprefpos: Vec<(usize, i64)>,
}

impl State {
    fn groups(&self) -> usize {
        self.groupwidths.len()
    }

    fn checkgroup(&self, gid: usize) -> bool {
        gid < self.groups() && self.groupwidths[gid].is_some()
    }

    fn checklookbehindgroup(&self, gid: usize, source: &Source<'_>) -> R<()> {
        if let Some(lb) = self.lookbehindgroups {
            if !self.checkgroup(gid) {
                return Err(source.error("cannot refer to an open group", 0));
            }
            if gid >= lb {
                return Err(source.error(
                    "cannot refer to group defined in the same lookbehind subpattern",
                    0,
                ));
            }
        }
        Ok(())
    }
}

/// Result of [`parse`].
#[derive(Debug)]
pub(crate) struct Parsed {
    pub nodes: Vec<Node>,
    /// Number of capture groups (group 0 excluded).
    pub groups: usize,
    /// `groupindex` as `(name, number)` in definition order.
    pub names: Vec<(String, usize)>,
    /// Global flags (`flags` argument ORed with `(?aiLmsux)` at the start).
    pub flags: Flags,
}

/// A decoded escape: what `_escape` / `_class_escape` return.
enum Code {
    Lit(u32),
    Cat(Cat),
    At(At),
    Backref(usize),
}

fn is_oct(c: char) -> bool {
    ('0'..='7').contains(&c)
}

fn is_hex(c: char) -> bool {
    c.is_ascii_hexdigit()
}

fn simple_escape(c: char) -> Option<u32> {
    Some(match c {
        'a' => 7,
        'b' => 8,
        'f' => 12,
        'n' => 10,
        'r' => 13,
        't' => 9,
        'v' => 11,
        '\\' => 92,
        _ => return None,
    })
}

fn category(c: char) -> Option<Cat> {
    Some(match c {
        'd' => Cat::Digit,
        'D' => Cat::NotDigit,
        's' => Cat::Space,
        'S' => Cat::NotSpace,
        'w' => Cat::Word,
        'W' => Cat::NotWord,
        _ => return None,
    })
}

fn at_code(c: char) -> Option<At> {
    Some(match c {
        'A' => At::BeginningString,
        'b' => At::Boundary,
        'B' => At::NonBoundary,
        'z' | 'Z' => At::EndString,
        _ => return None,
    })
}

/// `unicodedata.lookup(name)`: case-insensitive, otherwise exact. The
/// `unicode_names2` lookup follows UAX44-LM2 (ignores spaces, `_` and hyphens),
/// so a hit through a canonical name is only accepted when the spelling matches.
fn lookup_name(name: &str) -> Option<char> {
    let c = unicode_names2::character(name)?;
    let loose = |s: &str| -> String {
        s.chars()
            .filter(|c| !matches!(c, ' ' | '_' | '-'))
            .flat_map(char::to_lowercase)
            .collect()
    };
    match unicode_names2::name(c) {
        Some(canonical) => {
            let canonical = canonical.to_string();
            if loose(&canonical) == loose(name) && canonical.to_uppercase() != name.to_uppercase() {
                None
            } else {
                Some(c)
            }
        }
        None => Some(c),
    }
}

/// The tail shared by `_class_escape` and `_escape`: `\x`, `\u`, `\U`, `\N`
/// forms. Returns `Ok(None)` when `c` is not one of them.
fn hex_like_escape(source: &mut Source<'_>, esc: Tok) -> R<Option<u32>> {
    let (digits, total) = match esc.ch {
        'x' => (2, 4),
        'u' => (4, 6),
        'U' => (8, 10),
        'N' => {
            if !source.matches('{')? {
                return Err(source.error("missing {", 0));
            }
            let name = source.getuntil('}', "character name")?;
            return match lookup_name(&name) {
                Some(c) => Ok(Some(u32::from(c))),
                None => Err(source.error(
                    format!("undefined character name {}", repr_str(&name)),
                    name.chars().count() as i64 + 4,
                )),
            };
        }
        _ => return Ok(None),
    };
    let mut escape = esc.text();
    escape.push_str(&source.getwhile(digits, is_hex)?);
    if escape.chars().count() != total {
        let len = escape.chars().count() as i64;
        return Err(source.error(format!("incomplete escape {escape}"), len));
    }
    let value = u32::from_str_radix(&escape[2..], 16).unwrap_or(0);
    if esc.ch == 'U' && char::from_u32(value).is_none() && value > 0x10_FFFF {
        // `chr(c)` raises ValueError, which falls through to "bad escape".
        let len = escape.chars().count() as i64;
        return Err(source.error(format!("bad escape {escape}"), len));
    }
    Ok(Some(value))
}

/// `_class_escape`.
fn class_escape(source: &mut Source<'_>, esc: Tok) -> R<Code> {
    if let Some(v) = simple_escape(esc.ch) {
        return Ok(Code::Lit(v));
    }
    if let Some(cat) = category(esc.ch) {
        return Ok(Code::Cat(cat));
    }
    if let Some(v) = hex_like_escape(source, esc)? {
        return Ok(Code::Lit(v));
    }
    if is_oct(esc.ch) {
        let mut escape = esc.text();
        escape.push_str(&source.getwhile(2, is_oct)?);
        let value = u32::from_str_radix(&escape[1..], 8).unwrap_or(0);
        if value > 0o377 {
            let len = escape.chars().count() as i64;
            return Err(source.error(
                format!("octal escape value {escape} outside of range 0-0o377"),
                len,
            ));
        }
        return Ok(Code::Lit(value));
    }
    if !esc.ch.is_ascii_digit() && !esc.ch.is_ascii_alphabetic() {
        return Ok(Code::Lit(u32::from(esc.ch)));
    }
    let text = esc.text();
    Err(source.error(format!("bad escape {text}"), 2))
}

/// `_escape`.
fn escape(source: &mut Source<'_>, esc: Tok, state: &State) -> R<Code> {
    if let Some(cat) = category(esc.ch) {
        return Ok(Code::Cat(cat));
    }
    if let Some(at) = at_code(esc.ch) {
        return Ok(Code::At(at));
    }
    if let Some(v) = simple_escape(esc.ch) {
        return Ok(Code::Lit(v));
    }
    if let Some(v) = hex_like_escape(source, esc)? {
        return Ok(Code::Lit(v));
    }
    if esc.ch == '0' {
        let mut text = esc.text();
        text.push_str(&source.getwhile(2, is_oct)?);
        return Ok(Code::Lit(u32::from_str_radix(&text[1..], 8).unwrap_or(0)));
    }
    if esc.ch.is_ascii_digit() {
        let mut text = esc.text();
        if source
            .next
            .is_some_and(|t| !t.escaped && t.ch.is_ascii_digit())
        {
            let second = source.get()?.map_or('0', |t| t.ch);
            text.push(second);
            let b = text.as_bytes();
            if is_oct(char::from(b[1]))
                && is_oct(char::from(b[2]))
                && source.next.is_some_and(|t| !t.escaped && is_oct(t.ch))
            {
                let third = source.get()?.map_or('0', |t| t.ch);
                text.push(third);
                let value = u32::from_str_radix(&text[1..], 8).unwrap_or(0);
                if value > 0o377 {
                    let len = text.chars().count() as i64;
                    return Err(source.error(
                        format!("octal escape value {text} outside of range 0-0o377"),
                        len,
                    ));
                }
                return Ok(Code::Lit(value));
            }
        }
        let group: usize = text[1..].parse().unwrap_or(usize::MAX);
        if group < state.groups() {
            if !state.checkgroup(group) {
                let len = text.len() as i64;
                return Err(source.error("cannot refer to an open group", len));
            }
            state.checklookbehindgroup(group, source)?;
            return Ok(Code::Backref(group));
        }
        let len = text.len() as i64;
        return Err(source.error(format!("invalid group reference {group}"), len - 1));
    }
    if !esc.ch.is_ascii_alphabetic() {
        return Ok(Code::Lit(u32::from(esc.ch)));
    }
    let text = esc.text();
    Err(source.error(format!("bad escape {text}"), 2))
}

/// `_parse_flags`. `Ok(None)` means "global flags".
fn parse_flags(
    source: &mut Source<'_>,
    state: &mut State,
    first: Tok,
) -> R<Option<(Flags, Flags)>> {
    let mut add = 0u32;
    let mut del = 0u32;
    let mut char_ = Some(first);
    let flag_of = |c: char| -> Option<u32> {
        Some(match c {
            'i' => Flags::IGNORECASE,
            'L' => Flags::LOCALE,
            'm' => Flags::MULTILINE,
            's' => Flags::DOTALL,
            'x' => Flags::VERBOSE,
            'a' => Flags::ASCII,
            'u' => Flags::UNICODE,
            _ => return None,
        })
    };
    let is_flag = |t: Tok| !t.escaped && flag_of(t.ch).is_some();
    if !first.is('-') {
        loop {
            let Some(cur) = char_ else { unreachable!() };
            let flag = flag_of(cur.ch).unwrap_or(0);
            if cur.ch == 'L' {
                return Err(source.error(
                    "bad inline flags: cannot use 'L' flag with a str pattern",
                    0,
                ));
            }
            add |= flag;
            if flag & Flags::TYPE_FLAGS != 0 && add & Flags::TYPE_FLAGS != flag {
                return Err(source.error(
                    "bad inline flags: flags 'a', 'u' and 'L' are incompatible",
                    0,
                ));
            }
            char_ = source.get()?;
            let Some(c) = char_ else {
                return Err(source.error("missing -, : or )", 0));
            };
            if !c.escaped && matches!(c.ch, ')' | '-' | ':') {
                break;
            }
            if !is_flag(c) {
                let msg = if !c.escaped && c.ch.is_alphabetic() {
                    "unknown flag"
                } else {
                    "missing -, : or )"
                };
                return Err(source.error(msg, c.len()));
            }
        }
    }
    let Some(mut cur) = char_ else { unreachable!() };
    if cur.is(')') {
        state.flags = Flags(state.flags.0 | add);
        return Ok(None);
    }
    // `GLOBAL_FLAGS` is `SRE_FLAG_DEBUG`, which cannot be spelled inline.
    if cur.is('-') {
        let Some(c) = source.get()? else {
            return Err(source.error("missing flag", 0));
        };
        if !is_flag(c) {
            let msg = if !c.escaped && c.ch.is_alphabetic() {
                "unknown flag"
            } else {
                "missing flag"
            };
            return Err(source.error(msg, c.len()));
        }
        cur = c;
        loop {
            let flag = flag_of(cur.ch).unwrap_or(0);
            if flag & Flags::TYPE_FLAGS != 0 {
                return Err(source.error(
                    "bad inline flags: cannot turn off flags 'a', 'u' and 'L'",
                    0,
                ));
            }
            del |= flag;
            let Some(c) = source.get()? else {
                return Err(source.error("missing :", 0));
            };
            if c.is(':') {
                break;
            }
            if !is_flag(c) {
                let msg = if !c.escaped && c.ch.is_alphabetic() {
                    "unknown flag"
                } else {
                    "missing :"
                };
                return Err(source.error(msg, c.len()));
            }
            cur = c;
        }
    }
    if add & del != 0 {
        return Err(source.error("bad inline flags: flag turned on and off", 1));
    }
    Ok(Some((Flags(add), Flags(del))))
}

fn parse_sub(
    source: &mut Source<'_>,
    state: &mut State,
    mut verbose: bool,
    nested: usize,
) -> R<Vec<Node>> {
    if nested > MAX_NESTING {
        return Err(PyReError::plain("maximum recursion depth exceeded"));
    }
    let mut items: Vec<Vec<Node>> = Vec::new();
    loop {
        let first = nested == 0 && items.is_empty();
        items.push(parse_seq(source, state, verbose, nested + 1, first)?);
        if !source.matches('|')? {
            break;
        }
        if nested == 0 {
            verbose = state.flags.has(Flags::VERBOSE);
        }
    }
    if items.len() == 1 {
        return Ok(items.pop().unwrap_or_default());
    }
    Ok(vec![Node::Branch(items)])
}

/// Parses `{m,n}`'s tail. Returns `None` (and rewinds) when the brace is a
/// literal.
fn parse_brace(source: &mut Source<'_>, here: usize) -> R<Option<(u64, u64)>> {
    let mut lo = String::new();
    let mut hi = String::new();
    let digit = |t: Option<Tok>| t.is_some_and(|t| !t.escaped && t.ch.is_ascii_digit());
    while digit(source.next) {
        lo.push(source.get()?.map_or('0', |t| t.ch));
    }
    if source.matches(',')? {
        while digit(source.next) {
            hi.push(source.get()?.map_or('0', |t| t.ch));
        }
    } else {
        hi.clone_from(&lo);
    }
    if !source.matches('}')? {
        source.seek(here)?;
        return Ok(None);
    }
    let overflow = || PyReError::plain("the repetition number is too large");
    let mut min = 0u64;
    let mut max = MAXREPEAT;
    if !lo.is_empty() {
        min = lo.parse::<u64>().map_err(|_| overflow())?;
        if min >= MAXREPEAT {
            return Err(overflow());
        }
    }
    if !hi.is_empty() {
        max = hi.parse::<u64>().map_err(|_| overflow())?;
        if max >= MAXREPEAT {
            return Err(overflow());
        }
        if max < min {
            return Err(source.error(
                "min repeat greater than max repeat",
                source.tell() - i64::try_from(here).unwrap_or(0),
            ));
        }
    }
    Ok(Some((min, max)))
}

#[allow(clippy::too_many_lines)]
fn parse_seq(
    source: &mut Source<'_>,
    state: &mut State,
    mut verbose: bool,
    nested: usize,
    first: bool,
) -> R<Vec<Node>> {
    if nested > MAX_NESTING {
        return Err(PyReError::plain("maximum recursion depth exceeded"));
    }
    let mut sub: Vec<Node> = Vec::new();
    while let Some(this) = source.next {
        if this.is('|') || this.is(')') {
            break;
        }
        source.get()?;

        if verbose && !this.escaped {
            if matches!(this.ch, ' ' | '\t' | '\n' | '\r' | '\u{b}' | '\u{c}') {
                continue;
            }
            if this.ch == '#' {
                loop {
                    let t = source.get()?;
                    if t.is_none_or(|t| t.is('\n')) {
                        break;
                    }
                }
                continue;
            }
        }

        if this.escaped {
            match escape(source, this, state)? {
                Code::Lit(v) => sub.push(Node::Lit(v)),
                Code::Cat(c) => sub.push(Node::Set {
                    negate: false,
                    items: vec![SetItem::Cat(c)],
                }),
                Code::At(a) => sub.push(Node::At(a)),
                Code::Backref(g) => sub.push(Node::Backref(g)),
            }
            continue;
        }

        match this.ch {
            '[' => {
                let here = source.tell() - 1;
                let mut set: Vec<SetItem> = Vec::new();
                let negate = source.matches('^')?;
                loop {
                    let Some(this) = source.get()? else {
                        return Err(
                            source.error("unterminated character set", source.tell() - here)
                        );
                    };
                    if this.is(']') && !set.is_empty() {
                        break;
                    }
                    let code1 = if this.escaped {
                        class_escape(source, this)?
                    } else {
                        Code::Lit(u32::from(this.ch))
                    };
                    if source.matches('-')? {
                        let Some(that) = source.get()? else {
                            return Err(
                                source.error("unterminated character set", source.tell() - here)
                            );
                        };
                        if that.is(']') {
                            set.push(set_item(&code1));
                            set.push(SetItem::Lit(u32::from('-')));
                            break;
                        }
                        let code2 = if that.escaped {
                            class_escape(source, that)?
                        } else {
                            Code::Lit(u32::from(that.ch))
                        };
                        let (Code::Lit(lo), Code::Lit(hi)) = (&code1, &code2) else {
                            let msg =
                                format!("bad character range {}-{}", this.text(), that.text());
                            return Err(source.error(msg, this.len() + 1 + that.len()));
                        };
                        if hi < lo {
                            let msg =
                                format!("bad character range {}-{}", this.text(), that.text());
                            return Err(source.error(msg, this.len() + 1 + that.len()));
                        }
                        set.push(SetItem::Range(*lo, *hi));
                    } else {
                        set.push(set_item(&code1));
                    }
                }
                let mut uniq: Vec<SetItem> = Vec::with_capacity(set.len());
                for item in set {
                    if !uniq.contains(&item) {
                        uniq.push(item);
                    }
                }
                match (uniq.as_slice(), negate) {
                    ([SetItem::Lit(c)], false) => sub.push(Node::Lit(*c)),
                    _ => sub.push(Node::Set {
                        negate,
                        items: uniq,
                    }),
                }
            }
            '*' | '+' | '?' | '{' => {
                let here_tok = source.tell();
                let here = usize::try_from(here_tok).unwrap_or(0);
                let (min, max) = match this.ch {
                    '?' => (0, 1),
                    '*' => (0, MAXREPEAT),
                    '+' => (1, MAXREPEAT),
                    _ => {
                        if source.next.is_some_and(|t| t.is('}')) {
                            sub.push(Node::Lit(u32::from('{')));
                            continue;
                        }
                        match parse_brace(source, here)? {
                            Some(mm) => mm,
                            None => {
                                sub.push(Node::Lit(u32::from('{')));
                                continue;
                            }
                        }
                    }
                };
                let offset = source.tell() - here_tok + 1;
                let Some(last) = sub.pop() else {
                    return Err(source.error("nothing to repeat", offset));
                };
                if matches!(last, Node::At(_)) {
                    return Err(source.error("nothing to repeat", offset));
                }
                if matches!(last, Node::Repeat { .. }) {
                    return Err(source.error("multiple repeat", offset));
                }
                let body = match last {
                    Node::Group {
                        index: None,
                        add,
                        del,
                        body,
                    } if add.0 == 0 && del.0 == 0 => body,
                    other => vec![other],
                };
                let kind = if source.matches('?')? {
                    RepeatKind::Lazy
                } else if source.matches('+')? {
                    RepeatKind::Possessive
                } else {
                    RepeatKind::Greedy
                };
                sub.push(Node::Repeat {
                    kind,
                    min,
                    max: if max == MAXREPEAT { None } else { Some(max) },
                    body,
                });
            }
            '.' => sub.push(Node::Any),
            '(' => {
                let start = source.tell() - 1;
                match parse_group(source, state, verbose, nested, first, &sub, start)? {
                    GroupResult::Node(n) => sub.push(n),
                    GroupResult::Continue => {}
                    GroupResult::GlobalFlags => verbose = state.flags.has(Flags::VERBOSE),
                }
            }
            '^' => sub.push(Node::At(At::Beginning)),
            '$' => sub.push(Node::At(At::End)),
            c => sub.push(Node::Lit(u32::from(c))),
        }
    }
    Ok(sub)
}

fn set_item(code: &Code) -> SetItem {
    match code {
        Code::Lit(v) => SetItem::Lit(*v),
        Code::Cat(c) => SetItem::Cat(*c),
        // `class_escape` never yields these.
        Code::At(_) | Code::Backref(_) => SetItem::Lit(0),
    }
}

enum GroupResult {
    Node(Node),
    /// `continue` without appending (comments).
    Continue,
    GlobalFlags,
}

/// The `(` branch of `_parse`.
#[allow(clippy::too_many_lines)]
fn parse_group(
    source: &mut Source<'_>,
    state: &mut State,
    verbose: bool,
    nested: usize,
    first: bool,
    sub: &[Node],
    start: i64,
) -> R<GroupResult> {
    let mut capture = true;
    let mut atomic = false;
    let mut name: Option<String> = None;
    let mut add = Flags(0);
    let mut del = Flags(0);
    if source.matches('?')? {
        let Some(c) = source.get()? else {
            return Err(source.error("unexpected end of pattern", 0));
        };
        if c.is('P') {
            if source.matches('<')? {
                let n = source.getuntil('>', "group name")?;
                source.checkgroupname(&n, 1)?;
                name = Some(n);
            } else if source.matches('=')? {
                let n = source.getuntil(')', "group name")?;
                source.checkgroupname(&n, 1)?;
                let len = n.chars().count() as i64;
                let Some(&gid) = state.groupdict.get(&n) else {
                    return Err(
                        source.error(format!("unknown group name {}", repr_str(&n)), len + 1)
                    );
                };
                if !state.checkgroup(gid) {
                    return Err(source.error("cannot refer to an open group", len + 1));
                }
                state.checklookbehindgroup(gid, source)?;
                return Ok(GroupResult::Node(Node::Backref(gid)));
            } else {
                let Some(c2) = source.get()? else {
                    return Err(source.error("unexpected end of pattern", 0));
                };
                let t = c2.text();
                return Err(source.error(format!("unknown extension ?P{t}"), c2.len() + 2));
            }
        } else if c.is(':') {
            capture = false;
        } else if c.is('#') {
            loop {
                if source.next.is_none() {
                    return Err(
                        source.error("missing ), unterminated comment", source.tell() - start)
                    );
                }
                if source.get()?.is_some_and(|t| t.is(')')) {
                    break;
                }
            }
            return Ok(GroupResult::Continue);
        } else if c.is('=') || c.is('!') || c.is('<') {
            let mut ch = c;
            let mut behind = false;
            let mut saved_lb = None;
            if c.is('<') {
                let Some(c2) = source.get()? else {
                    return Err(source.error("unexpected end of pattern", 0));
                };
                if !(c2.is('=') || c2.is('!')) {
                    let t = c2.text();
                    return Err(source.error(format!("unknown extension ?<{t}"), c2.len() + 2));
                }
                ch = c2;
                behind = true;
                saved_lb = state.lookbehindgroups;
                if saved_lb.is_none() {
                    state.lookbehindgroups = Some(state.groups());
                }
            }
            let p = parse_sub(source, state, verbose, nested + 1)?;
            if behind && saved_lb.is_none() {
                state.lookbehindgroups = None;
            }
            if !source.matches(')')? {
                return Err(
                    source.error("missing ), unterminated subpattern", source.tell() - start)
                );
            }
            let negate = ch.is('!');
            return Ok(GroupResult::Node(if !negate {
                Node::Look {
                    behind,
                    negate: false,
                    body: p,
                }
            } else if !p.is_empty() {
                Node::Look {
                    behind,
                    negate: true,
                    body: p,
                }
            } else {
                Node::Fail
            }));
        } else if c.is('(') {
            let condname = source.getuntil(')', "group name")?;
            let len = condname.chars().count() as i64;
            let condgroup = if condname.is_empty() || !condname.bytes().all(|b| b.is_ascii_digit())
            {
                source.checkgroupname(&condname, 1)?;
                let Some(&g) = state.groupdict.get(&condname) else {
                    return Err(source.error(
                        format!("unknown group name {}", repr_str(&condname)),
                        len + 1,
                    ));
                };
                g
            } else {
                let g: usize = condname.parse().unwrap_or(usize::MAX);
                if g == 0 {
                    return Err(source.error("bad group number", len + 1));
                }
                if g >= MAXGROUPS {
                    return Err(source.error(format!("invalid group reference {g}"), len + 1));
                }
                if !state.grouprefpos.iter().any(|&(k, _)| k == g) {
                    state.grouprefpos.push((g, source.tell() - len - 1));
                }
                g
            };
            state.checklookbehindgroup(condgroup, source)?;
            let yes = parse_seq(source, state, verbose, nested + 1, false)?;
            let no = if source.matches('|')? {
                let no = parse_seq(source, state, verbose, nested + 1, false)?;
                if source.next.is_some_and(|t| t.is('|')) {
                    return Err(source.error("conditional backref with more than two branches", 0));
                }
                Some(no)
            } else {
                None
            };
            if !source.matches(')')? {
                return Err(
                    source.error("missing ), unterminated subpattern", source.tell() - start)
                );
            }
            return Ok(GroupResult::Node(Node::Cond {
                group: condgroup,
                yes,
                no,
            }));
        } else if c.is('>') {
            capture = false;
            atomic = true;
        } else if !c.escaped && (c.ch == '-' || "iLmsxau".contains(c.ch)) {
            match parse_flags(source, state, c)? {
                None => {
                    if !first || !sub.is_empty() {
                        return Err(source.error(
                            "global flags not at the start of the expression",
                            source.tell() - start,
                        ));
                    }
                    return Ok(GroupResult::GlobalFlags);
                }
                Some((a, d)) => {
                    add = a;
                    del = d;
                    capture = false;
                }
            }
        } else {
            let t = c.text();
            return Err(source.error(format!("unknown extension ?{t}"), c.len() + 1));
        }
    }

    let group = if capture {
        let gid = state.groups();
        state.groupwidths.push(None);
        if state.groups() > MAXGROUPS {
            return Err(source.error("too many groups", 1));
        }
        if let Some(n) = &name {
            if let Some(&ogid) = state.groupdict.get(n) {
                let msg = format!(
                    "redefinition of group name {} as group {gid}; was group {ogid}",
                    repr_str(n)
                );
                return Err(source.error(msg, n.chars().count() as i64 + 1));
            }
            state.groupdict.insert(n.clone(), gid);
            state.names.push((n.clone(), gid));
        }
        Some(gid)
    } else {
        None
    };
    let sub_verbose = (verbose || add.has(Flags::VERBOSE)) && !del.has(Flags::VERBOSE);
    let p = parse_sub(source, state, sub_verbose, nested + 1)?;
    if !source.matches(')')? {
        return Err(source.error("missing ), unterminated subpattern", source.tell() - start));
    }
    if let Some(g) = group {
        state.groupwidths[g] = Some(width(&p, &state.groupwidths));
    }
    if atomic {
        return Ok(GroupResult::Node(Node::Atomic(p)));
    }
    Ok(GroupResult::Node(Node::Group {
        index: group,
        add,
        del,
        body: p,
    }))
}

/// `sre_parse.parse` followed by the compile-stage checks. `flags` are the
/// `re.compile` flags (only `MULTILINE` is used by Fail2Ban).
pub(crate) fn parse(pattern: &str, flags: Flags) -> Result<Parsed, PyReError> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut source = Source::new(&chars)?;
    let mut state = State {
        flags,
        groupdict: HashMap::new(),
        names: Vec::new(),
        groupwidths: vec![None],
        lookbehindgroups: None,
        grouprefpos: Vec::new(),
    };
    let verbose = flags.has(Flags::VERBOSE);
    let nodes = parse_sub(&mut source, &mut state, verbose, 0)?;
    if source.next.is_some() {
        return Err(source.error("unbalanced parenthesis", 0));
    }
    for &(g, pos) in &state.grouprefpos {
        if g >= state.groups() {
            return Err(PyReError::at(
                format!("invalid group reference {g}"),
                &chars,
                pos,
            ));
        }
    }
    let gw: &GroupWidths = &state.groupwidths;
    check_lookbehind(&nodes, gw).map_err(PyReError::plain)?;
    Ok(Parsed {
        nodes,
        groups: state.groups() - 1,
        names: state.names,
        flags: state.flags,
    })
}
