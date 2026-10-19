//! Python `re` -> `fancy-regex` translation (the single place that compiles a
//! Python-syntax regular expression).
//!
//! [`compile_py_regex`] takes the text of a Python 3.14 `str` pattern and
//! produces a [`PyRegex`] whose [`PyRegex::search`] behaves like
//! `re.search(text, pos, endpos)`. It is deliberately the only function the
//! rest of the crate uses to obtain a regex engine, so it can later be swapped
//! for the project's shared translator.
//!
//! Differences between the two dialects that are handled here:
//!
//! * `\w`, `\W`, `\b`, `\B`, `\s`, `\S`: Python's classes (Unicode 16, from
//!   `f2b_helpers::pychar`) are spliced in as explicit character classes, so
//!   they do not depend on the Unicode version of the Rust toolchain.
//! * `$` (without `(?m)`) matches at the end *and before a trailing newline*;
//!   `\Z` is the absolute end (`\z` in Rust).
//! * a bare `[` inside a class, `]` first in a class, `&&`/`--`/`~~` inside a
//!   class (all literal in Python) are emitted as escaped code points.
//! * `{` that does not start a valid quantifier is a literal; `{,n}` is `{0,n}`.
//! * escapes: Python's set of valid escapes (`\a \f \v \xhh \uhhhh \Uhhhhhhhh`,
//!   octal, `\<` etc. are literals, unknown ASCII-letter escapes are errors).
//! * duplicate group names, unknown group references, nested/multiple repeat,
//!   unbalanced parentheses and global flags that are not at the start are
//!   rejected like Python does.
//! * under `(?i)` a literal `i` also matches `\u{130}` and `\u{131}`
//!   (Python's case-insensitive equivalences; Rust does not fold them).
//!
//! Not supported (reported as errors): possessive quantifiers, verbose mode
//! `(?x)`, `(?a)`, `(?L)`, `\N{...}`, non-ASCII group names, and Python's
//! "look-behind requires fixed-width pattern" check is left to fancy-regex.

use std::collections::HashMap;
use std::fmt::Write;
use std::sync::{Arc, LazyLock, Mutex};

use f2b_helpers::pychar;

/// Capture spans (byte offsets), index 0 is the whole match.
pub(crate) type Caps = Vec<Option<(usize, usize)>>;

#[derive(Debug, Clone)]
pub(crate) struct PyRegex {
    re: Arc<fancy_regex::Regex>,
    /// `names[i]` is the name of capture group `i` (`names[0]` is `None`).
    names: Vec<Option<String>>,
}

/// Backtracking budget; Python has none, this only stops runaway patterns.
const BACKTRACK_LIMIT: usize = 50_000_000;

/// Memo of successful compilations (pure function of the pattern text, so it
/// has no observable state; it only saves recompiling the default templates
/// for every detector). Bounded: cleared when it grows past `MEMO_MAX`.
static MEMO: LazyLock<Mutex<HashMap<String, PyRegex>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
const MEMO_MAX: usize = 2048;

/// Compile a Python-syntax pattern. The error is the Python-style message.
pub(crate) fn compile_py_regex(pattern: &str) -> Result<PyRegex, String> {
    if let Ok(memo) = MEMO.lock()
        && let Some(re) = memo.get(pattern)
    {
        return Ok(re.clone());
    }
    let tr = translate(pattern)?;
    let re = fancy_regex::RegexBuilder::new(&tr.out)
        .backtrack_limit(BACKTRACK_LIMIT)
        .build()
        .map_err(|e| e.to_string())?;
    let compiled = PyRegex {
        re: Arc::new(re),
        names: tr.names,
    };
    if let Ok(mut memo) = MEMO.lock() {
        if memo.len() >= MEMO_MAX {
            memo.clear();
        }
        memo.insert(pattern.to_string(), compiled.clone());
    }
    Ok(compiled)
}

impl PyRegex {
    /// `re.search(text, pos)`; the caller slices `text` to emulate `endpos`.
    /// A runtime failure of the engine (backtrack limit) counts as no match.
    pub(crate) fn search(&self, text: &str, pos: usize) -> Option<Caps> {
        let caps = self.re.captures_from_pos(text, pos).ok()??;
        Some(
            (0..caps.len())
                .map(|i| caps.get(i).map(|m| (m.start(), m.end())))
                .collect(),
        )
    }

    /// `(group index, name)` of every named group, in definition order.
    pub(crate) fn named_groups(&self) -> impl Iterator<Item = (usize, &str)> {
        self.names
            .iter()
            .enumerate()
            .filter_map(|(i, n)| n.as_deref().map(|n| (i, n)))
    }
}

/// Python `re.sub(repl_fn, text)` for all (non-overlapping, non-empty) matches
/// of `re`; `repl` gets the captures and the text.
pub(crate) fn sub_all(
    re: &PyRegex,
    text: &str,
    count: usize,
    mut repl: impl FnMut(&Caps, &str) -> String,
) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    let mut pos = 0;
    let mut n = 0;
    while pos <= text.len() && (count == 0 || n < count) {
        let Some(caps) = re.search(text, pos) else {
            break;
        };
        let (s, e) = caps[0].unwrap_or((pos, pos));
        out.push_str(&text[last..s]);
        out.push_str(&repl(&caps, text));
        last = e;
        n += 1;
        if e == s {
            // empty match: copy one char and move on (Python semantics)
            match text[e..].chars().next() {
                Some(c) => {
                    out.push(c);
                    last = e + c.len_utf8();
                    pos = last;
                }
                None => break,
            }
        } else {
            pos = e;
        }
    }
    out.push_str(&text[last..]);
    out
}

// ---------------------------------------------------------------------------
// Translator
// ---------------------------------------------------------------------------

/// Body of a character class holding Python's `\w`, as `\x{..}-\x{..}` ranges.
static WORD_BODY: LazyLock<String> = LazyLock::new(|| {
    let mut ranges: Vec<(u32, u32)> = Vec::new();
    for cp in 0..=0x10FFFFu32 {
        let Some(c) = char::from_u32(cp) else {
            continue;
        };
        if pychar::is_word(c) {
            match ranges.last_mut() {
                Some(r) if r.1 + 1 == cp => r.1 = cp,
                _ => ranges.push((cp, cp)),
            }
        }
    }
    let mut s = String::new();
    for (a, b) in ranges {
        if a == b {
            let _ = write!(s, "\\x{{{a:x}}}");
        } else {
            let _ = write!(s, "\\x{{{a:x}}}-\\x{{{b:x}}}");
        }
    }
    s
});

const SPACE_EXTRA: &str = "\\x{1c}-\\x{1f}";

struct Translated {
    out: String,
    names: Vec<Option<String>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Flags {
    i: bool,
    m: bool,
    s: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Last {
    /// start of pattern / group / alternative
    Nothing,
    Atom,
    /// `^`, `$`, `\A`, `\Z`, `\b`, `\B`
    At,
    /// a quantifier; `true` once a lazy `?` followed it
    Quant(bool),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum GKind {
    Plain,
    /// `(?=` / `(?!`: zero width
    Ahead,
    /// `(?<=` / `(?<!`: must be fixed width
    Behind,
    /// `(?(id)yes|no)`
    Cond,
}

enum Open {
    /// a group; `Some(i)` capture index. `flags` are restored on close.
    Group {
        capture: Option<usize>,
        flags: Flags,
        kind: GKind,
        /// output offset of the `(`
        start: usize,
    },
}

/// Python's `getwidth()` bookkeeping of one sequence/alternation level.
#[derive(Clone, Copy)]
struct WFrame {
    alt_lo: u64,
    alt_hi: u64,
    alts: usize,
    cur: (u64, u64),
    prev: (u64, u64),
    last_w: (u64, u64),
    /// byte offset in the output where the last atom starts
    last_start: usize,
}

const INF: u64 = 1 << 40;

impl WFrame {
    fn new() -> Self {
        Self {
            alt_lo: u64::MAX,
            alt_hi: 0,
            alts: 0,
            cur: (0, 0),
            prev: (0, 0),
            last_w: (0, 0),
            last_start: 0,
        }
    }

    fn end_alt(&mut self) {
        self.alt_lo = self.alt_lo.min(self.cur.0);
        self.alt_hi = self.alt_hi.max(self.cur.1);
        self.alts += 1;
        self.cur = (0, 0);
        self.prev = (0, 0);
        self.last_w = (0, 0);
        self.last_start = 0;
    }
}

struct Tr {
    c: Vec<char>,
    p: usize,
    out: String,
    names: Vec<Option<String>>,
    by_name: HashMap<String, usize>,
    closed: Vec<bool>,
    open: Vec<Open>,
    /// output offset where the token being translated started
    tok_start: usize,
    /// the last atom is a look-around group
    last_assert: bool,
    /// width frames: the root plus one per open group
    wf: Vec<WFrame>,
    /// `(lo, hi)` width of every closed capture group
    gwidth: Vec<(u64, u64)>,
    flags: Flags,
    last: Last,
    /// no token (except global flags) emitted yet
    at_start: bool,
}

fn translate(pattern: &str) -> Result<Translated, String> {
    let mut t = Tr {
        c: pattern.chars().collect(),
        p: 0,
        out: String::with_capacity(pattern.len() + 16),
        names: vec![None],
        by_name: HashMap::new(),
        closed: vec![true],
        open: Vec::new(),
        tok_start: 0,
        last_assert: false,
        wf: vec![WFrame::new()],
        gwidth: vec![(0, 0)],
        flags: Flags {
            i: false,
            m: false,
            s: false,
        },
        last: Last::Nothing,
        at_start: true,
    };
    t.run()?;
    Ok(Translated {
        out: t.out,
        names: t.names,
    })
}

fn lit(out: &mut String, c: char) {
    if c.is_ascii_alphanumeric() || c == '_' || !c.is_ascii() {
        out.push(c);
    } else {
        let _ = write!(out, "\\x{{{:x}}}", u32::from(c));
    }
}

fn hex(out: &mut String, c: char) {
    let _ = write!(out, "\\x{{{:x}}}", u32::from(c));
}

impl Tr {
    fn peek(&self) -> Option<char> {
        self.c.get(self.p).copied()
    }

    fn peek_at(&self, n: usize) -> Option<char> {
        self.c.get(self.p + n).copied()
    }

    fn next(&mut self) -> Option<char> {
        let c = self.c.get(self.p).copied();
        if c.is_some() {
            self.p += 1;
        }
        c
    }

    fn eat(&mut self, c: char) -> bool {
        if self.peek() == Some(c) {
            self.p += 1;
            true
        } else {
            false
        }
    }

    /// Emit an atom: the literal char `c` (outside a class).
    fn push_literal(&mut self, c: char) {
        if self.flags.i && (c == 'i' || c == 'I') {
            self.out.push_str("[iI\\x{130}\\x{131}]");
        } else {
            lit(&mut self.out, c);
        }
        self.atom(1, 1);
    }

    fn run(&mut self) -> Result<(), String> {
        while let Some(ch) = self.next() {
            self.tok_start = self.out.len();
            match ch {
                '\\' => self.escape()?,
                '[' => {
                    self.class()?;
                    self.at_start = false;
                    self.atom(1, 1);
                }
                '(' => self.group_open()?,
                ')' => self.group_close()?,
                '|' => {
                    self.at_start = false;
                    self.out.push('|');
                    self.frame().end_alt();
                    self.last = Last::Nothing;
                }
                '*' | '+' | '?' => {
                    let (min, max) = match ch {
                        '*' => (0, INF),
                        '+' => (1, INF),
                        _ => (0, 1),
                    };
                    self.quantifier(ch, &ch.to_string(), min, max)?;
                }
                '{' => self.brace()?,
                '}' => {
                    self.at_start = false;
                    self.out.push_str("\\}");
                    self.atom(1, 1);
                }
                '.' => {
                    self.at_start = false;
                    self.out.push('.');
                    self.atom(1, 1);
                }
                '^' => {
                    self.at_start = false;
                    self.out.push('^');
                    self.zero();
                }
                '$' => {
                    self.at_start = false;
                    if self.flags.m {
                        self.out.push('$');
                    } else {
                        self.out.push_str("(?:\\z|(?=\\n\\z))");
                    }
                    self.zero();
                }
                c => {
                    self.at_start = false;
                    self.push_literal(c);
                }
            }
        }
        if !self.open.is_empty() {
            return Err("missing ), unterminated subpattern".into());
        }
        Ok(())
    }

    fn quantifier(&mut self, ch: char, text: &str, min: u64, max: u64) -> Result<(), String> {
        match self.last {
            Last::Nothing | Last::At => return Err("nothing to repeat".into()),
            Last::Quant(done) => {
                if ch == '?' && text == "?" && !done {
                    self.out.push('?');
                    self.last = Last::Quant(true);
                    return Ok(());
                }
                if ch == '+' && text == "+" && !done {
                    // possessive quantifier: `X*+` is `(?>X*)`
                    let start = self.frame().last_start;
                    self.out.insert_str(start, "(?>");
                    self.out.push(')');
                    self.last = Last::Quant(true);
                    return Ok(());
                }
                return Err("multiple repeat".into());
            }
            Last::Atom => {}
        }
        if self.last_assert {
            // Python allows repeating an assertion; fancy-regex does not. A
            // repeated assertion matches the empty string, so `X*` is `(?:X|)`
            // and `X+` is `X`.
            if min == 0 {
                self.out.pop();
                self.out.push_str("|)");
            }
            self.last = Last::Quant(false);
            return Ok(());
        }
        self.out.push_str(text);
        let f = self.frame();
        let (lo, hi) = f.last_w;
        f.cur = (
            (f.prev.0 + lo.saturating_mul(min)).min(INF),
            (f.prev.1.saturating_add(hi.saturating_mul(max))).min(INF),
        );
        self.last = Last::Quant(false);
        Ok(())
    }

    /// `{` seen: a valid Python quantifier `{m}`, `{m,}`, `{,n}`, `{m,n}`
    /// (ASCII digits) or else a literal brace.
    fn brace(&mut self) -> Result<(), String> {
        let save = self.p;
        if self.peek() != Some('}') {
            let mut lo = String::new();
            while let Some(d) = self.peek().filter(char::is_ascii_digit) {
                lo.push(d);
                self.p += 1;
            }
            let mut hi = String::new();
            let comma = self.eat(',');
            if comma {
                while let Some(d) = self.peek().filter(char::is_ascii_digit) {
                    hi.push(d);
                    self.p += 1;
                }
            } else {
                hi.clone_from(&lo);
            }
            if self.eat('}') {
                let lo_n: u64 = if lo.is_empty() {
                    0
                } else {
                    lo.parse()
                        .map_err(|_| "the repetition number is too large")?
                };
                let hi_n: Option<u64> = if hi.is_empty() {
                    None
                } else {
                    Some(
                        hi.parse()
                            .map_err(|_| "the repetition number is too large")?,
                    )
                };
                if hi_n.is_some_and(|h| h < lo_n) {
                    return Err("min repeat greater than max repeat".into());
                }
                let text = match hi_n {
                    Some(h) if comma => format!("{{{lo_n},{h}}}"),
                    Some(h) => format!("{{{h}}}"),
                    None => format!("{{{lo_n},}}"),
                };
                return self.quantifier('{', &text, lo_n, hi_n.unwrap_or(INF));
            }
        }
        self.p = save;
        self.at_start = false;
        self.out.push_str("\\{");
        self.atom(1, 1);
        Ok(())
    }

    fn word_class(&mut self, negate: bool) {
        self.out.push_str(if negate { "[^" } else { "[" });
        self.out.push_str(&WORD_BODY);
        self.out.push(']');
    }

    fn word_boundary(&mut self, negate: bool) {
        let w = format!("[{}]", *WORD_BODY);
        if negate {
            let _ = write!(self.out, "(?:(?<={w})(?={w})|(?<!{w})(?!{w}))");
        } else {
            let _ = write!(self.out, "(?:(?<={w})(?!{w})|(?<!{w})(?={w}))");
        }
    }

    fn read_hex(&mut self, n: usize, what: char) -> Result<char, String> {
        let mut v: u32 = 0;
        for _ in 0..n {
            let d = self
                .next()
                .and_then(|c| c.to_digit(16))
                .ok_or_else(|| format!("incomplete escape \\{what}"))?;
            v = v * 16 + d;
        }
        char::from_u32(v).ok_or_else(|| format!("bad escape \\{what}"))
    }

    /// `\` seen outside a class.
    fn escape(&mut self) -> Result<(), String> {
        let Some(e) = self.next() else {
            return Err("bad escape (end of pattern)".into());
        };
        self.at_start = false;
        match e {
            'A' => {
                self.out.push_str("\\A");
                self.zero();
            }
            'Z' => {
                self.out.push_str("\\z");
                self.zero();
            }
            'b' => {
                self.word_boundary(false);
                self.zero();
            }
            'B' => {
                self.word_boundary(true);
                self.zero();
            }
            'd' => {
                self.out.push_str("\\d");
                self.atom(1, 1);
            }
            'D' => {
                self.out.push_str("\\D");
                self.atom(1, 1);
            }
            's' => {
                let _ = write!(self.out, "[\\s{SPACE_EXTRA}]");
                self.atom(1, 1);
            }
            'S' => {
                let _ = write!(self.out, "[^\\s{SPACE_EXTRA}]");
                self.atom(1, 1);
            }
            'w' => {
                self.word_class(false);
                self.atom(1, 1);
            }
            'W' => {
                self.word_class(true);
                self.atom(1, 1);
            }
            'a' => self.push_literal('\x07'),
            'f' => self.push_literal('\x0c'),
            'n' => self.push_literal('\n'),
            'r' => self.push_literal('\r'),
            't' => self.push_literal('\t'),
            'v' => self.push_literal('\x0b'),
            'x' => {
                let c = self.read_hex(2, 'x')?;
                self.push_literal(c);
            }
            'u' => {
                let c = self.read_hex(4, 'u')?;
                self.push_literal(c);
            }
            'U' => {
                let c = self.read_hex(8, 'U')?;
                self.push_literal(c);
            }
            '0' => {
                let c = self.octal(0)?;
                self.push_literal(c);
            }
            '1'..='9' => {
                let d = e.to_digit(10).unwrap_or(0);
                // two more octal digits after an octal first digit: octal escape
                if let (Some(a), Some(b)) = (self.peek(), self.peek_at(1))
                    && matches!(e, '0'..='7')
                    && matches!(a, '0'..='7')
                    && matches!(b, '0'..='7')
                {
                    self.p += 2;
                    let v = d * 64 + a.to_digit(8).unwrap_or(0) * 8 + b.to_digit(8).unwrap_or(0);
                    if v > 0o377 {
                        return Err(format!(
                            "octal escape value \\{e}{a}{b} outside of range 0-0o377"
                        ));
                    }
                    let c = char::from_u32(v).unwrap_or('\0');
                    self.push_literal(c);
                    return Ok(());
                }
                let mut g = d as usize;
                if let Some(n) = self.peek().filter(char::is_ascii_digit) {
                    self.p += 1;
                    g = g * 10 + n.to_digit(10).unwrap_or(0) as usize;
                }
                if g >= self.closed.len() {
                    return Err(format!("invalid group reference {g}"));
                }
                if !self.closed[g] {
                    return Err("cannot refer to an open group".into());
                }
                let _ = write!(self.out, "(?:\\{g})");
                let (lo, hi) = self.gwidth[g];
                self.atom(lo, hi);
            }
            c if c.is_ascii_alphabetic() => {
                return Err(format!("bad escape \\{c}"));
            }
            c => self.push_literal(c),
        }
        Ok(())
    }

    /// Octal escape: `\0` followed by up to two more octal digits (first
    /// digit already consumed; `first` is its value).
    fn octal(&mut self, first: u32) -> Result<char, String> {
        let mut v = first;
        for _ in 0..2 {
            match self.peek().and_then(|c| c.to_digit(8)) {
                Some(d) => {
                    v = v * 8 + d;
                    self.p += 1;
                }
                None => break,
            }
        }
        Ok(char::from_u32(v).unwrap_or('\0'))
    }

    fn read_until(&mut self, end: char, what: &str) -> Result<String, String> {
        let mut s = String::new();
        loop {
            match self.next() {
                Some(c) if c == end => return Ok(s),
                Some(c) => s.push(c),
                None => return Err(format!("missing {end}, unterminated {what}")),
            }
        }
    }

    fn check_name(name: &str) -> Result<(), String> {
        let mut chars = name.chars();
        let ok = chars
            .next()
            .is_some_and(|c| c == '_' || unicode_ident::is_xid_start(c))
            && chars.all(unicode_ident::is_xid_continue);
        if ok {
            Ok(())
        } else if name.is_empty() {
            Err("missing group name".into())
        } else {
            Err(format!("bad character in group name '{name}'"))
        }
    }

    fn group_open(&mut self) -> Result<(), String> {
        let was_start = self.at_start && self.open.is_empty();
        self.at_start = false;
        let saved = self.flags;
        if !self.eat('?') {
            let idx = self.names.len();
            self.names.push(None);
            self.closed.push(false);
            self.gwidth.push((0, 0));
            self.out.push('(');
            self.push_group(Some(idx), saved, GKind::Plain);
            self.last = Last::Nothing;
            return Ok(());
        }
        let Some(x) = self.next() else {
            return Err("unexpected end of pattern".into());
        };
        match x {
            'P' => match self.next() {
                Some('<') => {
                    let name = self.read_until('>', "group name")?;
                    Self::check_name(&name)?;
                    if let Some(prev) = self.by_name.get(&name) {
                        return Err(format!(
                            "redefinition of group name '{name}' as group {}; was group {prev}",
                            self.names.len()
                        ));
                    }
                    let idx = self.names.len();
                    self.by_name.insert(name.clone(), idx);
                    self.out.push('(');
                    self.names.push(Some(name));
                    self.closed.push(false);
                    self.gwidth.push((0, 0));
                    self.push_group(Some(idx), saved, GKind::Plain);
                    self.last = Last::Nothing;
                }
                Some('=') => {
                    let name = self.read_until(')', "group name")?;
                    Self::check_name(&name)?;
                    let Some(&idx) = self.by_name.get(&name) else {
                        return Err(format!("unknown group name '{name}'"));
                    };
                    if !self.closed[idx] {
                        return Err("cannot refer to an open group".into());
                    }
                    let _ = write!(self.out, "(?:\\{idx})");
                    let (lo, hi) = self.gwidth[idx];
                    self.atom(lo, hi);
                }
                _ => return Err("unknown extension ?P".into()),
            },
            ':' | '=' | '!' | '>' => {
                self.out.push_str("(?");
                self.out.push(x);
                let kind = if x == '=' || x == '!' {
                    GKind::Ahead
                } else {
                    GKind::Plain
                };
                self.push_group(None, saved, kind);
                self.last = Last::Nothing;
            }
            '<' => match self.next() {
                Some(y @ ('=' | '!')) => {
                    self.out.push_str("(?<");
                    self.out.push(y);
                    self.push_group(None, saved, GKind::Behind);
                    self.last = Last::Nothing;
                }
                Some(y) => return Err(format!("unknown extension ?<{y}")),
                None => return Err("unexpected end of pattern".into()),
            },
            '#' => {
                // comment: ignored, does not interrupt `x(?#c)*`
                self.read_until(')', "comment")?;
                self.at_start = was_start;
            }
            '(' => {
                let id = self.read_until(')', "group name")?;
                let target = if !id.is_empty() && id.chars().all(|c| c.is_ascii_digit()) {
                    let g: usize = id.parse().map_err(|_| "invalid group reference")?;
                    if g == 0 || g >= self.closed.len() {
                        return Err(format!("invalid group reference {g}"));
                    }
                    if !self.closed[g] {
                        return Err("cannot refer to an open group".into());
                    }
                    id
                } else {
                    Self::check_name(&id)?;
                    match self.by_name.get(&id) {
                        Some(g) => g.to_string(),
                        None => return Err(format!("unknown group name '{id}'")),
                    }
                };
                let _ = write!(self.out, "(?({target})");
                self.push_group(None, saved, GKind::Cond);
                self.last = Last::Nothing;
            }
            c if "aiLmsux-".contains(c) => {
                self.p -= 1;
                self.flag_group(saved, was_start)?;
            }
            c => return Err(format!("unknown extension ?{c}")),
        }
        Ok(())
    }

    /// `(?` followed by flag letters: a global `(?i)` or a scoped `(?i-m:...)`.
    fn flag_group(&mut self, saved: Flags, was_start: bool) -> Result<(), String> {
        let mut add = String::new();
        while let Some(c) = self.peek().filter(|c| "aiLmsux".contains(*c)) {
            add.push(c);
            self.p += 1;
        }
        let mut del = String::new();
        let global = self.peek() == Some(')');
        if global {
            self.p += 1;
            if !was_start {
                return Err("global flags not at the start of the expression".into());
            }
            if add.is_empty() {
                return Err("missing flag".into());
            }
        } else if self.eat('-') {
            while let Some(c) = self.peek().filter(|c| "imsx".contains(*c)) {
                del.push(c);
                self.p += 1;
            }
            if !self.eat(':') {
                return Err("missing :".into());
            }
            if del.is_empty() {
                return Err("missing flag".into());
            }
        } else if !self.eat(':') {
            return Err("missing -, : or )".into());
        }
        let mut f = self.flags;
        for (list, on) in [(&add, true), (&del, false)] {
            for c in list.chars() {
                match c {
                    'i' => f.i = on,
                    'm' => f.m = on,
                    's' => f.s = on,
                    'u' => {}
                    'a' | 'L' | 'x' => {
                        return Err(format!("flag (?{c}) is not supported"));
                    }
                    _ => return Err("unknown flag".into()),
                }
            }
        }
        let mut emit = String::new();
        for (name, now, before) in [
            ('i', f.i, self.flags.i),
            ('m', f.m, self.flags.m),
            ('s', f.s, self.flags.s),
        ] {
            if now && !before {
                emit.push(name);
            }
        }
        let mut neg = String::new();
        for (name, now, before) in [
            ('i', f.i, self.flags.i),
            ('m', f.m, self.flags.m),
            ('s', f.s, self.flags.s),
        ] {
            if !now && before {
                neg.push(name);
            }
        }
        if global {
            // `(?flags)`
            if !emit.is_empty() || !neg.is_empty() {
                let _ = write!(self.out, "(?{emit})");
            }
            self.flags = f;
            self.at_start = true;
            self.last = Last::Nothing;
        } else {
            self.out.push_str("(?");
            self.out.push_str(&emit);
            if !neg.is_empty() {
                self.out.push('-');
                self.out.push_str(&neg);
            }
            self.out.push(':');
            self.flags = f;
            self.push_group(None, saved, GKind::Plain);
            self.last = Last::Nothing;
        }
        Ok(())
    }

    fn push_group(&mut self, capture: Option<usize>, flags: Flags, kind: GKind) {
        self.open.push(Open::Group {
            capture,
            flags,
            kind,
            start: self.tok_start,
        });
        self.wf.push(WFrame::new());
        self.last = Last::Nothing;
    }

    fn frame(&mut self) -> &mut WFrame {
        let i = self.wf.len() - 1;
        &mut self.wf[i]
    }

    /// An atom of width `(lo, hi)` was emitted.
    fn atom(&mut self, lo: u64, hi: u64) {
        let start = self.tok_start;
        let f = self.frame();
        f.prev = f.cur;
        f.last_w = (lo, hi);
        f.last_start = start;
        f.cur = ((f.cur.0 + lo).min(INF), (f.cur.1 + hi).min(INF));
        self.last = Last::Atom;
        self.last_assert = false;
    }

    /// A zero-width assertion (`^`, `\b`, ...) was emitted.
    fn zero(&mut self) {
        self.last = Last::At;
    }

    fn group_close(&mut self) -> Result<(), String> {
        self.at_start = false;
        let Some(Open::Group {
            capture,
            flags,
            kind,
            start,
        }) = self.open.pop()
        else {
            return Err("unbalanced parenthesis".into());
        };
        let mut fr = self.wf.pop().unwrap_or_else(WFrame::new);
        fr.end_alt();
        let (mut lo, hi) = (fr.alt_lo, fr.alt_hi);
        if kind == GKind::Cond {
            if fr.alts > 2 {
                return Err("conditional backref with more than two branches".into());
            }
            if fr.alts == 1 {
                lo = 0;
            }
        }
        if kind == GKind::Behind && lo != hi {
            return Err("look-behind requires fixed-width pattern".into());
        }
        if let Some(i) = capture {
            self.closed[i] = true;
            self.gwidth[i] = (lo, hi);
        }
        self.flags = flags;
        self.out.push(')');
        if matches!(kind, GKind::Ahead | GKind::Behind) {
            // Python allows repeating an assertion; fancy-regex does not
            self.out.insert_str(start, "(?:");
            self.out.push(')');
            self.atom(0, 0);
            self.last_assert = true;
        } else {
            self.atom(lo, hi);
        }
        self.frame().last_start = start;
        Ok(())
    }

    /// `[` seen: translate a character class to explicit code points.
    fn class(&mut self) -> Result<(), String> {
        let mut body = String::new();
        let negate = self.eat('^');
        let mut first = true;
        loop {
            let Some(c) = self.next() else {
                return Err("unterminated character set".into());
            };
            if c == ']' && !first {
                break;
            }
            first = false;
            let item = if c == '\\' {
                self.class_escape()?
            } else {
                ClassItem::Char(c)
            };
            match item {
                ClassItem::Set(text) => {
                    if self.peek() == Some('-') && self.peek_at(1).is_some_and(|n| n != ']') {
                        return Err("bad character range".into());
                    }
                    body.push_str(&text);
                }
                ClassItem::Char(lo) => {
                    if self.peek() == Some('-') && self.peek_at(1).is_some_and(|n| n != ']') {
                        self.p += 1;
                        let Some(h) = self.next() else {
                            return Err("unterminated character set".into());
                        };
                        let hi = if h == '\\' {
                            match self.class_escape()? {
                                ClassItem::Char(hc) => hc,
                                ClassItem::Set(_) => return Err("bad character range".into()),
                            }
                        } else {
                            h
                        };
                        if hi < lo {
                            return Err(format!("bad character range {lo}-{hi}"));
                        }
                        hex(&mut body, lo);
                        body.push('-');
                        hex(&mut body, hi);
                    } else {
                        hex(&mut body, lo);
                    }
                }
            }
        }
        self.out.push('[');
        if negate {
            self.out.push('^');
        }
        self.out.push_str(&body);
        self.out.push(']');
        Ok(())
    }

    fn class_escape(&mut self) -> Result<ClassItem, String> {
        let Some(e) = self.next() else {
            return Err("bad escape (end of pattern)".into());
        };
        Ok(match e {
            'd' => ClassItem::Set("\\d".into()),
            'D' => ClassItem::Set("[^\\d]".into()),
            's' => ClassItem::Set(format!("\\s{SPACE_EXTRA}")),
            'S' => ClassItem::Set(format!("[^\\s{SPACE_EXTRA}]")),
            'w' => ClassItem::Set(WORD_BODY.clone()),
            'W' => ClassItem::Set(format!("[^{}]", *WORD_BODY)),
            'b' => ClassItem::Char('\x08'),
            'a' => ClassItem::Char('\x07'),
            'f' => ClassItem::Char('\x0c'),
            'n' => ClassItem::Char('\n'),
            'r' => ClassItem::Char('\r'),
            't' => ClassItem::Char('\t'),
            'v' => ClassItem::Char('\x0b'),
            'x' => ClassItem::Char(self.read_hex(2, 'x')?),
            'u' => ClassItem::Char(self.read_hex(4, 'u')?),
            'U' => ClassItem::Char(self.read_hex(8, 'U')?),
            '0'..='7' => {
                let first = e.to_digit(8).unwrap_or(0);
                let c = self.octal(first)?;
                ClassItem::Char(c)
            }
            '8' | '9' => return Err(format!("bad escape \\{e}")),
            c if c.is_ascii_alphabetic() => return Err(format!("bad escape \\{c}")),
            c => ClassItem::Char(c),
        })
    }
}

enum ClassItem {
    Char(char),
    /// text to splice into the Rust class
    Set(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(p: &str, text: &str) -> Option<(usize, usize)> {
        compile_py_regex(p)
            .unwrap_or_else(|e| panic!("{p}: {e}"))
            .search(text, 0)
            .map(|c| c[0].unwrap())
    }

    #[test]
    fn dollar_matches_before_trailing_newline_only() {
        assert_eq!(found("a$", "a\n"), Some((0, 1)));
        assert_eq!(found("a$", "a\nb"), None);
        assert_eq!(found(r"a\Z", "a\n"), None);
        assert_eq!(found("(?m)a$", "a\nb"), Some((0, 1)));
    }

    #[test]
    fn python_class_and_brace_quirks() {
        assert_eq!(found("[[]x", "a[x"), Some((1, 3)));
        assert_eq!(found("[]a]+", "x]a]"), Some((1, 4)));
        assert_eq!(found("x{", "ax{"), Some((1, 3)));
        assert_eq!(found("a{,2}b", "aaab"), Some((1, 4)));
        assert_eq!(found("[a&&b]+", "&&"), Some((0, 2)));
        assert_eq!(found(r"\<x\>", "<x>"), Some((0, 3)));
    }

    #[test]
    fn python_word_class_is_not_rust_word_class() {
        // U+0300 (combining grave) is `\w` in Rust, not in Python
        assert_eq!(found(r"\w", "\u{300}"), None);
        assert_eq!(found(r"\s", "\u{1c}"), Some((0, 1)));
        assert_eq!(found(r"\bx", "\u{300}x"), Some((2, 3)));
    }

    #[test]
    fn rejects_what_python_rejects() {
        for p in [
            "(?P<a>x)(?P<a>y)",
            r"\y",
            "(a",
            "a)",
            "a**",
            "*a",
            "x(?i)",
            "(?<n>a)",
            "[b-a]",
            r"\1",
            "(?P=zz)",
            "(?P<a>x",
            "a{3,2}",
        ] {
            assert!(compile_py_regex(p).is_err(), "{p} should be rejected");
        }
    }
}
