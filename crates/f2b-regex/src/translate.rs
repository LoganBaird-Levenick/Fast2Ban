//! Python `re` pattern -> Rust regex syntax.
//!
//! The pattern is parsed with a port of CPython's parser ([`crate::pyparse`])
//! and re-emitted for the `regex` crate (linear time) or, when it uses features
//! that crate lacks, for `fancy-regex`. All groups are emitted as *numbered*
//! groups; names are kept in [`Translated::names`], so Python group names
//! (arbitrary Unicode identifiers) never reach the engines.
//!
//! # Translation rules
//!
//! | Python | Emitted |
//! |---|---|
//! | `\d`, `\s`, `\w` (and negations, also inside `[...]`) | explicit code point classes built from Python 3.14 / Unicode 16 tables (Rust's `\s`/`\w` differ: e.g. `\s` has `U+001C..U+001F`, `\w` has no combining marks but has `No`) |
//! | any `[...]` | explicit `\x{..}` ranges; Python's bare `[`, `&&`, `~~`, `--` are plain members |
//! | `^`, `\A` | `\A`, or `(?m:^)` under `re.MULTILINE` |
//! | `\Z`, `\z` | `\z` |
//! | `$` | `(?m:$)` under `re.MULTILINE`; otherwise see *haystack gate* below |
//! | `(?P<n>..)`, `(?P=n)`, `(?(n)..)` | numbered group, `(?:\N)`, `(?(N)..)` (fancy-regex) |
//! | `(?i)x` global flags | `(?i:x)` around the pattern; `(?s)`/`(?m)`/`(?x)`/`(?a)` are resolved while emitting |
//! | `a*+`, `(?>..)` | `(?>a*)`, `(?>..)` (fancy-regex); a possessive repeat of a multi-character body makes each iteration atomic, `(?>(?:(?>X)){n,m})`, as CPython does |
//! | `.` | `.` or `(?s:.)` |
//! | `(?!)` | a class that never matches |
//! | `(?<=:):` right after a group that always ends in `:` (the tail of `IP_6_RE`) | `:` (the lookbehind is vacuous), which keeps `<HOST>` patterns on the linear engine |
//!
//! # Haystack gate
//!
//! Three Python constructs cannot be expressed exactly by the linear engine
//! for every haystack. The linear/primary pattern is emitted with the closest
//! construct that is exact on a restricted class of haystacks ([`Gate`]) and
//! a second, exact, backtracking pattern is emitted for all other haystacks:
//!
//! * `$` without `MULTILINE` matches at the end *and before a final `\n`*;
//!   the primary pattern uses `(?m:$)`, exact when the only `\n` of the
//!   haystack is its last byte (the shape of every buffer built from one log
//!   line). Otherwise `(?=\n?\z)` is used.
//! * `\b` / `\B` use Python's `\w`; Rust's differ on non-ASCII characters
//!   (combining marks, numeric letters). The primary pattern uses Rust's `\b`,
//!   exact for ASCII haystacks. Otherwise explicit `(?<=\w)(?!\w)|(?<!\w)(?=\w)`
//!   lookarounds with Python's `\w` are used.
//!
//! # Known deviations
//!
//! * Case folding of `(?i)` follows Rust's simple case folding (Python's
//!   `lower()`-based matching agrees except for exotic code points).
//! * A repeated pattern whose body can match empty has Rust's capture
//!   semantics for the empty iteration, which can differ from Python's for
//!   groups that iterate with an empty match (`(a*)*` style).

use crate::charset::{self, ANY_CHAR, NEVER};

/// Python's `\w` as a Rust class.
const WORD_CLASS: &str = r"[\p{L}\p{N}_]";
use crate::pyast::{At, Flags, Node, RepeatKind, SetItem};
use crate::pyparse::{self, PyReError};

/// Which engine runs a pattern.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineKind {
    /// The linear-time `regex` crate.
    Linear,
    /// `fancy-regex` (backtracking; lookaround, backreferences, conditionals,
    /// atomic groups).
    Backtracking,
}

/// Conditions on the haystack under which the primary pattern is exact.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Gate {
    /// The haystack must be ASCII (pattern uses Unicode `\b` / `\B`).
    pub ascii_only: bool,
    /// The haystack's only `\n` may be its last byte (pattern uses `$`
    /// without `MULTILINE`).
    pub newline_only_last: bool,
}

impl Gate {
    /// Whether `haystack` satisfies every condition of the gate.
    #[must_use]
    pub fn admits(self, haystack: &str) -> bool {
        let bytes = haystack.as_bytes();
        if self.ascii_only && !haystack.is_ascii() {
            return false;
        }
        if self.newline_only_last {
            match memchr::memchr(b'\n', bytes) {
                None => {}
                Some(i) if i + 1 == bytes.len() => {}
                Some(_) => return false,
            }
        }
        true
    }

    fn is_open(self) -> bool {
        self == Gate::default()
    }
}

/// A pattern translated for the Rust engines.
#[derive(Clone, Debug)]
pub struct Translated {
    /// Pattern for the primary engine; exact for every haystack the
    /// [`Gate`] admits.
    pub primary: String,
    /// Engine `primary` is meant for.
    pub primary_engine: EngineKind,
    /// Exact `fancy-regex` pattern for haystacks the gate rejects; `None`
    /// when the gate is open (the primary pattern is always exact).
    pub exact: Option<String>,
    /// Gate of the primary pattern.
    pub gate: Gate,
    /// Linear-time superset of a backtracking pattern, valid for every
    /// buffer: when it does not match, the pattern cannot match. `None` for
    /// patterns that already run on the linear engine.
    pub prefilter: Option<String>,
    /// Number of capture groups (group 0 excluded).
    pub groups: usize,
    /// Python `groupindex`: `(name, group number)` in definition order.
    pub names: Vec<(String, usize)>,
    /// The compiled pattern's `flags` (global inline flags included).
    pub(crate) flags: Flags,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Primary,
    Exact,
    /// A linear-time *superset* of the pattern (lookarounds, `\b`, atomicity
    /// dropped, backreferences become `.*`): a buffer it rejects cannot match
    /// the real pattern. Valid for every buffer.
    Relaxed,
}

struct Emitter {
    mode: Mode,
    out: String,
    fancy: bool,
    gate: Gate,
    /// The pattern runs on `fancy-regex`, which has no inline `(?-u:...)`.
    on_fancy: bool,
}

/// Whether a node sequence can only match the empty string, without consuming
/// (assertions, empty groups and repeats or alternations of them).
/// `fancy-regex` refuses to repeat such expressions; Python allows it and the
/// result is the expression once (or, with a minimum of 0, nothing).
fn zero_width(nodes: &[Node]) -> bool {
    nodes.iter().all(|n| match n {
        Node::At(_) | Node::Look { .. } | Node::Fail => true,
        Node::Group { body, .. } | Node::Atomic(body) | Node::Repeat { body, .. } => {
            zero_width(body)
        }
        Node::Branch(alts) => alts.iter().all(|a| zero_width(a)),
        Node::Cond { yes, no, .. } => zero_width(yes) && no.as_deref().is_none_or(zero_width),
        Node::Lit(_) | Node::Any | Node::Set { .. } | Node::Backref(_) => false,
    })
}

/// Whether a node sequence defines capture groups.
fn has_capture(nodes: &[Node]) -> bool {
    nodes.iter().any(|n| match n {
        Node::Group { index, body, .. } => index.is_some() || has_capture(body),
        Node::Atomic(body) | Node::Repeat { body, .. } | Node::Look { body, .. } => {
            has_capture(body)
        }
        Node::Branch(alts) => alts.iter().any(|a| has_capture(a)),
        Node::Cond { yes, no, .. } => has_capture(yes) || no.as_deref().is_some_and(has_capture),
        Node::Lit(_)
        | Node::Any
        | Node::Set { .. }
        | Node::At(_)
        | Node::Backref(_)
        | Node::Fail => false,
    })
}

fn is_atom(n: &Node) -> bool {
    !matches!(n, Node::At(_) | Node::Repeat { .. })
}

impl Emitter {
    fn seq(&mut self, nodes: &[Node], fl: Flags) {
        for n in nodes {
            self.node(n, fl);
        }
    }

    /// Emits `nodes` as a single quantifiable atom.
    fn atom(&mut self, nodes: &[Node], fl: Flags) {
        if let [single] = nodes
            && is_atom(single)
        {
            self.node(single, fl);
        } else {
            self.out.push_str("(?:");
            self.seq(nodes, fl);
            self.out.push(')');
        }
    }

    fn at(&mut self, at: At, fl: Flags) {
        let multiline = fl.has(Flags::MULTILINE);
        let ascii = fl.has(Flags::ASCII);
        match at {
            At::Beginning if multiline => self.out.push_str("(?m:^)"),
            At::Beginning | At::BeginningString => self.out.push_str(r"\A"),
            At::EndString => self.out.push_str(r"\z"),
            At::End if multiline => self.out.push_str("(?m:$)"),
            At::End => match self.mode {
                Mode::Relaxed => self.out.push_str("(?m:$)"),
                Mode::Primary => {
                    self.gate.newline_only_last = true;
                    self.out.push_str("(?m:$)");
                }
                Mode::Exact => {
                    self.fancy = true;
                    self.out.push_str(r"(?=\n?\z)");
                }
            },
            At::Boundary | At::NonBoundary if self.mode == Mode::Relaxed && !ascii => {}
            At::Boundary | At::NonBoundary
                if ascii && (self.on_fancy || self.mode == Mode::Exact) =>
            {
                self.fancy = true;
                let w = r"[0-9A-Z_a-z]";
                if at == At::Boundary {
                    self.out
                        .push_str(&format!("(?:(?<={w})(?!{w})|(?<!{w})(?={w}))"));
                } else {
                    self.out
                        .push_str(&format!("(?:(?<={w})(?={w})|(?<!{w})(?!{w}))"));
                }
            }
            At::Boundary if ascii => self.out.push_str(r"(?-u:\b)"),
            At::NonBoundary if ascii => self.out.push_str(r"(?-u:\B)"),
            At::Boundary => match self.mode {
                Mode::Relaxed => {}
                Mode::Primary => {
                    self.gate.ascii_only = true;
                    self.out.push_str(r"\b");
                }
                Mode::Exact => {
                    self.fancy = true;
                    let w = WORD_CLASS;
                    self.out
                        .push_str(&format!("(?-i:(?<={w})(?!{w})|(?<!{w})(?={w}))"));
                }
            },
            At::NonBoundary => match self.mode {
                Mode::Relaxed => {}
                Mode::Primary => {
                    self.gate.ascii_only = true;
                    self.out.push_str(r"\B");
                }
                Mode::Exact => {
                    self.fancy = true;
                    let w = WORD_CLASS;
                    self.out
                        .push_str(&format!("(?-i:(?<={w})(?={w})|(?<!{w})(?!{w}))"));
                }
            },
        }
    }

    fn node(&mut self, n: &Node, fl: Flags) {
        match n {
            Node::Lit(c) if fl.has(Flags::ASCII) && fl.has(Flags::IGNORECASE) => {
                let mut ranges = vec![(*c, *c)];
                charset::ascii_fold(&mut ranges);
                self.out.push_str("(?-i:");
                if let [(lo, hi)] = ranges.as_slice()
                    && lo == hi
                {
                    charset::push_literal(&mut self.out, *c);
                } else {
                    charset::push_class(&mut self.out, &ranges, false);
                }
                self.out.push(')');
            }
            Node::Lit(c) if fl.has(Flags::IGNORECASE) && [0x49, 0x69, 0x130, 0x131].contains(c) => {
                let mut ranges = vec![(0x49, 0x49), (0x69, 0x69), (0x130, 0x130), (0x131, 0x131)];
                charset::normalize(&mut ranges);
                charset::push_class(&mut self.out, &ranges, false);
            }
            Node::Lit(c) => charset::push_literal(&mut self.out, *c),
            Node::Any => {
                if fl.has(Flags::DOTALL) {
                    self.out.push_str(ANY_CHAR);
                } else {
                    self.out.push('.');
                }
            }
            Node::Set { negate, items } if fl.has(Flags::ASCII) && fl.has(Flags::IGNORECASE) => {
                let mut ranges = charset::set_ranges(items, true);
                charset::ascii_fold(&mut ranges);
                self.out.push_str("(?-i:");
                charset::push_class(&mut self.out, &ranges, *negate);
                self.out.push(')');
            }
            Node::Set { negate, items }
                if fl.has(Flags::IGNORECASE)
                    && items.iter().all(|i| matches!(i, SetItem::Cat(_))) =>
            {
                // categories are not case-folded by Python
                self.out.push_str("(?-i:");
                charset::push_set(&mut self.out, items, *negate, fl.has(Flags::ASCII));
                self.out.push(')');
            }
            Node::Set { negate, items } if fl.has(Flags::IGNORECASE) && !fl.has(Flags::ASCII) => {
                charset::push_set_icase(&mut self.out, items, *negate);
            }
            Node::Set { negate, items } => {
                charset::push_set(&mut self.out, items, *negate, fl.has(Flags::ASCII));
            }
            Node::At(a) => self.at(*a, fl),
            Node::Group {
                index,
                add,
                del,
                body,
            } => {
                let nfl = fl.combine(*add, *del);
                if index.is_some() {
                    self.out.push('(');
                } else {
                    match (fl.has(Flags::IGNORECASE), nfl.has(Flags::IGNORECASE)) {
                        (false, true) => self.out.push_str("(?i:"),
                        (true, false) => self.out.push_str("(?-i:"),
                        _ => self.out.push_str("(?:"),
                    }
                }
                self.seq(body, nfl);
                self.out.push(')');
            }
            Node::Branch(alts) => {
                self.out.push_str("(?:");
                for (i, alt) in alts.iter().enumerate() {
                    if i > 0 {
                        self.out.push('|');
                    }
                    self.seq(alt, fl);
                }
                self.out.push(')');
            }
            Node::Repeat {
                kind,
                min,
                max,
                body,
            } => self.repeat(*kind, *min, *max, body, fl),
            Node::Backref(_) if self.mode == Mode::Relaxed => self.out.push_str("(?s:.*)"),
            Node::Backref(g) => {
                self.fancy = true;
                self.out.push_str(&format!("(?:\\{g})"));
            }
            Node::Look { .. } if self.mode == Mode::Relaxed => {}
            Node::Look {
                behind,
                negate,
                body,
            } => {
                self.fancy = true;
                self.out.push_str(match (behind, negate) {
                    (false, false) => "(?=",
                    (false, true) => "(?!",
                    (true, false) => "(?<=",
                    (true, true) => "(?<!",
                });
                self.seq(body, fl);
                self.out.push(')');
            }
            Node::Fail => self.out.push_str(NEVER),
            Node::Atomic(body) if self.mode == Mode::Relaxed => {
                self.out.push_str("(?:");
                self.seq(body, fl);
                self.out.push(')');
            }
            Node::Atomic(body) => {
                self.fancy = true;
                self.out.push_str("(?>");
                self.seq(body, fl);
                self.out.push(')');
            }
            Node::Cond { yes, no, .. } if self.mode == Mode::Relaxed => {
                self.out.push_str("(?:");
                self.seq(yes, fl);
                self.out.push('|');
                if let Some(no) = no {
                    self.seq(no, fl);
                }
                self.out.push(')');
            }
            Node::Cond { group, yes, no } => {
                self.fancy = true;
                self.out.push_str(&format!("(?({group})"));
                if yes.is_empty() {
                    // fancy-regex fails an empty true-branch (also `(?:)`)
                    self.out.push_str("(?=)");
                } else {
                    self.seq(yes, fl);
                }
                // An explicit (possibly empty) else-branch: fancy-regex fails some
                // conditionals without one, e.g. `(a+)(?(1)(?:b|))`.
                self.out.push('|');
                if let Some(no) = no {
                    self.seq(no, fl);
                }
                self.out.push(')');
            }
        }
    }

    /// `X{min,max}` for a zero-width `X` (the engines reject repeating
    /// lookarounds). Python enters the loop at most once because an empty
    /// iteration ends it: `X` once when `min >= 1`, else `X` or nothing (in
    /// the order the quantifier's greediness asks for).
    fn repeat_zero_width(
        &mut self,
        kind: RepeatKind,
        min: u64,
        max: Option<u64>,
        body: &[Node],
        fl: Flags,
    ) {
        if max == Some(0) {
            if has_capture(body) {
                // keep the groups (numbering, backreferences) that never run
                self.out.push_str("(?:");
                self.out.push_str(NEVER);
                self.seq(body, fl);
                self.out.push_str("|)");
            }
            return;
        }
        if min >= 1 {
            self.seq(body, fl);
            return;
        }
        match kind {
            RepeatKind::Greedy => {
                self.out.push_str("(?:");
                self.seq(body, fl);
                self.out.push_str("|)");
            }
            RepeatKind::Lazy => {
                self.out.push_str("(?:|");
                self.seq(body, fl);
                self.out.push(')');
            }
            RepeatKind::Possessive => {
                self.fancy = true;
                self.out.push_str("(?>");
                self.seq(body, fl);
                self.out.push_str("|)");
            }
        }
    }

    fn repeat(&mut self, kind: RepeatKind, min: u64, max: Option<u64>, body: &[Node], fl: Flags) {
        let kind = if self.mode == Mode::Relaxed && kind == RepeatKind::Possessive {
            RepeatKind::Greedy
        } else {
            kind
        };
        if zero_width(body) {
            self.repeat_zero_width(kind, min, max, body, fl);
            return;
        }
        if kind == RepeatKind::Possessive {
            // CPython's possessive repeat makes every *iteration* atomic (no
            // backtracking into an earlier iteration, even before the repeat
            // completes), unlike `(?>X{n,m})`: `(?:a+|b){2}+` cannot match
            // "aaa". A single-character body has no such difference.
            self.fancy = true;
            self.out.push_str("(?>");
            if matches!(body, [Node::Lit(_) | Node::Any | Node::Set { .. }]) {
                self.atom(body, fl);
            } else {
                self.out.push_str("(?:(?>");
                self.seq(body, fl);
                self.out.push_str("))");
            }
        } else {
            self.atom(body, fl);
        }
        match (min, max) {
            (0, None) => self.out.push('*'),
            (1, None) => self.out.push('+'),
            (0, Some(1)) => self.out.push('?'),
            (n, None) => self.out.push_str(&format!("{{{n},}}")),
            (n, Some(m)) if n == m => self.out.push_str(&format!("{{{n}}}")),
            (n, Some(m)) => self.out.push_str(&format!("{{{n},{m}}}")),
        }
        if kind == RepeatKind::Lazy {
            self.out.push('?');
        }
        if kind == RepeatKind::Possessive {
            self.out.push(')');
        }
    }
}

/// What the last character consumed by a node sequence is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tail {
    /// Always ends with this code point.
    Char(u32),
    /// Ends with this code point or consumes nothing.
    Opt(u32),
    /// Consumes nothing.
    Zero,
    Unknown,
}

fn tail(nodes: &[Node]) -> Tail {
    let mut pending: Option<u32> = None;
    for n in nodes.iter().rev() {
        match tail_node(n) {
            Tail::Char(c) => {
                return if pending.is_none_or(|p| p == c) {
                    Tail::Char(c)
                } else {
                    Tail::Unknown
                };
            }
            Tail::Opt(c) => {
                if pending.is_some_and(|p| p != c) {
                    return Tail::Unknown;
                }
                pending = Some(c);
            }
            Tail::Zero => {}
            Tail::Unknown => return Tail::Unknown,
        }
    }
    pending.map_or(Tail::Zero, Tail::Opt)
}

fn tail_alts<'a>(alts: impl Iterator<Item = &'a [Node]>) -> Tail {
    let mut ch: Option<u32> = None;
    let mut all_char = true;
    for alt in alts {
        match tail(alt) {
            Tail::Unknown => return Tail::Unknown,
            Tail::Zero => all_char = false,
            t @ (Tail::Char(c) | Tail::Opt(c)) => {
                if ch.is_some_and(|p| p != c) {
                    return Tail::Unknown;
                }
                ch = Some(c);
                all_char &= matches!(t, Tail::Char(_));
            }
        }
    }
    match (ch, all_char) {
        (Some(c), true) => Tail::Char(c),
        (Some(c), false) => Tail::Opt(c),
        (None, _) => Tail::Zero,
    }
}

fn tail_node(n: &Node) -> Tail {
    match n {
        Node::Lit(c) => Tail::Char(*c),
        Node::At(_) | Node::Look { .. } | Node::Fail => Tail::Zero,
        Node::Group { body, .. } | Node::Atomic(body) => tail(body),
        Node::Branch(alts) => tail_alts(alts.iter().map(Vec::as_slice)),
        Node::Repeat { min, body, .. } => match tail(body) {
            Tail::Char(c) if *min == 0 => Tail::Opt(c),
            t => t,
        },
        Node::Cond { yes, no, .. } => tail_alts(
            std::iter::once(yes.as_slice()).chain(std::iter::once(no.as_deref().unwrap_or(&[]))),
        ),
        Node::Any | Node::Set { .. } | Node::Backref(_) => Tail::Unknown,
    }
}

/// Removes `(?<=c)` lookbehinds that are vacuous because the character before
/// them is always `c` (uncased ASCII only). `outer` is the known preceding
/// character at the start of `nodes`.
fn drop_vacuous_lookbehind(nodes: &mut Vec<Node>, outer: Option<u32>) {
    let mut i = 0;
    while i < nodes.len() {
        let prev = match tail(&nodes[..i]) {
            _ if i == 0 => outer,
            Tail::Char(c) => Some(c),
            Tail::Zero => outer,
            Tail::Opt(c) if outer == Some(c) => Some(c),
            Tail::Opt(_) | Tail::Unknown => None,
        };
        if let Node::Look {
            behind: true,
            negate: false,
            body,
        } = &nodes[i]
            && let [Node::Lit(c)] = body.as_slice()
            && prev == Some(*c)
            && char::from_u32(*c).is_some_and(|ch| ch.is_ascii() && !ch.is_ascii_alphabetic())
        {
            nodes.remove(i);
            continue;
        }
        match &mut nodes[i] {
            Node::Group { body, .. } | Node::Atomic(body) => drop_vacuous_lookbehind(body, prev),
            Node::Branch(alts) => {
                for alt in alts {
                    drop_vacuous_lookbehind(alt, prev);
                }
            }
            Node::Cond { yes, no, .. } => {
                drop_vacuous_lookbehind(yes, prev);
                if let Some(no) = no {
                    drop_vacuous_lookbehind(no, prev);
                }
            }
            Node::Look {
                behind: false,
                body,
                ..
            } => drop_vacuous_lookbehind(body, prev),
            Node::Look { body, .. } | Node::Repeat { body, .. } => {
                drop_vacuous_lookbehind(body, None);
            }
            _ => {}
        }
        i += 1;
    }
}

fn emit(nodes: &[Node], flags: Flags, mode: Mode, on_fancy: bool) -> Emitter {
    let mut e = Emitter {
        mode,
        out: String::new(),
        fancy: false,
        gate: Gate::default(),
        on_fancy,
    };
    let wrap = flags.has(Flags::IGNORECASE);
    if wrap {
        e.out.push_str("(?i:");
    }
    e.seq(nodes, flags);
    if wrap {
        e.out.push(')');
    }
    if e.out.is_empty() {
        e.out.push_str("(?:)");
    }
    e
}

/// Translates a Python `re` pattern (a `str` pattern compiled with
/// `re.MULTILINE` when `multiline`) for the Rust engines.
///
/// # Errors
/// [`PyReError`] with CPython's message wherever `re.compile` raises.
pub fn translate(pattern: &str, multiline: bool) -> Result<Translated, PyReError> {
    let flags = Flags(if multiline { Flags::MULTILINE } else { 0 });
    let mut parsed = pyparse::parse(pattern, flags)?;
    drop_vacuous_lookbehind(&mut parsed.nodes, None);
    let mut primary = emit(&parsed.nodes, parsed.flags, Mode::Primary, false);
    if primary.fancy {
        primary = emit(&parsed.nodes, parsed.flags, Mode::Primary, true);
    }
    let (exact, gate) = if primary.gate.is_open() {
        (None, primary.gate)
    } else {
        (
            Some(emit(&parsed.nodes, parsed.flags, Mode::Exact, true).out),
            primary.gate,
        )
    };
    let prefilter = (primary.fancy || exact.is_some())
        .then(|| emit(&parsed.nodes, parsed.flags, Mode::Relaxed, false).out);
    Ok(Translated {
        primary: primary.out,
        prefilter,
        primary_engine: if primary.fancy {
            EngineKind::Backtracking
        } else {
            EngineKind::Linear
        },
        exact,
        gate,
        groups: parsed.groups,
        names: parsed.names,
        flags: parsed.flags,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tr(p: &str) -> Translated {
        translate(p, false).unwrap_or_else(|e| panic!("{p}: {e}"))
    }

    /// postfix.conf: `[^[]*\[<HOST>\]`; a bare `[` is literal in Python.
    #[test]
    fn bare_bracket_in_class_is_literal() {
        let t = tr(r"^from [^[]*\[x\]");
        assert_eq!(t.primary_engine, EngineKind::Linear);
        let re = regex::Regex::new(&t.primary).unwrap();
        assert!(re.is_match("from abc[x]"));
        assert!(!re.is_match("from a[b[x]"));
    }

    /// Set operators of Rust are plain members in Python.
    #[test]
    fn set_operator_sequences_are_members() {
        let re = regex::Regex::new(&tr("[a&&b~~c]+").primary).unwrap();
        assert_eq!(re.find("x&&~~y").map(|m| m.as_str()), Some("&&~~"));
        let re = regex::Regex::new(&tr("[,--]+").primary).unwrap();
        assert_eq!(re.find("x,-y").map(|m| m.as_str()), Some(",-"));
    }

    /// `IP_6_RE`'s `(?<=:):` is vacuous and must not push `<HOST>` patterns
    /// onto the backtracking engine.
    #[test]
    fn vacuous_lookbehind_of_ip6_keeps_linear_engine() {
        let host = crate::resolve_host_tag("^<HOST>$", crate::UseDns::Yes);
        let t = tr(&host);
        assert_eq!(t.primary_engine, EngineKind::Linear);
        assert!(!t.primary.contains("(?<="), "{}", t.primary);
        // a lookbehind that is not vacuous stays
        assert_eq!(tr("(?<=a)b").primary_engine, EngineKind::Backtracking);
    }

    /// apache-noscript.conf: `(?P<_q>')...(?(_q)'|)`.
    #[test]
    fn conditional_on_named_group() {
        let t = tr(r"^(?:stderr from |script (?P<_q>'))x\b\S*(?(_q)'|) end");
        assert_eq!(t.primary_engine, EngineKind::Backtracking);
        assert_eq!(t.names, vec![("_q".to_owned(), 1)]);
        let re = fancy_regex::Regex::new(&t.primary).unwrap();
        assert!(re.is_match("script 'x' end").unwrap());
        assert!(!re.is_match("script 'x end").unwrap());
        assert!(re.is_match("stderr from x end").unwrap());
    }

    /// `$` without MULTILINE also matches before a final `\n`; the gate keeps
    /// the linear pattern exact and routes other buffers to the exact one.
    #[test]
    fn dollar_gate() {
        let t = tr("a$");
        assert!(t.gate.newline_only_last);
        assert!(t.exact.is_some());
        assert!(t.gate.admits("xa\n"));
        assert!(!t.gate.admits("a\nb\n"));
        assert!(translate("a$", true).unwrap().exact.is_none());
    }

    #[test]
    fn python_errors_are_reported_with_positions() {
        assert_eq!(
            translate("a**", false).unwrap_err().to_string(),
            "multiple repeat at position 2"
        );
        assert_eq!(
            translate("(?<=a+)b", false).unwrap_err().to_string(),
            "look-behind requires fixed-width pattern"
        );
    }
}
