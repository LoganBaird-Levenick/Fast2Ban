//! Intermediate form of a parsed Python `re` pattern (the equivalent of
//! `sre_parse`'s `SubPattern` tree), as far as it is needed to re-emit the
//! pattern for the Rust engines.

/// `_sre.MAXREPEAT` (64-bit build, Python 3.14): "unbounded" repeat count.
pub(crate) const MAXREPEAT: u64 = 4_294_967_295;
/// `sre_parse.MAXWIDTH`.
const MAXWIDTH: u128 = 1 << 64;
/// `_sre.MAXCODE` (`CODESIZE` is 4 bytes).
const MAXCODE: u128 = 4_294_967_295;

/// Inline / global flag set (the `SRE_FLAG_*` subset that matters for `str`
/// patterns).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Flags(pub u32);

impl Flags {
    pub const IGNORECASE: u32 = 2;
    pub const LOCALE: u32 = 4;
    pub const MULTILINE: u32 = 8;
    pub const DOTALL: u32 = 16;
    pub const UNICODE: u32 = 32;
    pub const VERBOSE: u32 = 64;
    pub const ASCII: u32 = 256;
    /// `TYPE_FLAGS`: the mutually exclusive character-set flags.
    pub const TYPE_FLAGS: u32 = Self::ASCII | Self::LOCALE | Self::UNICODE;

    pub fn has(self, flag: u32) -> bool {
        self.0 & flag != 0
    }

    /// `_compiler._combine_flags`.
    pub fn combine(self, add: Flags, del: Flags) -> Flags {
        let mut flags = self.0;
        if add.0 & Self::TYPE_FLAGS != 0 {
            flags &= !Self::TYPE_FLAGS;
        }
        Flags((flags | add.0) & !del.0)
    }
}

/// `CATEGORY_*` classes (`\d \D \s \S \w \W`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Cat {
    Digit,
    NotDigit,
    Space,
    NotSpace,
    Word,
    NotWord,
}

/// `AT_*` zero-width assertions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum At {
    /// `^`
    Beginning,
    /// `$`
    End,
    /// `\A`
    BeginningString,
    /// `\Z` / `\z`
    EndString,
    /// `\b`
    Boundary,
    /// `\B`
    NonBoundary,
}

/// One member of a character set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SetItem {
    Lit(u32),
    Range(u32, u32),
    Cat(Cat),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RepeatKind {
    Greedy,
    Lazy,
    Possessive,
}

/// A parsed node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Node {
    /// A literal code point (may be a lone surrogate from `\ud800`, which no
    /// Rust `str` can contain).
    Lit(u32),
    /// `.`
    Any,
    /// `[...]` (a one-member positive set is turned into [`Node::Lit`] as
    /// `sre_parse` does).
    Set {
        negate: bool,
        items: Vec<SetItem>,
    },
    At(At),
    /// `(...)`, `(?:...)` and `(?flags:...)`.
    Group {
        index: Option<usize>,
        add: Flags,
        del: Flags,
        body: Vec<Node>,
    },
    /// `a|b|c` (two or more alternatives).
    Branch(Vec<Vec<Node>>),
    Repeat {
        kind: RepeatKind,
        min: u64,
        /// `None` is `MAXREPEAT` (unbounded).
        max: Option<u64>,
        body: Vec<Node>,
    },
    /// `\N` / `(?P=name)`
    Backref(usize),
    /// `(?=..)`, `(?!..)`, `(?<=..)`, `(?<!..)`
    Look {
        behind: bool,
        negate: bool,
        body: Vec<Node>,
    },
    /// `(?!)`: an empty negative lookaround, which can never match.
    Fail,
    /// `(?>...)`
    Atomic(Vec<Node>),
    /// `(?(group)yes|no)`
    Cond {
        group: usize,
        yes: Vec<Node>,
        no: Option<Vec<Node>>,
    },
}

/// `(min, max)` width of a subpattern, `SubPattern.getwidth()`.
pub(crate) type Width = (u128, u128);

/// Widths of the already closed groups (index 0 is the whole pattern).
pub(crate) type GroupWidths = [Option<Width>];

/// `SubPattern.getwidth()`.
pub(crate) fn width(nodes: &[Node], groups: &GroupWidths) -> Width {
    let mut lo: u128 = 0;
    let mut hi: u128 = 0;
    for node in nodes {
        match node {
            Node::Branch(alts) => {
                let mut i = MAXWIDTH;
                let mut j = 0;
                for alt in alts {
                    let (l, h) = width(alt, groups);
                    i = i.min(l);
                    j = j.max(h);
                }
                lo += i;
                hi += j;
            }
            Node::Atomic(body) | Node::Group { body, .. } => {
                let (i, j) = width(body, groups);
                lo += i;
                hi += j;
            }
            Node::Repeat { min, max, body, .. } => {
                let (i, j) = width(body, groups);
                lo += i * u128::from(*min);
                match max {
                    None if j != 0 => hi = MAXWIDTH,
                    None => hi += j * u128::from(MAXREPEAT),
                    Some(max) => hi += j * u128::from(*max),
                }
            }
            Node::Lit(_) | Node::Any | Node::Set { .. } => {
                lo += 1;
                hi += 1;
            }
            Node::Backref(g) => {
                let (i, j) = groups.get(*g).copied().flatten().unwrap_or((0, 0));
                lo += i;
                hi += j;
            }
            Node::Cond { yes, no, .. } => {
                let (mut i, mut j) = width(yes, groups);
                match no {
                    Some(no) => {
                        let (l, h) = width(no, groups);
                        i = i.min(l);
                        j = j.max(h);
                    }
                    None => i = 0,
                }
                lo += i;
                hi += j;
            }
            Node::At(_) | Node::Look { .. } | Node::Fail => {}
        }
        // Python clamps only at the end of each subpattern; the running sums
        // cannot overflow u128 before that (each term is <= 2^64 * 2^32).
    }
    (lo.min(MAXWIDTH), hi.min(MAXWIDTH))
}

/// Compile-stage checks of `_compiler._compile` that can fail: lookbehind
/// widths. Returns the error message, in compile (depth-first) order.
pub(crate) fn check_lookbehind(nodes: &[Node], groups: &GroupWidths) -> Result<(), &'static str> {
    for node in nodes {
        match node {
            Node::Look {
                behind,
                negate: _,
                body,
            } => {
                if *behind {
                    let (lo, hi) = width(body, groups);
                    if lo > MAXCODE {
                        return Err("looks too much behind");
                    }
                    if lo != hi {
                        return Err("look-behind requires fixed-width pattern");
                    }
                }
                check_lookbehind(body, groups)?;
            }
            Node::Group { body, .. } | Node::Atomic(body) | Node::Repeat { body, .. } => {
                check_lookbehind(body, groups)?;
            }
            Node::Branch(alts) => {
                for alt in alts {
                    check_lookbehind(alt, groups)?;
                }
            }
            Node::Cond { yes, no, .. } => {
                check_lookbehind(yes, groups)?;
                if let Some(no) = no {
                    check_lookbehind(no, groups)?;
                }
            }
            Node::Lit(_)
            | Node::Any
            | Node::Set { .. }
            | Node::At(_)
            | Node::Backref(_)
            | Node::Fail => {}
        }
    }
    Ok(())
}
