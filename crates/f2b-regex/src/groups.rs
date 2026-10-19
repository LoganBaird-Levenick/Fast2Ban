//! Group dictionaries (`getGroups()`), tuple lines and the `str.splitlines`
//! used by upstream.

use std::borrow::Cow;

/// Value of a group in `Match.groupdict()` after upstream's alt/tuple merging.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GroupValue<S> {
    /// `None`: the group did not participate in the match (or was never set).
    None,
    /// A matched string (possibly empty).
    Str(S),
    /// Combination of `<F-TUPLE_x>` parts (see [`crate::Match::groups`]); items
    /// are `None` for parts that did not participate.
    Tuple(Vec<Option<S>>),
}

impl<S> GroupValue<S> {
    /// Python truthiness: `None` and the empty string are false; a tuple is
    /// true when it has items.
    #[must_use]
    pub fn is_truthy(&self) -> bool
    where
        S: AsRef<str>,
    {
        match self {
            GroupValue::None => false,
            GroupValue::Str(s) => !s.as_ref().is_empty(),
            GroupValue::Tuple(t) => !t.is_empty(),
        }
    }

    /// The string, if this is [`GroupValue::Str`].
    #[must_use]
    pub fn as_str(&self) -> Option<&str>
    where
        S: AsRef<str>,
    {
        match self {
            GroupValue::Str(s) => Some(s.as_ref()),
            _ => None,
        }
    }
}

impl GroupValue<&str> {
    /// Copies the borrowed text.
    #[must_use]
    pub fn to_owned_value(&self) -> GroupValue<String> {
        match self {
            GroupValue::None => GroupValue::None,
            GroupValue::Str(s) => GroupValue::Str((*s).to_owned()),
            GroupValue::Tuple(t) => {
                GroupValue::Tuple(t.iter().map(|o| o.map(str::to_owned)).collect())
            }
        }
    }
}

/// The dictionary returned by upstream's `getGroups()`: insertion-ordered
/// (named groups in definition order, then merged `alt_`/`tuple_` targets that
/// are not themselves groups).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Groups<'a> {
    entries: Vec<(&'a str, GroupValue<&'a str>)>,
}

impl<'a> Groups<'a> {
    pub(crate) fn with_capacity(n: usize) -> Groups<'a> {
        Groups {
            entries: Vec::with_capacity(n),
        }
    }

    pub(crate) fn push(&mut self, key: &'a str, value: GroupValue<&'a str>) {
        self.entries.push((key, value));
    }

    /// `dict.get(key)`: `None` when the key is absent; a present key whose
    /// group did not match yields `Some(&GroupValue::None)`.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&GroupValue<&'a str>> {
        self.entries.iter().find(|(k, _)| *k == key).map(|(_, v)| v)
    }

    /// `fail.get(key)` as the matched string.
    #[must_use]
    pub fn get_str(&self, key: &str) -> Option<&'a str> {
        match self.get(key) {
            Some(GroupValue::Str(s)) => Some(s),
            _ => None,
        }
    }

    /// `dict[key] = value`: replaces in place or appends.
    pub(crate) fn set(&mut self, key: &'a str, value: GroupValue<&'a str>) {
        match self.entries.iter_mut().find(|(k, _)| *k == key) {
            Some((_, v)) => *v = value,
            None => self.entries.push((key, value)),
        }
    }

    /// Entries in dictionary order.
    pub fn iter(&self) -> impl Iterator<Item = (&'a str, &GroupValue<&'a str>)> {
        self.entries.iter().map(|(k, v)| (*k, v))
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Owned copy, for storing beyond the buffer's lifetime.
    #[must_use]
    pub fn into_owned(self) -> Vec<(String, GroupValue<String>)> {
        self.entries
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned_value()))
            .collect()
    }
}

/// One `(prematch, datematch, postdatematch)` tuple of upstream's line buffer.
///
/// The searched text of a line is `pre + post` (the date part is cut out),
/// i.e. Python's `"".join(v[::2])`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TupleLine<S = String> {
    /// Text before the date match.
    pub pre: S,
    /// The date match.
    pub date: S,
    /// Text after the date match.
    pub post: S,
}

impl<S: AsRef<str>> TupleLine<S> {
    /// `TupleLine { pre, date, post }`.
    pub fn new(pre: S, date: S, post: S) -> TupleLine<S> {
        TupleLine { pre, date, post }
    }

    /// Whether `pre + post == text`.
    pub(crate) fn text_eq(&self, text: &str) -> bool {
        let pre = self.pre.as_ref();
        let post = self.post.as_ref();
        text.len() == pre.len() + post.len() && text.starts_with(pre) && text[pre.len()..] == *post
    }
}

/// `Regex._tupleLinesBuf`: the lines' `pre + post` joined by `\n` plus a final
/// `\n`, written into `out` (which is cleared first, so a buffer can be
/// reused for every line).
pub fn tuple_lines_buf<S: AsRef<str>>(lines: &[TupleLine<S>], out: &mut String) {
    out.clear();
    for (i, line) in lines.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(line.pre.as_ref());
        out.push_str(line.post.as_ref());
    }
    out.push('\n');
}

/// `str.splitlines(False)`.
pub(crate) fn splitlines(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut chars = s.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        let is_break = matches!(
            c,
            '\n' | '\r'
                | '\u{b}'
                | '\u{c}'
                | '\u{1c}'
                | '\u{1d}'
                | '\u{1e}'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        );
        if !is_break {
            continue;
        }
        out.push(&s[start..i]);
        let mut next = i + c.len_utf8();
        if c == '\r' && chars.peek().is_some_and(|&(_, n)| n == '\n') {
            chars.next();
            next += 1;
        }
        start = next;
    }
    if start < s.len() {
        out.push(&s[start..]);
    }
    out
}

/// `splitlines` of a possibly owned string, as borrowed or owned lines.
pub(crate) fn split_cow(s: Cow<'_, str>) -> Vec<Cow<'_, str>> {
    match s {
        Cow::Borrowed(b) => splitlines(b).into_iter().map(Cow::Borrowed).collect(),
        Cow::Owned(o) => splitlines(&o)
            .into_iter()
            .map(|l| Cow::Owned(l.to_owned()))
            .collect(),
    }
}
