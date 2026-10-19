use crate::pychar::is_space;
use indexmap::IndexMap;
use std::borrow::Cow;

/// `helpers._as_bool` for a string value: `val.lower() in ('1', 'on', 'true', 'yes')`.
///
/// Only ASCII case folding can turn a character into one of the accepted spellings,
/// so ASCII case-insensitive comparison is exactly Python's `str.lower()` test.
#[must_use]
pub fn as_bool(val: &str) -> bool {
    ["1", "on", "true", "yes"]
        .iter()
        .any(|t| val.eq_ignore_ascii_case(t))
}

/// `helpers.removeComments`: removes `# ...` / `; ...` comments (up to the end of the
/// line) that start a line or follow a whitespace character. The whitespace character
/// in front of the comment marker is removed together with the comment, exactly like
/// upstream's `(?m)(?:^|\s)[\#;].*` substitution (including when that whitespace is a
/// newline).
#[must_use]
pub fn remove_comments(s: &str) -> Cow<'_, str> {
    let is_marker = |c: Option<char>| matches!(c, Some('#' | ';'));
    let mut out: Option<String> = None;
    let mut copied = 0; // bytes of `s` already flushed to `out`
    let mut prev: Option<char> = None; // character before the current position
    let mut iter = s.char_indices().peekable();
    while let Some((j, c)) = iter.next() {
        let line_start = prev.is_none_or(|p| p == '\n');
        // First alternative `^[#;]` (no whitespace consumed), then `\s[#;]`.
        // `marker` is the byte offset of the `[#;]` character.
        let marker = if line_start && is_marker(Some(c)) {
            j
        } else if is_space(c) && is_marker(iter.peek().map(|&(_, n)| n)) {
            j + c.len_utf8()
        } else {
            prev = Some(c);
            continue;
        };
        let start = j;
        // `.*`: everything after the marker up to (not including) the next '\n'.
        let end = s[marker + 1..]
            .find('\n')
            .map_or(s.len(), |k| marker + 1 + k);
        let buf = out.get_or_insert_with(|| String::with_capacity(s.len()));
        buf.push_str(&s[copied..start]);
        copied = end;
        // Resume scanning at `end`; `prev` is the last character of the match, which
        // is never '\n' (the match stops before it).
        prev = s[start..end].chars().next_back();
        while iter.peek().is_some_and(|&(k, _)| k < end) {
            iter.next();
        }
    }
    match out {
        None => Cow::Borrowed(s),
        Some(mut buf) => {
            buf.push_str(&s[copied..]);
            Cow::Owned(buf)
        }
    }
}

/// `helpers.splitwords`: splits on any run of whitespace and/or commas and drops empty
/// entries. With `ignore_comments`, [`remove_comments`] is applied first.
#[must_use]
pub fn splitwords(s: &str, ignore_comments: bool) -> Vec<String> {
    let s = if ignore_comments {
        remove_comments(s)
    } else {
        Cow::Borrowed(s)
    };
    s.split(|c: char| c == ',' || is_space(c))
        .filter(|w| !w.is_empty())
        .map(str::to_owned)
        .collect()
}

/// `helpers._merge_dicts`: `{**x, **y}` when `y` is non-empty, otherwise `x` itself
/// (borrowed, not copied). Keys of `y` that already exist in `x` keep `x`'s position
/// and take `y`'s value; new keys are appended in `y`'s order.
#[must_use]
pub fn merge_dicts<'a>(
    x: &'a IndexMap<String, String>,
    y: &IndexMap<String, String>,
) -> Cow<'a, IndexMap<String, String>> {
    if y.is_empty() {
        return Cow::Borrowed(x);
    }
    let mut merged = x.clone();
    merged.extend(y.iter().map(|(k, v)| (k.clone(), v.clone())));
    Cow::Owned(merged)
}
