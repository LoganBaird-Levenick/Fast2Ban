//! `substituteRecursiveTags`: safe recursive interpolation of `<tag>` references.

use crate::pychar::repr_str;
use indexmap::IndexMap;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fmt;

/// Fallback resolver for tag names that are not keys of the tag map (upstream's `addrepl`).
pub type AddRepl<'a> = &'a dyn Fn(&str) -> Option<String>;

/// Maximum number of times tag X may be substituted into tag Y (`MAX_TAG_REPLACE_COUNT`).
pub const MAX_TAG_REPLACE_COUNT: u32 = 25;

/// Self-referencing (or runaway embedded) tag definitions that cannot be resolved.
///
/// `Display` is upstream's `ValueError` message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagError {
    /// Tag whose value was being substituted.
    pub tag: String,
    /// Tag found in the value that triggered the failure.
    pub found: String,
    /// Python `repr` of the substitution-count dict of `tag` at that point
    /// (e.g. `{'a': 1, 'b': 26}`).
    pub counts: String,
    /// Value of `tag` at that point.
    pub value: String,
}

impl fmt::Display for TagError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "properties contain self referencing definitions and cannot be resolved, \
             fail tag: {}, found: {} in {}, value: {}",
            self.tag, self.found, self.counts, self.value
        )
    }
}

impl std::error::Error for TagError {}

/// Leftmost match of `TAG_CRE` (`<([^ <>]+)>`) at or after byte offset `from`:
/// `(start, end)` of the whole `<tag>`.
fn find_tag(s: &str, from: usize) -> Option<(usize, usize)> {
    let b = s.as_bytes();
    let mut i = from;
    while let Some(off) = s[i..].find('<') {
        let start = i + off;
        // Bytes of multi-byte characters never equal these ASCII delimiters.
        let name = b[start + 1..]
            .iter()
            .take_while(|&&c| !matches!(c, b' ' | b'<' | b'>'))
            .count();
        let end = start + 1 + name;
        if name > 0 && b.get(end) == Some(&b'>') {
            return Some((start, end + 1));
        }
        i = start + 1;
    }
    None
}

fn counts_repr(counts: &IndexMap<String, u32>) -> String {
    let items: Vec<String> = counts
        .iter()
        .map(|(k, n)| format!("{}: {n}", repr_str(k)))
        .collect();
    format!("{{{}}}", items.join(", "))
}

/// `helpers.substituteRecursiveTags`: replaces `<tag>` references inside the values of
/// `inptags` by the values of the referenced tags, recursively (including tags built
/// from other tags, like `<<A><B>>`).
///
/// * With a non-empty `conditional` (e.g. `family=inet6`), `<x>` is first looked up as
///   `x?conditional`, then as `x`.
/// * References whose name is in `ignore` are left alone, and so are tags in `ignore`
///   themselves (their values are not processed).
/// * `addrepl` is consulted for names that are not tags (upstream passes
///   `getCombOption`); names it does not resolve are left in place, like all
///   unknown names (`<HOST>`, `<STDIN>`, ...).
///
/// The result has the same keys in the same order as `inptags`; values are updated in
/// place. `inptags` itself is never modified.
///
/// Extension point: upstream also accepts `CallingMap` inputs whose callable values
/// (`getRawItem`) are skipped and converted lazily on lookup. That is not needed by the
/// config layer and is not modelled; the later action engine will add its own
/// substitution entry point for it.
///
/// # Errors
/// [`TagError`] when a tag (transitively) references itself, or an embedded-recursive
/// tag is substituted more than [`MAX_TAG_REPLACE_COUNT`] times.
pub fn substitute_recursive_tags(
    inptags: &IndexMap<String, String>,
    conditional: &str,
    ignore: &HashSet<String>,
    addrepl: Option<AddRepl<'_>>,
) -> Result<IndexMap<String, String>, TagError> {
    // Copy of `inptags` with substituted values, created on first change (Python:
    // `tags = inptags.copy()`). Keys and order never change, so tags are addressed by
    // their index.
    let mut work: Option<IndexMap<String, String>> = None;
    let mut done = vec![false; inptags.len()];
    let mut rep_counts: HashMap<usize, IndexMap<String, u32>> = HashMap::new();
    loop {
        let mut rep_flag = false;
        for (idx, is_done) in done.iter_mut().enumerate() {
            let tags = work.as_ref().unwrap_or(inptags);
            let Some((tag, orgval)) = tags.get_index(idx) else {
                break;
            };
            if ignore.contains(tag.as_str()) || *is_done {
                continue;
            }
            let mut value = orgval.clone();
            let had_counts = rep_counts.contains_key(&idx);
            let mut rplc = rep_counts.remove(&idx).unwrap_or_default();
            let mut m = find_tag(&value, 0);
            while let Some((start, end)) = m {
                let rtag = value[start + 1..end - 1].to_owned();
                if ignore.contains(rtag.as_str()) {
                    m = find_tag(&value, end);
                    continue;
                }
                if rtag == *tag || rplc.get(&rtag).copied().unwrap_or(1) > MAX_TAG_REPLACE_COUNT {
                    return Err(TagError {
                        tag: tag.clone(),
                        found: rtag,
                        counts: counts_repr(&rplc),
                        value,
                    });
                }
                let mut repl: Option<Cow<'_, str>> = None;
                if !conditional.is_empty() {
                    repl = tags
                        .get(&format!("{rtag}?{conditional}"))
                        .map(|v| Cow::Borrowed(v.as_str()));
                }
                if repl.is_none() {
                    repl = tags.get(&rtag).map(|v| Cow::Borrowed(v.as_str()));
                    if repl.is_none() {
                        repl = addrepl.and_then(|f| f(&rtag)).map(Cow::Owned);
                    }
                }
                let Some(repl) = repl else {
                    // Missing tags are fine (`<HOST>`, `<STDIN>`): continue after them.
                    m = find_tag(&value, end);
                    continue;
                };
                // Python resumes the search at the numeric offset `m.start()` of the
                // *new* value; offsets are characters there, so convert.
                let char_start = value[..start].chars().count();
                value = value.replace(&format!("<{rtag}>"), &repl);
                *rplc.entry(rtag).or_insert(0) += 1;
                let resume = value
                    .char_indices()
                    .nth(char_start)
                    .map_or(value.len(), |(b, _)| b);
                m = find_tag(&value, resume);
            }
            let changed = value != *orgval;
            let mut keep_counts = had_counts;
            if changed {
                // Still contains a tag: possible embedded-recursive substitution.
                if find_tag(&value, 0).is_some() {
                    keep_counts = true;
                    rep_flag = true;
                }
            }
            if keep_counts {
                rep_counts.insert(idx, rplc);
            }
            let unresolved = value.contains('<');
            if changed
                && let Some((_, slot)) = work
                    .get_or_insert_with(|| inptags.clone())
                    .get_index_mut(idx)
            {
                *slot = value;
            }
            if !unresolved {
                *is_done = true;
            }
        }
        if !rep_flag {
            break;
        }
    }
    Ok(work.unwrap_or_else(|| inptags.clone()))
}
