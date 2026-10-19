//! Port of upstream `server/datetemplate.py`: `DateTemplate`, `DatePatternRegex`,
//! `DateEpoch` and `DateTai64n`.

use std::sync::LazyLock;

use f2b_helpers::pychar;

use crate::civil::{PyExc, PyResult};
use crate::error::DateError;
use crate::pyint::py_float;
use crate::pyre::{Caps, PyRegex, compile_py_regex, sub_all};
use crate::strptime::{TimeCtx, TimeRe, expand_pattern, group_dict_to_time};

pub(crate) const LINE_BEGIN: u8 = 8;
pub(crate) const LINE_END: u8 = 4;
pub(crate) const WORD_BEGIN: u8 = 2;
pub(crate) const WORD_END: u8 = 1;

fn re(p: &str) -> PyRegex {
    compile_py_regex(p).unwrap_or_else(|e| unreachable!("static pattern {p}: {e}"))
}

// check already grouped contains "(", but ignores char "\(" and conditional "(?(id)...)":
pub(crate) static RE_GROUPED: LazyLock<PyRegex> =
    LazyLock::new(|| re(r"(?<!(?:\(\?))(?<!\\)\((?!\?)"));
static RE_GLOBALFLAGS: LazyLock<PyRegex> = LazyLock::new(|| re(r"((?:^|(?<!\\))\(\?[a-z]+\))"));
static RE_EXLINE_NO_BOUNDS: LazyLock<PyRegex> = LazyLock::new(|| re(r"^\{UNB\}"));
static RE_EXLINE_BOUND_BEG: LazyLock<PyRegex> = LazyLock::new(|| re(r"^\{\^LN-BEG\}"));
static RE_EXSANC_BOUND_BEG: LazyLock<PyRegex> = LazyLock::new(|| re(r"^\((?:\?:)?\^\|\\b\|\\W\)"));
static RE_EXEANC_BOUND_BEG: LazyLock<PyRegex> = LazyLock::new(|| re(r"\(\?=\\b\|\\W\|\$\)$"));
static RE_NO_WRD_BOUND_BEG: LazyLock<PyRegex> =
    LazyLock::new(|| re(r"^\(*(?:\(\?\w+\))?(?:\^|\(*\*\*|\((?:\?:)?\^)"));
static RE_NO_WRD_BOUND_END: LazyLock<PyRegex> =
    LazyLock::new(|| re(r"(?<!\\)(?:\$\)?|\\b|\\s|\*\*\)*)$"));
static RE_DEL_WRD_BOUNDS: LazyLock<PyRegex> =
    LazyLock::new(|| re(r"^\(*(?:\(\?\w+\))?\(*\*\*|(?<!\\)\*\*\)*$"));
static RE_LINE_BOUND_BEG: LazyLock<PyRegex> =
    LazyLock::new(|| re(r"^(?:\(\?\w+\))?(?:\^|\((?:\?:)?\^(?!\|))"));
static RE_LINE_BOUND_END: LazyLock<PyRegex> = LazyLock::new(|| re(r"(?<![\\\|])(?:\$\)?)$"));
static RE_ALPHA_PATTERN: LazyLock<PyRegex> = LazyLock::new(|| re(r"(?<!\%)\%[aAbBpc]"));
pub(crate) static RE_EPOCH_PATTERN: LazyLock<PyRegex> =
    LazyLock::new(|| re(r"(?i)(?<!\\)\{L?EPOCH\}"));
pub(crate) static RE_DATE_PREMATCH: LazyLock<PyRegex> =
    LazyLock::new(|| re(r"(?i)(?<!\\)\{DATE\}"));

/// `wordBegin` argument of `DateTemplate.setRegex`: `False`, `True` or `'start'`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WordBegin {
    No,
    Word,
    Start,
}

/// `DateTemplate.unboundPattern`.
pub(crate) fn unbound_pattern(pattern: &str) -> String {
    let s = sub_all(&RE_EXLINE_NO_BOUNDS, pattern, 0, |_, _| String::new());
    let s = sub_all(&RE_EXLINE_BOUND_BEG, &s, 0, |_, _| String::new());
    let s = sub_all(&RE_EXSANC_BOUND_BEG, &s, 0, |_, _| String::new());
    sub_all(&RE_EXEANC_BOUND_BEG, &s, 0, |_, _| String::new())
}

/// `RE_GROUP[0].sub(r"\1(\2)\3", regex)`: wrap the body (without leading
/// flags/`^` and trailing `$`) into a group.
fn add_group(regex: &str) -> String {
    if regex.contains('\n') {
        // `.` does not match a newline: no match, regex unchanged
        return regex.to_string();
    }
    let flag_group_len = |s: &str| -> usize {
        // `\(\?\w+\)`
        let Some(r) = s.strip_prefix("(?") else {
            return 0;
        };
        let w: usize = r
            .chars()
            .take_while(|c| pychar::is_word(*c))
            .map(char::len_utf8)
            .sum();
        if w > 0 && r[w..].starts_with(')') {
            2 + w + 1
        } else {
            0
        }
    };
    let mut i = flag_group_len(regex);
    if regex[i..].starts_with('^') {
        i += 1;
    }
    i += flag_group_len(&regex[i..]);
    let rest = &regex[i..];
    let (body, dollar) = match rest.strip_suffix('$') {
        Some(b) => (b, "$"),
        None => (rest, ""),
    };
    format!("{}({}){}", &regex[..i], body, dollar)
}

/// `DateTemplate.setRegex`: returns the final regex and the flags; may
/// prefix `name` with `{^LN-BEG}`.
fn finish_regex(
    name: &mut String,
    regex: &str,
    word_begin: WordBegin,
    word_end: bool,
) -> (String, u8) {
    let mut regex = pychar::strip(regex).to_string();
    // cut global flags like (?iu) from RE in order to pre-set it after processing:
    let gf = RE_GLOBALFLAGS
        .search(&regex, 0)
        .and_then(|c| c[1])
        .map(|(s, e)| {
            let g = regex[s..e].to_string();
            regex.replace_range(s..e, "");
            g
        });
    // check word boundaries needed:
    let bound_begin =
        word_begin != WordBegin::No && RE_NO_WRD_BOUND_BEG.search(&regex, 0).is_none();
    let bound_end = word_end && RE_NO_WRD_BOUND_END.search(&regex, 0).is_none();
    // if no group add it now, should always have a group(1):
    if RE_GROUPED.search(&regex, 0).is_none() {
        regex = add_group(&regex);
    }
    let mut flags = 0;
    if bound_begin {
        flags |= if word_begin != WordBegin::Start {
            WORD_BEGIN
        } else {
            LINE_BEGIN
        };
        if word_begin != WordBegin::Start {
            regex.insert_str(0, r"(?=^|\b|\W)");
        } else {
            regex.insert_str(0, r"^(?:\W{0,2})?");
            if !name.starts_with("{^LN-BEG}") {
                name.insert_str(0, "{^LN-BEG}");
            }
        }
    }
    if bound_end {
        flags |= WORD_END;
        regex.push_str(r"(?=\b|\W|$)");
    }
    if flags & LINE_BEGIN == 0 && RE_LINE_BOUND_BEG.search(&regex, 0).is_some() {
        flags |= LINE_BEGIN;
    }
    if flags & LINE_END == 0 && RE_LINE_BOUND_END.search(&regex, 0).is_some() {
        flags |= LINE_END;
    }
    // remove possible special pattern "**" in front and end of regex:
    let regex = sub_all(&RE_DEL_WRD_BOUNDS, &regex, 0, |c, t| {
        let (s, e) = c[0].unwrap_or((0, 0));
        t[s..e].replace("**", "")
    });
    let regex = match gf {
        Some(g) => g + &regex, // restore global flags
        None => regex,
    };
    (regex, flags)
}

#[derive(Debug, Clone)]
pub(crate) enum Kind {
    /// `DatePatternRegex`, with its original `pattern`
    Pattern {
        pattern: String,
    },
    /// `DateEpoch`; `grp_idx` is the group holding the number
    Epoch {
        grp_idx: usize,
        long_frm: bool,
    },
    Tai64n,
}

#[derive(Debug, Clone)]
pub(crate) struct Template {
    pub name: String,
    pub weight: f64,
    /// `DateTemplate.hits`: successful `matchDate` calls
    pub hits: u64,
    pub flags: u8,
    pub regex: String,
    pub kind: Kind,
    re: PyRegex,
    /// `(group index, name)` of the named groups (for `groupdict()`)
    groups: Vec<(usize, String)>,
}

fn pattern_err(pattern: &str, message: impl std::fmt::Display) -> DateError {
    DateError::Pattern {
        pattern: pattern.to_string(),
        message: message.to_string(),
    }
}

impl Template {
    fn build(
        name: String,
        regex: String,
        flags: u8,
        kind: Kind,
        shown: &str,
    ) -> Result<Self, DateError> {
        let re = compile_py_regex(&regex).map_err(|e| pattern_err(shown, e))?;
        let groups = re.named_groups().map(|(i, n)| (i, n.to_string())).collect();
        Ok(Self {
            name,
            weight: 1.0,
            hits: 0,
            flags,
            regex,
            kind,
            re,
            groups,
        })
    }

    /// `DatePatternRegex(pattern)`.
    pub(crate) fn from_pattern(orig: &str, tre: &TimeRe) -> Result<Self, DateError> {
        let mut pattern = orig.to_string();
        let (mut word_begin, mut word_end) = (WordBegin::Word, true);
        // if unbound signalled - reset boundaries left and right:
        if RE_EXLINE_NO_BOUNDS.search(&pattern, 0).is_some() {
            pattern = sub_all(&RE_EXLINE_NO_BOUNDS, &pattern, 0, |_, _| String::new());
            word_begin = WordBegin::No;
            word_end = false;
        }
        // if explicit given {^LN-BEG} - remove it from pattern and set 'start' in wordBegin:
        if word_begin != WordBegin::No && RE_EXLINE_BOUND_BEG.search(&pattern, 0).is_some() {
            pattern = sub_all(&RE_EXLINE_BOUND_BEG, &pattern, 0, |_, _| String::new());
            word_begin = WordBegin::Start;
        }
        let failed = |e: String| {
            pattern_err(
                orig,
                format!(
                    "Failed to set datepattern '{orig}' (may be an invalid format or unescaped percent char): {e}"
                ),
            )
        };
        // wrap to regex:
        let (mut name, mut regex) = expand_pattern(&pattern, tre).map_err(failed)?;
        // if expected add (?iu) for "ignore case" and "unicode":
        if RE_ALPHA_PATTERN.search(&pattern, 0).is_some() {
            regex.insert_str(0, "(?iu)");
        }
        let (regex, flags) = finish_regex(&mut name, &regex, word_begin, word_end);
        Self::build(
            name,
            regex,
            flags,
            Kind::Pattern {
                pattern: orig.to_string(),
            },
            orig,
        )
    }

    /// `DateEpoch(lineBeginOnly, pattern, longFrm)`.
    pub(crate) fn epoch(
        line_begin_only: bool,
        pattern: Option<&str>,
        long_frm: bool,
    ) -> Result<Self, DateError> {
        let mut name = pattern.map_or("Epoch", |p| p).to_string();
        let mut epoch_re = r"\d{10,11}\b(?:\.\d{3,6})?";
        if long_frm {
            name = pattern.map_or("LongEpoch", |p| p).to_string();
            epoch_re = r"\d{10,11}(?:\d{3}(?:\.\d{1,6}|\d{3})?)?";
        }
        let shown = pattern.unwrap_or(&name).to_string();
        let mut grp_idx = 1;
        let (regex, wb, we) = if let Some(pattern) = pattern {
            // pattern should find the whole pattern, but cut out grouped match
            // (or whole match if no groups specified):
            let mut regex = sub_all(&RE_EPOCH_PATTERN, pattern, 0, |_, _| {
                format!("({epoch_re})")
            });
            if RE_GROUPED.search(pattern, 0).is_none() {
                regex = format!("({regex})");
            }
            grp_idx = 2;
            (regex, WordBegin::Word, true)
        } else if !line_begin_only {
            (
                format!(
                    r"((?:^|(?P<square>(?<=^\[))|(?P<selinux>(?<=\baudit\())){epoch_re})(?:(?(selinux)(?=:\d+\)))|(?(square)(?=\])))"
                ),
                WordBegin::No,
                true,
            )
        } else {
            (
                format!(r"((?P<square>(?<=^\[))?{epoch_re})(?(square)(?=\]))"),
                WordBegin::Start,
                true,
            )
        };
        let (regex, flags) = finish_regex(&mut name, &regex, wb, we);
        Self::build(
            name,
            regex,
            flags,
            Kind::Epoch { grp_idx, long_frm },
            &shown,
        )
    }

    /// `DateTai64n(wordBegin)`.
    pub(crate) fn tai64n(word_begin: WordBegin) -> Result<Self, DateError> {
        let mut name = "TAI64N".to_string();
        let (regex, flags) = finish_regex(&mut name, "@[0-9a-f]{24}", word_begin, true);
        Self::build(name, regex, flags, Kind::Tai64n, "TAI64N")
    }

    pub(crate) fn pattern(&self) -> Option<&str> {
        match &self.kind {
            Kind::Pattern { pattern } => Some(pattern),
            _ => None,
        }
    }

    /// `matchDate(line, pos, endpos)`: `pos`/`endpos` are byte offsets.
    pub(crate) fn match_date(&self, line: &str, pos: usize, endpos: usize) -> Option<Caps> {
        if pos > endpos {
            return None;
        }
        self.re.search(&line[..endpos], pos)
    }

    /// `getDate(line, dateMatch, default_tz)`: `Ok(None)` is upstream's
    /// `ValueError` (the caller treats it as "no date").
    pub(crate) fn get_date(
        &self,
        line: &str,
        caps: &Caps,
        ctx: &TimeCtx<'_>,
    ) -> PyResult<Option<f64>> {
        let group = |i: usize| -> PyResult<Option<&str>> {
            match caps.get(i) {
                None => Err(PyExc::Index),
                Some(c) => Ok(c.map(|(s, e)| &line[s..e])),
            }
        };
        match &self.kind {
            Kind::Pattern { .. } => {
                let found: Vec<(&str, Option<&str>)> = self
                    .groups
                    .iter()
                    .map(|(i, n)| (n.as_str(), caps[*i].map(|(s, e)| &line[s..e])))
                    .collect();
                match group_dict_to_time(&found, ctx) {
                    Ok(t) => Ok(Some(t)),
                    Err(PyExc::Value) => Ok(None),
                    Err(e) => Err(e),
                }
            }
            Kind::Epoch { grp_idx, long_frm } => {
                let v = group(*grp_idx)?.ok_or(PyExc::Type)?;
                let n = v.chars().count();
                let t = if *long_frm && n >= 13 {
                    let f = py_float(v);
                    let div = if n >= 16 && !v.contains('.') {
                        1_000_000.0
                    } else {
                        1000.0
                    };
                    f.map(|f| f / div)
                } else {
                    py_float(v)
                };
                Ok(t)
            }
            Kind::Tai64n => {
                let v = group(1)?.ok_or(PyExc::Type)?;
                // value[2:17]
                let seconds: String = v.chars().skip(2).take(15).collect();
                Ok(u64::from_str_radix(&seconds, 16).ok().map(|s| s as f64))
            }
        }
    }
}
