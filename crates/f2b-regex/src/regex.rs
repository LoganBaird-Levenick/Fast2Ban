//! `Regex` and `FailRegex` of upstream's `failregex.py`.

use std::borrow::Cow;
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::sync::LazyLock;

use f2b_helpers::pychar::{is_space, repr_str};
use f2b_types::{Cidr, IPAddr};

use crate::charset;
use crate::error::{MatchError, RegexError};
use crate::groups::{GroupValue, Groups, TupleLine, split_cow};
use crate::pyast::Flags;
use crate::tags::{UseDns, global_to_local_flags, map_tag_to_option, resolve_host_tag};
use crate::translate::{EngineKind, Gate, Translated, translate};

/// Default step limit of the backtracking engine (see
/// [`MatchError::BacktrackLimit`]).
pub const DEFAULT_BACKTRACK_LIMIT: usize = 1_000_000;

/// Compiled-size ceiling handed to the engines. Python has no limit; the
/// explicit Unicode classes of `\w` make big patterns legitimately large.
const SIZE_LIMIT: usize = 256 << 20;
const DFA_SIZE_LIMIT: usize = 32 << 20;

/// Groups used as failure identifier (`FAILURE_ID_GROPS`), in priority order.
pub const FAILURE_ID_GROUPS: [&str; 4] = ["fid", "ip4", "ip6", "dns"];

/// `FAILURE_ID_PRESENTS`: the groups one of which a failregex must define.
pub const FAILURE_ID_PRESENT: [&str; 5] = ["fid", "ip4", "ip6", "dns", "mlfid"];

/// Constructor arguments of upstream's `Regex(regex, multiline, useDns=...)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegexOptions {
    /// Compile with `re.MULTILINE` (filters with `maxlines > 1`).
    pub multiline: bool,
    /// `useDns` keyword: `no` makes `<HOST>` expand to `<ADDR>`.
    pub use_dns: UseDns,
    /// Step limit of the backtracking engine.
    pub backtrack_limit: usize,
}

impl Default for RegexOptions {
    fn default() -> Self {
        RegexOptions {
            multiline: false,
            use_dns: UseDns::Yes,
            backtrack_limit: DEFAULT_BACKTRACK_LIMIT,
        }
    }
}

enum Engine {
    Linear(regex::Regex, regex::CaptureLocations),
    Backtracking(fancy_regex::Regex),
}

/// `(key group-name, merged name)` of an `alt_`/`tuple_` group.
pub type Merge = (String, String);

/// A compiled failregex, equivalent of upstream's `Regex` class.
///
/// `search*` take `&mut self`: the object owns the reusable capture buffers
/// (nothing is allocated per search on the linear engine), and the returned
/// [`Match`] borrows it, like `Regex._matchCache` is the match of the last
/// `search()`.
pub struct Regex {
    regex: String,
    kind: EngineKind,
    gate: Gate,
    primary: Engine,
    /// Linear superset of `primary`/`exact`: rejects most buffers cheaply.
    prefilter: Option<regex::Regex>,
    exact_src: Option<String>,
    exact: Option<fancy_regex::Regex>,
    names: Vec<(String, usize)>,
    flags: Flags,
    alt_values: Vec<Merge>,
    tuple_values: Vec<Merge>,
    skip_groups: Vec<usize>,
    spans: Vec<Option<(usize, usize)>>,
    matched_idx: Vec<usize>,
    unmatched_idx: Vec<usize>,
}

impl fmt::Debug for Regex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Regex")
            .field("regex", &self.regex)
            .field("engine", &self.kind)
            .field("gate", &self.gate)
            .finish_non_exhaustive()
    }
}

/// `__str__`: `Regex('...')`.
impl fmt::Display for Regex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Regex({})", repr_str(&self.regex))
    }
}

/// `COMPLNAME_CRE`.
static COMPLNAME_CRE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"^(alt_|tuple_)(.*?)(?:_\d+)?$").expect("static regex is valid")
});

impl Regex {
    /// `Regex(regex)`: default options (single line, `useDns` yes).
    ///
    /// # Errors
    /// See [`Regex::with_options`].
    pub fn new(regex: &str) -> Result<Regex, RegexError> {
        Regex::with_options(regex, &RegexOptions::default())
    }

    /// `Regex(regex, multiline, useDns=...)`.
    ///
    /// Expands the tags, rewrites global flags to local ones, and compiles.
    /// Fails where upstream raises: empty regex, a pattern Python's `re`
    /// rejects (with Python's message), and see [`RegexError::Engine`].
    ///
    /// # Errors
    /// [`RegexError`].
    pub fn with_options(regex: &str, options: &RegexOptions) -> Result<Regex, RegexError> {
        let expanded = resolve_host_tag(regex, options.use_dns);
        if expanded.trim_start_matches(is_space).is_empty() {
            return Err(RegexError::Empty);
        }
        let expanded = global_to_local_flags(&expanded);
        let translated =
            translate(&expanded, options.multiline).map_err(|error| RegexError::Compile {
                regex: expanded.clone(),
                error,
            })?;
        Regex::build(expanded, translated, options)
    }

    fn build(regex: String, t: Translated, options: &RegexOptions) -> Result<Regex, RegexError> {
        let engine_err = |message: String| RegexError::Engine {
            regex: regex.clone(),
            message,
        };
        let primary = match t.primary_engine {
            EngineKind::Linear => {
                let re = regex::RegexBuilder::new(&t.primary)
                    .size_limit(SIZE_LIMIT)
                    .dfa_size_limit(DFA_SIZE_LIMIT)
                    .build()
                    .map_err(|e| engine_err(e.to_string()))?;
                let locs = re.capture_locations();
                Engine::Linear(re, locs)
            }
            EngineKind::Backtracking => Engine::Backtracking(
                build_fancy(&t.primary, options.backtrack_limit)
                    .map_err(|e| engine_err(e.to_string()))?,
            ),
        };
        // Validate the exact pattern eagerly: a pattern Python accepts must
        // not fail later, at search time.
        let exact = match &t.exact {
            Some(src) => Some(
                build_fancy(src, options.backtrack_limit).map_err(|e| engine_err(e.to_string()))?,
            ),
            None => None,
        };

        // The prefilter is an optimisation: a pattern the linear engine cannot
        // build (size limit) simply runs without it.
        let prefilter = t.prefilter.as_deref().and_then(|src| {
            regex::RegexBuilder::new(src)
                .size_limit(SIZE_LIMIT)
                .dfa_size_limit(DFA_SIZE_LIMIT)
                .build()
                .ok()
        });

        let mut alt_values: Vec<Merge> = Vec::new();
        let mut tuple_values: Vec<Merge> = Vec::new();
        for (k, _) in &t.names {
            if k.chars().count() <= "alt_".len() {
                continue;
            }
            if let Some(c) = COMPLNAME_CRE.captures(k) {
                let n = map_tag_to_option(&c[2]);
                if &c[1] == "alt_" {
                    alt_values.push((k.clone(), n));
                } else {
                    tuple_values.push((k.clone(), n));
                }
            }
        }
        alt_values.sort();
        tuple_values.sort();

        let mut skip_groups = Vec::new();
        while let Some(&(_, idx)) = t
            .names
            .iter()
            .find(|(n, _)| *n == format!("skiplines{}", skip_groups.len()))
        {
            skip_groups.push(idx);
        }

        Ok(Regex {
            regex,
            kind: t.primary_engine,
            gate: t.gate,
            primary,
            prefilter,
            exact_src: t.exact,
            exact,
            names: t.names,
            flags: t.flags,
            alt_values,
            tuple_values,
            skip_groups,
            spans: Vec::with_capacity(t.groups + 1),
            matched_idx: Vec::new(),
            unmatched_idx: Vec::new(),
        })
    }

    /// `getRegex()`: the effective (tag-expanded) regular expression.
    #[must_use]
    pub fn regex(&self) -> &str {
        &self.regex
    }

    /// Engine the primary pattern runs on (see [`EngineKind`]). Buffers outside
    /// the translation's gate always run on the backtracking engine.
    #[must_use]
    pub fn engine(&self) -> EngineKind {
        self.kind
    }

    /// Whether the translation needs the exact (backtracking) pattern for
    /// some buffers (`$`, `\b`, `\B`; see [`crate::translate`]).
    #[must_use]
    pub fn has_exact_fallback(&self) -> bool {
        self.exact_src.is_some()
    }

    /// `re.groupindex`: `(name, group number)` in definition order.
    #[must_use]
    pub fn group_names(&self) -> &[(String, usize)] {
        &self.names
    }

    /// Whether the regex defines a group named `name` (`name in groupindex`).
    #[must_use]
    pub fn has_group(&self, name: &str) -> bool {
        self.names.iter().any(|(n, _)| n == name)
    }

    /// Merge tables `(alt_*, target)` and `(tuple_*, target)` (sorted).
    #[must_use]
    pub fn merge_tables(&self) -> (&[Merge], &[Merge]) {
        (&self.alt_values, &self.tuple_values)
    }

    /// `str(match.re)` (`re.compile('...', re.MULTILINE)`).
    #[must_use]
    pub fn pattern_repr(&self) -> String {
        let mut text = repr_str(&self.regex);
        if text.chars().count() > 200 {
            text = text.chars().take(200).collect();
        }
        let mut flags = self.flags.0;
        if flags & Flags::TYPE_FLAGS == Flags::UNICODE {
            flags &= !Flags::UNICODE;
        }
        let names = [
            ("re.IGNORECASE", Flags::IGNORECASE),
            ("re.LOCALE", Flags::LOCALE),
            ("re.MULTILINE", Flags::MULTILINE),
            ("re.DOTALL", Flags::DOTALL),
            ("re.UNICODE", Flags::UNICODE),
            ("re.VERBOSE", Flags::VERBOSE),
            ("re.ASCII", Flags::ASCII),
        ];
        let joined: Vec<&str> = names
            .iter()
            .filter(|(_, v)| flags & v != 0)
            .map(|(n, _)| *n)
            .collect();
        if joined.is_empty() {
            format!("re.compile({text})")
        } else {
            format!("re.compile({text}, {})", joined.join("|"))
        }
    }

    /// Runs the search, filling `self.spans`.
    fn run(&mut self, hay: &str) -> Result<bool, MatchError> {
        if self.prefilter.as_ref().is_some_and(|p| !p.is_match(hay)) {
            return Ok(false);
        }
        if !self.gate.admits(hay) {
            if self.exact.is_none() {
                return Err(MatchError::Engine(
                    "no exact engine for buffer outside the gate".to_owned(),
                ));
            }
            let re = self.exact.as_ref().expect("checked above");
            return run_fancy(re, hay, &mut self.spans);
        }
        match &mut self.primary {
            Engine::Linear(re, locs) => {
                if re.captures_read(locs, hay).is_none() {
                    return Ok(false);
                }
                self.spans.clear();
                for i in 0..locs.len() {
                    self.spans.push(locs.get(i));
                }
                Ok(true)
            }
            Engine::Backtracking(re) => run_fancy(re, hay, &mut self.spans),
        }
    }

    /// `search(buf)` on a string buffer, without line bookkeeping
    /// (`matched_lines` / `unmatched_lines` of the match are empty).
    ///
    /// # Errors
    /// [`MatchError::BacktrackLimit`] / [`MatchError::Engine`] only.
    pub fn search_str<'a>(&'a mut self, buf: &'a str) -> Result<Option<Match<'a>>, MatchError> {
        self.matched_idx.clear();
        self.unmatched_idx.clear();
        if !self.run(buf)? {
            return Ok(None);
        }
        Ok(Some(Match { re: self, hay: buf }))
    }

    /// `search(buf, orgLines)`: searches `buf` (normally built with
    /// [`crate::tuple_lines_buf`] from `org_lines`) and records which of
    /// `org_lines` the match covers, exactly as upstream's multi-line
    /// bookkeeping does (lines captured by `<SKIPLINES>` count as unmatched).
    ///
    /// # Errors
    /// See [`Regex::search_str`].
    pub fn search_buf<'a, S: AsRef<str>>(
        &'a mut self,
        buf: &'a str,
        org_lines: &[TupleLine<S>],
    ) -> Result<Option<Match<'a>>, MatchError> {
        self.matched_idx.clear();
        self.unmatched_idx.clear();
        if !self.run(buf)? {
            return Ok(None);
        }
        let (start, end) = self.spans[0].unwrap_or((0, 0));
        let mut matched = std::mem::take(&mut self.matched_idx);
        let mut unmatched = std::mem::take(&mut self.unmatched_idx);
        let n_org = org_lines.len();
        if n_org <= 1 {
            matched.extend(0..n_org);
        } else {
            let bytes = buf.as_bytes();
            // `string.rindex("\n", 0, start + 1) + 1`, or 0.
            let upto = (start + 1).min(bytes.len());
            let line_start = memchr::memrchr(b'\n', &bytes[..upto]).map_or(0, |i| i + 1);
            // `string.index("\n", end - 1) + 1`, or len; `end - 1 == -1`
            // counts from the back in Python.
            let from = if end == 0 {
                bytes.len().saturating_sub(1)
            } else {
                end - 1
            };
            let line_end = bytes
                .get(from..)
                .and_then(|tail| memchr::memchr(b'\n', tail))
                .map_or(bytes.len(), |i| from + i + 1);
            let count1 = memchr::memchr_iter(b'\n', &bytes[..line_start]).count();
            let count2 = memchr::memchr_iter(b'\n', &bytes[..line_end]).count();
            let lc1 = count1.min(n_org);
            let lc2 = count2.min(n_org).max(lc1);
            matched.extend(lc1..lc2);
            unmatched.extend(0..lc1);
            let mut n = 0;
            for skipped in self.skipped_in(buf) {
                let found = matched
                    .get(n..)
                    .unwrap_or(&[])
                    .iter()
                    .position(|&i| org_lines[i].text_eq(&skipped));
                if let Some(m) = found {
                    unmatched.push(matched.remove(n + m));
                    n += m;
                }
            }
            unmatched.extend(lc2..n_org);
        }
        self.matched_idx = matched;
        self.unmatched_idx = unmatched;
        Ok(Some(Match { re: self, hay: buf }))
    }

    /// `search(tupleLines)`: builds the buffer into `scratch` (reuse one
    /// `String` for all searches) and searches it with `lines` as the original
    /// lines.
    ///
    /// # Errors
    /// See [`Regex::search_str`].
    pub fn search_lines<'a, S: AsRef<str>>(
        &'a mut self,
        lines: &[TupleLine<S>],
        scratch: &'a mut String,
    ) -> Result<Option<Match<'a>>, MatchError> {
        crate::groups::tuple_lines_buf(lines, scratch);
        self.search_buf(scratch.as_str(), lines)
    }

    /// Text of group `idx` of the last match.
    fn group_text<'h>(&self, hay: &'h str, idx: usize) -> Option<&'h str> {
        self.spans
            .get(idx)
            .copied()
            .flatten()
            .map(|(s, e)| &hay[s..e])
    }

    /// `getSkippedLines()` for the last match.
    fn skipped_in<'h>(&self, hay: &'h str) -> Vec<Cow<'h, str>> {
        let mut acc: Option<Cow<'h, str>> = None;
        for &idx in &self.skip_groups {
            if let Some(t) = self.group_text(hay, idx) {
                match &mut acc {
                    None => acc = Some(Cow::Borrowed(t)),
                    Some(a) => a.to_mut().push_str(t),
                }
            }
        }
        acc.map_or_else(Vec::new, split_cow)
    }
}

/// Message of [`MatchError::Engine`] when `fancy-regex` panicked.
const ENGINE_PANIC: &str = "backtracking regex engine panicked";

fn build_fancy(pattern: &str, limit: usize) -> Result<fancy_regex::Regex, fancy_regex::Error> {
    fancy_regex::RegexBuilder::new(pattern)
        .backtrack_limit(limit)
        .delegate_size_limit(SIZE_LIMIT)
        .delegate_dfa_size_limit(DFA_SIZE_LIMIT)
        .build()
}

fn run_fancy(
    re: &fancy_regex::Regex,
    hay: &str,
    spans: &mut Vec<Option<(usize, usize)>>,
) -> Result<bool, MatchError> {
    // fancy-regex 0.19 can panic (slice bounds in its backreference check) on
    // a few exotic patterns, e.g. `(?:(?=(k?)+?)\1)+é`: contain it.
    let found = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| re.captures(hay)))
        .map_err(|_| MatchError::Engine(ENGINE_PANIC.to_owned()))?;
    match found {
        Ok(Some(caps)) => {
            spans.clear();
            for i in 0..caps.len() {
                spans.push(caps.get(i).map(|m| (m.start(), m.end())));
            }
            Ok(true)
        }
        Ok(None) => Ok(false),
        Err(fancy_regex::Error::RuntimeError(
            fancy_regex::RuntimeError::BacktrackLimitExceeded,
        )) => Err(MatchError::BacktrackLimit),
        Err(e) => Err(MatchError::Engine(e.to_string())),
    }
}

/// The match of the last `search*` call (upstream's `_matchCache`).
#[derive(Clone, Copy, Debug)]
pub struct Match<'a> {
    re: &'a Regex,
    hay: &'a str,
}

impl<'a> Match<'a> {
    /// The regex that matched.
    #[must_use]
    pub fn regex(&self) -> &'a Regex {
        self.re
    }

    /// The searched buffer.
    #[must_use]
    pub fn haystack(&self) -> &'a str {
        self.hay
    }

    /// Byte offsets `(start, end)` of the whole match.
    #[must_use]
    pub fn span(&self) -> (usize, usize) {
        self.re.spans[0].unwrap_or((0, 0))
    }

    /// Start byte offset of the whole match.
    #[must_use]
    pub fn start(&self) -> usize {
        self.span().0
    }

    /// End byte offset of the whole match.
    #[must_use]
    pub fn end(&self) -> usize {
        self.span().1
    }

    /// `match.group(name)`: `None` when the regex has no such group (Python's
    /// `IndexError`), `Some(None)` when the group did not participate.
    #[must_use]
    pub fn group(&self, name: &str) -> Option<Option<&'a str>> {
        let (_, idx) = self.re.names.iter().find(|(n, _)| n == name)?;
        Some(self.re.group_text(self.hay, *idx))
    }

    /// `match.group(index)` by group number (0 is the whole match).
    #[must_use]
    pub fn group_at(&self, index: usize) -> Option<Option<&'a str>> {
        if index >= self.re.spans.len() {
            return None;
        }
        Some(self.re.group_text(self.hay, index))
    }

    /// `getGroups()`: `groupdict()` plus, if the regex has `alt_`/`tuple_`
    /// groups, the merged values (`_getGroupsWithAlt`).
    ///
    /// * `alt_NAME_N` (any number of `_N` suffixed alternatives, processed in
    ///   sorted order) sets `NAME` when `NAME` is unset or empty and the
    ///   alternative is non-empty; `NAME` is appended if it is not a group.
    /// * `tuple_NAME_N` appends its value to the tuple `NAME`: a non-tuple
    ///   existing value `t` becomes `(t, v)`, a missing/unset one `(None, v)`.
    #[must_use]
    pub fn groups(&self) -> Groups<'a> {
        let re = self.re;
        let mut fail = Groups::with_capacity(re.names.len() + 1);
        for (name, idx) in &re.names {
            let v = match re.group_text(self.hay, *idx) {
                Some(s) => GroupValue::Str(s),
                None => GroupValue::None,
            };
            fail.push(name, v);
        }
        for (k, n) in &re.alt_values {
            let v = fail.get(k).filter(|v| v.is_truthy()).cloned();
            if let Some(v) = v
                && !fail.get(n).is_some_and(GroupValue::is_truthy)
            {
                fail.set(n, v);
            }
        }
        for (k, n) in &re.tuple_values {
            let v = match fail.get(k) {
                Some(GroupValue::Str(s)) => Some(*s),
                _ => None,
            };
            let t = match fail.get(n) {
                Some(GroupValue::Tuple(t)) => {
                    let mut t = t.clone();
                    t.push(v);
                    t
                }
                Some(GroupValue::Str(s)) => vec![Some(*s), v],
                Some(GroupValue::None) | None => vec![None, v],
            };
            fail.set(n, GroupValue::Tuple(t));
        }
        fail
    }

    /// `getSkippedLines()`: the lines captured by `<SKIPLINES>`.
    #[must_use]
    pub fn skipped_lines(&self) -> Vec<Cow<'a, str>> {
        self.re.skipped_in(self.hay)
    }

    /// Indices (into the `org_lines` of the search) of the lines the match
    /// covers, `getMatchedTupleLines()`. Empty after
    /// [`Regex::search_str`].
    #[must_use]
    pub fn matched_lines(&self) -> &'a [usize] {
        &self.re.matched_idx
    }

    /// Indices of the other lines, `getUnmatchedTupleLines()`: lines before
    /// the match, lines captured by `<SKIPLINES>`, lines after it.
    #[must_use]
    pub fn unmatched_lines(&self) -> &'a [usize] {
        &self.re.unmatched_idx
    }

    /// `FailRegex.getFailID(groups)`: the first of `groups` that matched.
    ///
    /// # Errors
    /// [`MatchError::NoFailId`] when none of them is set (or exists).
    pub fn fail_id_in(&self, groups: &[&str]) -> Result<&'a str, MatchError> {
        for grp in groups {
            if let Some(Some(v)) = self.group(grp) {
                return Ok(v);
            }
        }
        Err(MatchError::NoFailId {
            buf: self.hay.to_owned(),
            pattern: self.re.pattern_repr(),
        })
    }

    /// `getFailID()` with the default `fid, ip4, ip6, dns`.
    ///
    /// # Errors
    /// See [`Match::fail_id_in`].
    pub fn fail_id(&self) -> Result<&'a str, MatchError> {
        self.fail_id_in(&FAILURE_ID_GROUPS)
    }

    /// `getHost()`: `ip4`, `ip6` or `dns`.
    ///
    /// # Errors
    /// See [`Match::fail_id_in`].
    pub fn host(&self) -> Result<&'a str, MatchError> {
        self.fail_id_in(&["ip4", "ip6", "dns"])
    }

    /// `getIP()`: `IPAddr(ip4|ip6, int(cidr or CIDR_UNSPEC))`.
    ///
    /// # Errors
    /// [`MatchError::NoFailId`] without an address group, [`MatchError::Ip`]
    /// when `IPAddr` rejects the text, [`MatchError::BadCidr`] for a
    /// tuple-valued `cidr`.
    pub fn ip(&self) -> Result<IPAddr, MatchError> {
        let text = self.fail_id_in(&["ip4", "ip6"])?;
        let groups = self.groups();
        let cidr = match groups.get("cidr") {
            Some(GroupValue::Str(s)) if !s.is_empty() => {
                cidr_from_int(charset::py_int(s).ok_or(MatchError::BadCidr)?)?
            }
            Some(v) if v.is_truthy() => return Err(MatchError::BadCidr),
            _ => Cidr::Unspec,
        };
        Ok(IPAddr::with_cidr(text, cidr)?)
    }
}

/// The integer `IPAddr(ipstr, cidr)` receives: `>= 0` a prefix length (values
/// beyond `u32` saturate), the negative `CIDR_*` / `FAM_*` constants
/// (`FAM_IPv4` / `FAM_IPv6` as on Linux, `-4` / `-12`).
fn cidr_from_int(n: i64) -> Result<Cidr, MatchError> {
    Ok(match n {
        -1 => Cidr::Unspec,
        -2 => Cidr::Raw,
        -4 => Cidr::Inet4,
        -12 => Cidr::Inet6,
        n if n >= 0 => Cidr::Prefix(u32::try_from(n).unwrap_or(u32::MAX)),
        _ => return Err(MatchError::BadCidr),
    })
}

/// A [`Regex`] that must carry a failure-id group (upstream's `FailRegex`).
///
/// Dereferences to [`Regex`] for searching and inspection.
pub struct FailRegex {
    inner: Regex,
}

impl fmt::Debug for FailRegex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("FailRegex").field(&self.inner).finish()
    }
}

/// `__str__`: `FailRegex('...')`.
impl fmt::Display for FailRegex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FailRegex({})", repr_str(&self.inner.regex))
    }
}

impl FailRegex {
    /// `FailRegex(regex, prefRegex, multiline, useDns)`.
    ///
    /// # Errors
    /// Everything [`Regex::with_options`] reports, plus
    /// [`RegexError::NoFailureId`] unless the regex (or `pref_regex`) has one
    /// of the groups `fid`, `ip4`, `ip6`, `dns`, `mlfid`.
    pub fn new(
        regex: &str,
        pref_regex: Option<&Regex>,
        options: &RegexOptions,
    ) -> Result<FailRegex, RegexError> {
        let inner = Regex::with_options(regex, options)?;
        let has_id = |r: &Regex| FAILURE_ID_PRESENT.iter().any(|g| r.has_group(g));
        if !has_id(&inner) && !pref_regex.is_some_and(has_id) {
            return Err(RegexError::NoFailureId {
                regex: inner.regex.clone(),
            });
        }
        Ok(FailRegex { inner })
    }
}

impl Deref for FailRegex {
    type Target = Regex;

    fn deref(&self) -> &Regex {
        &self.inner
    }
}

impl DerefMut for FailRegex {
    fn deref_mut(&mut self) -> &mut Regex {
        &mut self.inner
    }
}
