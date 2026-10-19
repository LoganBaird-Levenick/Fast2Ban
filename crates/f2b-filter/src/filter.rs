//! The filter core: port of the failure-finding half of upstream's `Filter`
//! (`fail2ban/server/filter.py`): `findFailure`, `_ignoreLine`,
//! `_mergeFailure` and the regex/option configuration it needs.
//!
//! Date splitting (`processLine`) lives in `process.rs`.

use std::collections::HashMap;
use std::sync::Arc;

use f2b_config::pyutil::py_int;
use f2b_date::{DateDetector, DateEnv, LocalZone};
use f2b_regex::{
    FailRegex, GroupValue, MatchError, Regex, RegexOptions, TupleLine, UseDns, tuple_lines_buf,
};
use f2b_types::{Cidr, DnsUtils, IPAddr, SharedClock, TtlCache};

use crate::error::{FilterError, Result};
use crate::failval::{FailData, FailVal};

/// One failure found in a line: upstream's `[failRegexIndex, fid, date, fail]`.
#[derive(Clone, Debug, PartialEq)]
pub struct FailEntry {
    /// Index of the failregex that matched (`-1` never occurs here).
    pub regex_index: usize,
    /// Failure id / address; `None` for a pending multi-line failure.
    pub fid: Option<IPAddr>,
    /// Time of the failure (`None` when unknown and `check_find_time` is off).
    pub date: Option<f64>,
    pub fail: FailData,
}

/// Callback invoked when an `ignoreregex` matched (`onIgnoreRegex`).
pub type IgnoreCallback = Box<dyn FnMut(usize, &Regex) + Send>;

/// Working state of one `findFailure` call (upstream's `orgBuffer`,
/// `self.__lineBuffer` and `buf`).
pub(crate) struct Ctx {
    /// `orgBuffer`: the lines the searches started from.
    pub org: Vec<TupleLine<String>>,
    /// `self.__lineBuffer` when it was rebound (`None`: still `org`).
    pub repl: Option<Vec<TupleLine<String>>>,
    /// Whether `Filter::scratch` holds the buffer text of the current line buffer.
    pub buf_valid: bool,
}

impl Ctx {
    fn current(&self) -> &[TupleLine<String>] {
        self.repl.as_deref().unwrap_or(&self.org)
    }
}

/// Outcome of handling one matched failregex.
enum Flow {
    /// Go on with the next failregex.
    Next,
    /// Stop iterating failregexes (`break`), returning what was collected.
    Stop,
}

pub struct Filter {
    pub(crate) clock: SharedClock,
    dns: Arc<DnsUtils>,
    pref_regex: Option<Regex>,
    fail_regex: Vec<FailRegex>,
    ignore_regex: Vec<Regex>,
    use_dns: UseDns,
    find_time: f64,
    max_lines: usize,
    /// `self.__lineBuffer` between calls (multi-line state).
    pub(crate) line_buffer: Vec<TupleLine<String>>,
    pub(crate) last_time_text: String,
    pub(crate) last_date: Option<f64>,
    pub(crate) log_timezone: Option<String>,
    mlfid_cache: Option<TtlCache<String, FailData>>,
    pub(crate) date_env: DateEnv,
    pub(crate) date_detector: Option<DateDetector>,
    scratch: String,
    pub(crate) warn_next: HashMap<&'static str, f64>,
    on_ignore_regex: Option<IgnoreCallback>,
    /// Return raw hosts, do not resolve DNS (`returnRawHost`).
    pub return_raw_host: bool,
    /// Check every regex instead of stopping at the first match (tests, fail2ban-regex).
    pub check_all_regex: bool,
    /// Do not report pending (id-less) failures (`ignorePending`).
    pub ignore_pending: bool,
    /// Drop obsolete failures / simulate now for odd dates (`checkFindTime`).
    pub check_find_time: bool,
    /// Filter is in operation mode, processing new messages (`inOperation`).
    pub in_operation: bool,
}

impl std::fmt::Debug for Filter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Filter")
            .field("use_dns", &self.use_dns)
            .field("max_lines", &self.max_lines)
            .field("fail_regex", &self.fail_regex.len())
            .field("ignore_regex", &self.ignore_regex.len())
            .finish_non_exhaustive()
    }
}

impl Filter {
    /// `Filter(None)` with `useDns='warn'`.
    pub fn new(clock: SharedClock, dns: Arc<DnsUtils>, zone: LocalZone) -> Self {
        let date_env = DateEnv::new(clock.clone(), zone);
        Self {
            date_detector: Some(DateDetector::new(date_env.clone())),
            date_env,
            clock,
            dns,
            pref_regex: None,
            fail_regex: Vec::new(),
            ignore_regex: Vec::new(),
            use_dns: UseDns::Warn,
            find_time: 600.0,
            max_lines: 1,
            line_buffer: Vec::new(),
            last_time_text: String::new(),
            last_date: None,
            log_timezone: None,
            mlfid_cache: None,
            scratch: String::new(),
            warn_next: HashMap::new(),
            on_ignore_regex: None,
            return_raw_host: false,
            check_all_regex: false,
            ignore_pending: true,
            check_find_time: true,
            in_operation: true,
        }
    }

    // ------------------------------------------------------------ configuration

    fn regex_options(&self, multiline: bool) -> RegexOptions {
        RegexOptions {
            multiline,
            use_dns: self.use_dns,
            ..RegexOptions::default()
        }
    }

    /// `setUseDns`: anything but yes/warn/no/raw falls back to `no`.
    pub fn set_use_dns(&mut self, value: &str) {
        self.use_dns = match value.to_lowercase().as_str() {
            "yes" => UseDns::Yes,
            "warn" => UseDns::Warn,
            "raw" => UseDns::Raw,
            "no" => UseDns::No,
            other => {
                log::error!("Incorrect value {other:?} specified for usedns. Using safe 'no'");
                UseDns::No
            }
        };
    }

    pub fn use_dns(&self) -> UseDns {
        self.use_dns
    }

    /// `prefRegex = value` (empty clears it). Compiled single-line, like upstream.
    pub fn set_pref_regex(&mut self, value: Option<&str>) -> Result<()> {
        self.pref_regex = match value {
            Some(v) if !v.is_empty() => Some(Regex::with_options(v, &self.regex_options(false))?),
            _ => None,
        };
        Ok(())
    }

    pub fn pref_regex(&self) -> Option<&Regex> {
        self.pref_regex.as_ref()
    }

    pub fn pref_regex_mut(&mut self) -> Option<&mut Regex> {
        self.pref_regex.as_mut()
    }

    /// `addFailRegex`.
    pub fn add_fail_regex(&mut self, value: &str) -> Result<()> {
        let opts = self.regex_options(self.max_lines > 1);
        let regex = FailRegex::new(value, self.pref_regex.as_ref(), &opts)?;
        self.fail_regex.push(regex);
        Ok(())
    }

    /// `delFailRegex()` (all).
    pub fn clear_fail_regex(&mut self) {
        self.fail_regex.clear();
    }

    pub fn fail_regexes(&self) -> &[FailRegex] {
        &self.fail_regex
    }

    /// `addIgnoreRegex`. Compiled single-line, like upstream.
    pub fn add_ignore_regex(&mut self, value: &str) -> Result<()> {
        let regex = Regex::with_options(value, &self.regex_options(false))?;
        self.ignore_regex.push(regex);
        Ok(())
    }

    /// `delIgnoreRegex()` (all).
    pub fn clear_ignore_regex(&mut self) {
        self.ignore_regex.clear();
    }

    pub fn ignore_regexes(&self) -> &[Regex] {
        &self.ignore_regex
    }

    /// `setDatePattern`: `None` disables date detection (`dateDetector = None`);
    /// otherwise newline separated patterns replace the default templates.
    pub fn set_date_pattern(&mut self, pattern: Option<&str>) -> Result<()> {
        self.date_detector = match pattern {
            None => None,
            Some(p) => Some(
                DateDetector::from_date_pattern(
                    p,
                    self.log_timezone.as_deref(),
                    self.date_env.clone(),
                )
                .map_err(|e| FilterError::Value(e.to_string()))?,
            ),
        };
        Ok(())
    }

    /// `dateDetector` (None when disabled).
    pub fn date_detector(&self) -> Option<&DateDetector> {
        self.date_detector.as_ref()
    }

    /// `setLogTimeZone`: validated, then applied to the detector.
    pub fn set_log_time_zone(&mut self, tz: &str) -> Result<()> {
        f2b_date::validate_time_zone(tz).map_err(|e| FilterError::Value(e.to_string()))?;
        self.log_timezone = Some(tz.to_owned());
        if let Some(dd) = self.date_detector.as_mut() {
            dd.set_default_tz(Some(tz))
                .map_err(|e| FilterError::Value(e.to_string()))?;
        }
        Ok(())
    }

    pub fn log_time_zone(&self) -> Option<&str> {
        self.log_timezone.as_deref()
    }

    /// `setMaxLines`.
    pub fn set_max_lines(&mut self, value: i64) -> Result<()> {
        if value <= 0 {
            return Err(FilterError::Value(
                "maxlines must be integer greater than zero".to_owned(),
            ));
        }
        self.max_lines = usize::try_from(value).unwrap_or(usize::MAX);
        Ok(())
    }

    pub fn max_lines(&self) -> usize {
        self.max_lines
    }

    pub fn set_find_time(&mut self, seconds: f64) {
        self.find_time = seconds;
    }

    pub fn find_time(&self) -> f64 {
        self.find_time
    }

    /// The multi-line buffer (`self.__lineBuffer`).
    pub fn line_buffer(&self) -> &[TupleLine<String>] {
        &self.line_buffer
    }

    pub fn last_date(&self) -> Option<f64> {
        self.last_date
    }

    /// `onIgnoreRegex` callback.
    pub fn set_on_ignore_regex(&mut self, cb: Option<IgnoreCallback>) {
        self.on_ignore_regex = cb;
    }

    /// `_logWarnOnce`: warn once per day per key, trace otherwise.
    pub(crate) fn warn_once(&mut self, key: &'static str, msgs: &[String]) {
        let now = self.clock.time();
        if now < self.warn_next.get(key).copied().unwrap_or(0.0) {
            for m in msgs.iter().take(1) {
                log::trace!("{m}");
            }
        } else {
            self.warn_next.insert(key, now + 24.0 * 60.0 * 60.0);
            for m in msgs {
                log::warn!("{m}");
            }
        }
    }

    // ------------------------------------------------------------ searching

    /// Searches the prefregex in `scratch`; owned groups of a match.
    fn search_pref(&mut self, ctx: &Ctx) -> Result<Option<FailData>> {
        let Some(pref) = self.pref_regex.as_mut() else {
            return Ok(None);
        };
        match pref.search_buf(&self.scratch, &ctx.org) {
            Ok(Some(m)) => Ok(Some(groups_to_fail(m.groups()))),
            Ok(None) => Ok(None),
            Err(MatchError::BacktrackLimit) => {
                log::warn!("prefregex backtracking limit exceeded, line treated as not matching");
                Ok(None)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Searches failregex `idx` in `scratch`.
    fn search_fail(&mut self, idx: usize, ctx: &Ctx) -> Result<Option<MatchData>> {
        match self.fail_regex[idx].search_buf(&self.scratch, &ctx.org) {
            Ok(Some(m)) => Ok(Some(MatchData {
                fail: groups_to_fail(m.groups()),
                matched: m
                    .matched_lines()
                    .iter()
                    .map(|&i| ctx.org[i].clone())
                    .collect(),
                unmatched: m
                    .unmatched_lines()
                    .iter()
                    .map(|&i| ctx.org[i].clone())
                    .collect(),
            })),
            Ok(None) => Ok(None),
            Err(MatchError::BacktrackLimit) => {
                log::warn!(
                    "failregex {idx} backtracking limit exceeded, line treated as not matching"
                );
                Ok(None)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// `_ignoreLine`: index of the first matching `ignoreregex`.
    fn ignore_line(
        &mut self,
        ctx: &mut Ctx,
        fail_match: Option<&MatchData>,
    ) -> Result<Option<usize>> {
        // if multi-line buffer - use matched only, otherwise (single line) - original buf
        let mut tmp = String::new();
        let (buf, lines): (&str, &[TupleLine<String>]) = match fail_match {
            Some(fm) if self.max_lines > 1 => {
                tuple_lines_buf(&fm.matched, &mut tmp);
                (tmp.as_str(), fm.matched.as_slice())
            }
            _ => (self.scratch.as_str(), ctx.org.as_slice()),
        };
        let mut found = None;
        for idx in 0..self.ignore_regex.len() {
            let hit = match self.ignore_regex[idx].search_buf(buf, lines) {
                Ok(m) => m.is_some(),
                Err(MatchError::BacktrackLimit) => false,
                Err(e) => return Err(e.into()),
            };
            if !hit {
                continue;
            }
            found = Some(idx);
            log::trace!("  Matched ignoreregex {idx} and was ignored");
            if let Some(cb) = self.on_ignore_regex.as_mut() {
                cb(idx, &self.ignore_regex[idx]);
            }
            // remove ignored match
            if (!self.check_all_regex || self.max_lines > 1) && fail_match.is_some() {
                if let Some(fm) = fail_match {
                    ctx.repl = Some(fm.unmatched.clone());
                    ctx.buf_valid = false;
                }
            }
            if !self.check_all_regex {
                break;
            }
        }
        Ok(found)
    }

    /// `_updateUsers`; returns the number of users now known.
    fn update_users(fail: &mut FailData, user: Option<&FailVal>) -> usize {
        if let Some(u) = user.filter(|u| u.truthy()) {
            let item = match u {
                FailVal::Str(s) => GroupValue::Str(s.clone()),
                FailVal::Tuple(t) => GroupValue::Tuple(t.clone()),
                _ => return users_len(fail),
            };
            match fail.get_mut("users") {
                Some(FailVal::Set(set)) => {
                    if !set.contains(&item) {
                        set.push(item);
                    }
                }
                // no (or an empty/foreign) users value: start a new set in place
                Some(slot) => *slot = FailVal::Set(vec![item]),
                None => fail.insert("users", FailVal::Set(vec![item])),
            }
        }
        users_len(fail)
    }

    /// `_mergeFailure`: merge a failure into the cached state of its
    /// multi-line failure id. The cache entry of `mlfid` is left holding an
    /// empty placeholder; the caller must hand the final dictionary back with
    /// [`Filter::mlfid_store_back`] (upstream aliases the cached dict).
    fn merge_failure(
        &mut self,
        mlfid: &str,
        mut fail: FailData,
        matched: &[TupleLine<String>],
    ) -> FailData {
        let mut nfflgs: u8 = 0;
        if fail.truthy("mlfgained") {
            nfflgs |= 8 | 1;
            if !fail.truthy("nofail") {
                let g = fail.get("mlfgained").cloned().unwrap_or(FailVal::None);
                fail.insert("nofail", g);
            }
        } else if fail.truthy("nofail") {
            nfflgs |= 1;
        }
        if fail.pop("mlfforget").is_some_and(|v| v.truthy()) {
            nfflgs |= 2;
        }
        let key = mlfid.to_owned();
        let existing = self
            .mlfid_cache
            .as_mut()
            .and_then(|c| c.get_mut(&key))
            .map(std::mem::take);
        let users_n;
        if let Some(mut groups) = existing {
            // update users set (hold all users of connect)
            users_n = Self::update_users(&mut groups, fail.get("user"));
            // be sure we've correct current state ('nofail' and 'mlfgained' only from last failure)
            if groups.pop("nofail").is_some_and(|v| v.truthy()) {
                nfflgs |= 4;
            }
            if groups.pop("mlfgained").is_some_and(|v| v.truthy()) {
                nfflgs |= 4;
            }
            // gained resets all pending failures (retaining users to check it later)
            if nfflgs & 8 != 0 {
                groups.pop("mlfpending");
            }
            // if we had no pending failures then clear the matches (already provided)
            if nfflgs & 4 == 0 && !groups.truthy("mlfpending") {
                groups.pop("matches");
            }
            // overwrite multi-line failure with all values, available in fail
            groups.update_non_none(fail);
            fail = groups;
            // if forget (disconnect/reset) - remove cached entry
            if nfflgs & 2 != 0 {
                if let Some(c) = self.mlfid_cache.as_mut() {
                    c.unset(&key);
                }
            }
        } else {
            users_n = if nfflgs & 2 == 0 {
                let user = fail.get("user").cloned();
                let n = Self::update_users(&mut fail, user.as_ref());
                self.mlfid_cache
                    .get_or_insert_with(|| TtlCache::new(100, 5.0 * 60.0, self.clock.clone()))
                    .set(key, FailData::new());
                n
            } else {
                0
            };
        }
        // check users in order to avoid reset failure by multiple logon-attempts
        if fail.pop("mlfpending").is_some_and(|v| v.truthy()) || users_n > 1 {
            // pending failures or new user: reset 'nofail' because of failures or multiple users
            fail.pop("nofail");
            fail.pop("mlfgained");
            nfflgs &= !(8 | 1);
        }
        // merge matches
        if nfflgs & 1 == 0 {
            let mut m = match fail.pop("nofail-matches") {
                Some(FailVal::Lines(l)) => l,
                _ => Vec::new(),
            };
            if let Some(FailVal::Lines(l)) = fail.get("matches") {
                m.extend(l.iter().cloned());
            }
            if nfflgs & 8 == 0 {
                m.extend(matched.iter().cloned());
            }
            fail.insert("matches", FailVal::Lines(m));
        } else if nfflgs & 3 == 1 {
            let mut m = match fail.get("nofail-matches") {
                Some(FailVal::Lines(l)) => l.clone(),
                _ => Vec::new(),
            };
            m.extend(matched.iter().cloned());
            fail.insert("nofail-matches", FailVal::Lines(m));
        }
        fail
    }

    /// Put the final failure dictionary back into the cache entry of `mlfid`
    /// (if the entry still exists).
    fn mlfid_store_back(&mut self, mlfid: &str, fail: FailData) {
        if let Some(e) = self
            .mlfid_cache
            .as_mut()
            .and_then(|c| c.get_mut(&mlfid.to_owned()))
        {
            *e = fail;
        }
    }

    /// `findFailure`: failures found in one (date-split) log line.
    pub fn find_failure(
        &mut self,
        tuple: TupleLine<String>,
        date: Option<f64>,
        no_date: bool,
    ) -> Result<Vec<FailEntry>> {
        let mut fail_list: Vec<FailEntry> = Vec::new();
        let defcidr = if self.use_dns == UseDns::Raw || self.return_raw_host {
            Cidr::Raw
        } else {
            Cidr::Unspec
        };

        let org = if self.max_lines > 1 {
            let mut b = std::mem::take(&mut self.line_buffer);
            b.push(tuple);
            let start = b.len().saturating_sub(self.max_lines);
            b.drain(..start);
            b
        } else {
            vec![tuple]
        };
        let mut ctx = Ctx {
            org,
            repl: None,
            buf_valid: true,
        };
        tuple_lines_buf(&ctx.org, &mut self.scratch);

        let result = self.find_failure_inner(&mut ctx, date, no_date, defcidr, &mut fail_list);
        // upstream's `self.__lineBuffer` after the call
        self.line_buffer = ctx.repl.take().unwrap_or(ctx.org);
        result.map(|()| fail_list)
    }

    fn find_failure_inner(
        &mut self,
        ctx: &mut Ctx,
        date: Option<f64>,
        no_date: bool,
        defcidr: Cidr,
        fail_list: &mut Vec<FailEntry>,
    ) -> Result<()> {
        // Checks if we must ignore this line (only if fewer ignoreregex than failregex).
        if !self.ignore_regex.is_empty()
            && (self.ignore_regex.len() as isize) < self.fail_regex.len() as isize - 2
            && self.ignore_line(ctx, None)?.is_some()
        {
            return Ok(());
        }

        // Pre-filter fail regex (if available):
        let mut pre_groups = FailData::new();
        if self.pref_regex.is_some() {
            let Some(mut pg) = self.search_pref(ctx)? else {
                return Ok(());
            };
            let repl = pg.pop("content");
            // Content replacement:
            if let Some(FailVal::Str(r)) = repl.filter(FailVal::truthy) {
                ctx.repl = Some(vec![TupleLine::new(String::new(), String::new(), r)]);
                ctx.buf_valid = false;
            }
            pre_groups = pg;
        }

        // Iterates over all the regular expressions.
        for idx in 0..self.fail_regex.len() {
            if !ctx.buf_valid {
                tuple_lines_buf(ctx.current(), &mut self.scratch);
                ctx.buf_valid = true;
            }
            let Some(md) = self.search_fail(idx, ctx)? else {
                continue;
            };
            match self.handle_match(idx, md, ctx, date, no_date, defcidr, &pre_groups, fail_list) {
                Ok(Flow::Next) => {}
                Ok(Flow::Stop) => break,
                // RegexException: logged, next regex (upstream `except RegexException`)
                Err(FilterError::Match(e @ MatchError::NoFailId { .. })) => log::error!("{e}"),
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_match(
        &mut self,
        idx: usize,
        md: MatchData,
        ctx: &mut Ctx,
        date: Option<f64>,
        no_date: bool,
        defcidr: Cidr,
        pre_groups: &FailData,
        fail_list: &mut Vec<FailEntry>,
    ) -> Result<Flow> {
        log::trace!("  Matched failregex {idx}");
        // Checks if we must ignore this match.
        if !self.ignore_regex.is_empty() && self.ignore_line(ctx, Some(&md))?.is_some() {
            // The ignoreregex matched. Remove ignored match.
            ctx.buf_valid = false;
            return Ok(if self.check_all_regex {
                Flow::Next
            } else {
                Flow::Stop
            });
        }
        if no_date {
            self.warn_once(
                "noTime",
                &[
                    "Found a match but no valid date/time found.".to_owned(),
                    format!(
                        "Match without a timestamp: {}",
                        md.matched
                            .iter()
                            .map(|l| format!("{}{}{}", l.pre, l.date, l.post))
                            .collect::<Vec<_>>()
                            .join("\n")
                    ),
                    "Please try setting a custom date pattern (see man page jail.conf(5))."
                        .to_owned(),
                ],
            );
            if date.is_none() && self.check_find_time {
                return Ok(Flow::Next);
            }
        }
        let MatchData {
            fail: curr_fail,
            matched,
            unmatched,
        } = md;
        // we should check all regex (bypass on multi-line, otherwise too complex)
        if !self.check_all_regex || self.max_lines > 1 {
            ctx.repl = Some(unmatched);
            ctx.buf_valid = false;
        }
        // merge data if multi-line failure
        let mut cidr = defcidr;
        let mut raw = defcidr == Cidr::Raw;
        let mut fail = if pre_groups.is_empty() {
            curr_fail
        } else {
            let mut f = pre_groups.clone();
            f.update_non_none(curr_fail);
            f
        };
        // first try to check we have mlfid case (caching of connection id by multi-line)
        let mlfid = fail.get_str("mlfid").map(str::to_owned);
        if let Some(id) = &mlfid {
            fail = self.merge_failure(id, fail, &matched);
            let flow = self.finish_match(
                idx,
                &mut fail,
                Some(id),
                date,
                defcidr,
                &mut cidr,
                &mut raw,
                fail_list,
            );
            // the cached failure aliases the returned one upstream
            self.mlfid_store_back(id, fail);
            return flow;
        }
        // matched lines: fail["matches"] = fail.get("matches", []) + matched
        match fail.get_mut("matches") {
            Some(FailVal::Lines(l)) => l.extend(matched.iter().cloned()),
            _ => fail.insert("matches", FailVal::Lines(matched)),
        }
        self.finish_match(
            idx, &mut fail, None, date, defcidr, &mut cidr, &mut raw, fail_list,
        )
    }

    /// The part of `findFailure` after merging: id/ip extraction and DNS.
    #[allow(clippy::too_many_arguments)]
    fn finish_match(
        &mut self,
        idx: usize,
        fail: &mut FailData,
        mlfid: Option<&String>,
        date: Option<f64>,
        defcidr: Cidr,
        cidr: &mut Cidr,
        raw: &mut bool,
        fail_list: &mut Vec<FailEntry>,
    ) -> Result<Flow> {
        // bypass if no-failure case
        if mlfid.is_some() && fail.truthy("nofail") {
            log::trace!("Nofail by mlfid in regex {idx}");
            if !self.check_all_regex {
                return Ok(Flow::Stop);
            }
        }
        // failure-id
        let mut fid = fail.get_str("fid").map(str::to_owned);
        // ip-address or host
        let mut ip = fail.get_str("ip4").map(str::to_owned);
        if ip.is_some() {
            *cidr = cidr_from(fail, Cidr::Inet4)?;
            *raw = true;
        } else {
            ip = fail.get_str("ip6").map(str::to_owned);
            if ip.is_some() {
                *cidr = cidr_from(fail, Cidr::Inet6)?;
                *raw = true;
            } else {
                ip = fail.get_str("dns").map(str::to_owned);
                if ip.is_none() {
                    // first try to check we have mlfid case (cache connection id)
                    if fid.is_none() && mlfid.is_none() {
                        // if no failure-id also (obscure case, wrong regex), error out
                        return Err(FilterError::Match(MatchError::NoFailId {
                            buf: self.scratch.clone(),
                            pattern: self.fail_regex[idx].pattern_repr(),
                        }));
                    }
                    ip = fid.clone();
                    *raw = true;
                }
            }
        }
        let fids: Vec<Option<IPAddr>>;
        // if mlfid case (not failure)
        if fid.is_none() && ip.is_none() {
            log::trace!("No failure-id by mlfid in regex {idx}");
            fail.insert("mlfpending", FailVal::Int(1));
            if !self.check_all_regex && self.ignore_pending {
                return Ok(Flow::Stop);
            }
            fids = vec![None];
        } else if *raw {
            let ipt = ip.unwrap_or_default();
            // check ip/host equal failure-id, if not - failure with complex id
            match fid.take() {
                Some(f) if f != ipt => {
                    fail.insert("ip", FailVal::Ip(IPAddr::with_cidr(&ipt, *cidr)?));
                    fids = vec![Some(IPAddr::with_cidr(&f, defcidr)?)];
                }
                _ => fids = vec![Some(IPAddr::with_cidr(&ipt, *cidr)?)],
            }
        } else {
            // otherwise, try to use dns conversion
            let use_dns = match self.use_dns {
                UseDns::Yes => "yes",
                UseDns::Warn => "warn",
                UseDns::No => "no",
                UseDns::Raw => "raw",
            };
            fids = self
                .dns
                .text_to_ip(&ip.unwrap_or_default(), use_dns)
                .into_iter()
                .map(Some)
                .collect();
        }
        // if checkAllRegex we must make a copy (the merged/cached failure must stay intact)
        for fid in fids {
            fail_list.push(FailEntry {
                regex_index: idx,
                fid,
                date,
                fail: fail.clone(),
            });
        }
        Ok(if self.check_all_regex {
            Flow::Next
        } else {
            Flow::Stop
        })
    }
}

/// Owned result of a successful failregex search.
struct MatchData {
    fail: FailData,
    matched: Vec<TupleLine<String>>,
    unmatched: Vec<TupleLine<String>>,
}

fn groups_to_fail(groups: f2b_regex::Groups<'_>) -> FailData {
    groups
        .into_owned()
        .into_iter()
        .map(|(k, v)| (k, FailVal::from(v)))
        .collect()
}

fn users_len(fail: &FailData) -> usize {
    match fail.get("users") {
        Some(FailVal::Set(s)) => s.len(),
        _ => 0,
    }
}

/// `int(fail.get('cidr') or <family>)`.
fn cidr_from(fail: &FailData, family: Cidr) -> Result<Cidr> {
    match fail.get("cidr") {
        Some(v) if v.truthy() => match v.as_str().and_then(py_int) {
            Some(n) => Ok(Cidr::Prefix(u32::try_from(n.max(0)).unwrap_or(u32::MAX))),
            None => Err(FilterError::Value(format!(
                "invalid literal for int() with base 10: {:?}",
                v.as_str().unwrap_or_default()
            ))),
        },
        _ => Ok(family),
    }
}
