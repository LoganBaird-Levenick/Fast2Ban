//! Port of upstream `server/datedetector.py`.

use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use f2b_helpers::pychar;
use f2b_types::SharedClock;

use crate::civil::{Naive, PyExc};
use crate::error::{DateError, TimeError};
use crate::pyint::is_alnum;
use crate::pyre::{Caps, sub_all};
use crate::strptime::{TimeCtx, TimeRe, ex_year_regex, validate_time_zone};
use crate::template::{
    LINE_BEGIN, LINE_END, RE_DATE_PREMATCH, RE_EPOCH_PATTERN, Template, WordBegin, unbound_pattern,
};
use crate::zone::LocalZone;

/// Upstream `DateDetectorCache.DEFAULT_TEMPLATES`.
const DEFAULT_TEMPLATES: [&str; 17] = [
    // ISO 8601, simple date, optional subsecond and timezone:
    // 2005-01-23T21:59:59.981746, 2005-01-23 21:59:59, 2005-01-23  8:59:59
    // simple date: 2005/01/23 21:59:59
    // custom for syslog-ng 2006.12.21 06:43:20
    r"%ExY(?P<_sep>[-/.])%m(?P=_sep)%d(?:T|  ?)%H:%M:%S(?:[.,]%f)?(?:\s*%z)?",
    // asctime with optional day, subsecond and/or year:
    // Sun Jan 23 21:59:59.011 2005
    r"(?:%a )?%b %d %k:%M:%S(?:\.%f)?(?: %ExY)?",
    // asctime with optional day, subsecond and/or year coming after day
    // Sun Jan 23 2005 21:59:59.011
    r"(?:%a )?%b %d %ExY %k:%M:%S(?:\.%f)?",
    // simple date too (from x11vnc): 23/01/2005 21:59:59
    // and with optional year given by 2 digits: 23/01/05 21:59:59
    // 17-07-2008 17:23:25
    r"%d(?P<_sep>[-/])%m(?P=_sep)(?:%ExY|%Exy) %k:%M:%S",
    // Apache format optional time zone:
    // [31/Oct/2006:09:22:55 -0000]
    // 26-Jul-2007 15:20:52
    // named 26-Jul-2007 15:20:52.252
    // roundcube 26-Jul-2007 15:20:52 +0200
    r"%d(?P<_sep>[-/])%b(?P=_sep)%ExY[ :]?%H:%M:%S(?:\.%f)?(?: %z)?",
    // CPanel 05/20/2008:01:57:39
    r"%m/%d/%ExY:%H:%M:%S",
    // 01-27-2012 16:22:44.252
    // subseconds explicit to avoid possible %m<->%d confusion
    r"%m-%d-%ExY %k:%M:%S(?:\.%f)?",
    // Epoch
    r"EPOCH",
    // Only time information in the log
    r"{^LN-BEG}%H:%M:%S",
    // <09/16/08@05:03:30>
    r"^<%m/%d/%Exy@%H:%M:%S>",
    // MySQL: 130322 11:46:11
    r"%Exy%Exm%Exd  ?%H:%M:%S",
    // Apache Tomcat
    r"%b %d, %ExY %I:%M:%S %p",
    // ASSP: Apr-27-13 02:33:06
    r"^%b-%d-%Exy %k:%M:%S",
    // 20050123T215959, 20050123 215959, 20050123  85959, 20050123-21:59:59
    r"%ExY%Exm%Exd(?:-|T|  ?)%ExH:?%ExM:?%ExS(?:[.,]%f)?(?:\s*%z)?",
    // prefixed with optional named time zone (monit):
    // PDT Apr 16 21:05:29
    r"(?:%Z )?(?:%a )?%b %d %k:%M:%S(?:\.%f)?(?: %ExY)?",
    // +00:00 Jan 23 21:59:59.011 2005
    r"(?:%z )?(?:%a )?%b %d %k:%M:%S(?:\.%f)?(?: %ExY)?",
    // TAI64N
    r"TAI64N",
];

/// Upstream `DateDetector._unusedTime`: a template is "long unused" after 300 s.
const UNUSED_TIME: f64 = 300.0;
/// `0x7fffffff` of upstream.
const FAR: usize = 0x7fff_ffff;

/// Everything a detector needs from its surroundings (upstream reads these
/// from process globals: `MyTime`, `TZ`, the import-time year window).
#[derive(Debug, Clone)]
pub struct DateEnv {
    clock: SharedClock,
    zone: LocalZone,
    year_window_now: Option<f64>,
    wall_clock_year: Option<i64>,
}

impl DateEnv {
    /// `clock` replaces `MyTime.now()`/`time()`; `zone` is the process local
    /// zone (used to turn log lines without time zone into Unix time and to
    /// derive "now" fields).
    pub fn new(clock: SharedClock, zone: LocalZone) -> Self {
        Self {
            clock,
            zone,
            year_window_now: None,
            wall_clock_year: None,
        }
    }

    /// `MyTime.alternateNowTime`, used *only* for the year range of the
    /// `%ExY` pattern (upstream `_updateTimeRE`). `fail2ban-regex` calls
    /// `MyTime.setAlternateNow(0)`, which upstream treats like "unset"
    /// (`0 or 978393600`), so `Some(0.0)` behaves like `None` here too; the
    /// window starts at `min(t, 2001-01-02)`.
    #[must_use]
    pub fn with_year_window_now(mut self, t: Option<f64>) -> Self {
        self.year_window_now = t;
        self
    }

    /// The year `datetime.now()` had when upstream's `strptime` module was
    /// imported; the `%ExY` window ends three years after it. Defaults to the
    /// current wall-clock year (system time, in the local zone).
    #[must_use]
    pub fn with_wall_clock_year(mut self, year: i64) -> Self {
        self.wall_clock_year = Some(year);
        self
    }

    fn time_re(&self) -> TimeRe {
        let wall = self.wall_clock_year.unwrap_or_else(|| {
            let t = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0.0, |d| d.as_secs_f64());
            self.zone.local_civil(t).fields().year
        });
        TimeRe::new(ex_year_regex(wall, self.year_window_now, &self.zone))
    }
}

/// One entry of the detector's template list (read-only view).
#[derive(Debug, Clone, Copy)]
pub struct TemplateInfo<'a> {
    /// Template name (identity; unique within a detector).
    pub name: &'a str,
    /// The date pattern, for pattern templates (not for EPOCH/TAI64N).
    pub pattern: Option<&'a str>,
    /// The final regular expression (Python syntax).
    pub regex: &'a str,
    /// `DateTemplate` flags: `LINE_BEGIN` 8, `LINE_END` 4, `WORD_BEGIN` 2, `WORD_END` 1.
    pub flags: u8,
    /// Template weight (anchored default copies have 100.0).
    pub template_weight: f64,
    /// Hits of this template in this detector.
    pub hits: u64,
    /// Distance (character index) of the last match.
    pub distance: usize,
}

impl TemplateInfo<'_> {
    pub const LINE_BEGIN: u8 = LINE_BEGIN;
    pub const LINE_END: u8 = LINE_END;
}

/// One entry of the template list: the template object (index into the
/// detector's arena) plus upstream's `DateDetectorTemplate` counters.
#[derive(Debug, Clone)]
struct Slot {
    tid: usize,
    hits: u64,
    last_used: f64,
    distance: usize,
}

impl Slot {
    fn new(tid: usize) -> Self {
        Self {
            tid,
            hits: 0,
            last_used: 0.0,
            distance: FAR,
        }
    }
}

fn template_info(t: &Template) -> TemplateInfo<'_> {
    TemplateInfo {
        name: &t.name,
        pattern: t.pattern(),
        regex: &t.regex,
        flags: t.flags,
        template_weight: t.weight,
        hits: 0,
        distance: FAR,
    }
}

/// Result of [`DateDetector::match_time`] (upstream's `(match, template)`).
///
/// Valid until the next `match_time` call on the same detector (which may
/// reorder the templates).
#[derive(Debug, Clone)]
pub struct TimeMatch<'a> {
    line: &'a str,
    caps: Option<Caps>,
    template: usize,
}

impl<'a> TimeMatch<'a> {
    /// `true` if some template matched.
    pub fn is_match(&self) -> bool {
        self.caps.is_some()
    }

    /// Byte span of regex group 1 (the date text, `m.start(1)`/`m.end(1)`);
    /// `None` if nothing matched or the group did not participate.
    pub fn span(&self) -> Option<(usize, usize)> {
        self.caps.as_ref()?.get(1).copied().flatten()
    }

    /// The date text (group 1).
    pub fn date_text(&self) -> Option<&'a str> {
        self.span().map(|(s, e)| &self.line[s..e])
    }

    /// Byte span of the whole regex match (`m.start()`, `m.end()`).
    pub fn match_span(&self) -> Option<(usize, usize)> {
        self.caps.as_ref()?.first().copied().flatten()
    }

    /// Index of the winning template in the detector's list *after* the
    /// reorder done by this match.
    pub fn template_index(&self) -> Option<usize> {
        self.caps.as_ref().map(|_| self.template)
    }
}

/// `Filter.getDatePattern` result.
pub type DatePatternInfo<'a> = (Option<&'a str>, &'a str);

/// Character-index view of a line (upstream indexes `str` by code point).
struct Chars<'a> {
    line: &'a str,
    ascii: bool,
}

impl<'a> Chars<'a> {
    fn new(line: &'a str) -> Self {
        Self {
            line,
            ascii: line.is_ascii(),
        }
    }

    /// Character at index `i` (`line[i:i+1]`).
    fn at(&self, i: usize) -> Option<char> {
        if self.ascii {
            self.line.as_bytes().get(i).map(|b| char::from(*b))
        } else {
            self.line.chars().nth(i)
        }
    }

    /// `line[i-1:i]`
    fn before(&self, i: usize) -> Option<char> {
        i.checked_sub(1).and_then(|p| self.at(p))
    }

    /// Byte offset of character index `i`, clamped to the line length.
    fn byte_of(&self, i: usize) -> usize {
        if self.ascii {
            i.min(self.line.len())
        } else {
            self.line
                .char_indices()
                .nth(i)
                .map_or(self.line.len(), |(b, _)| b)
        }
    }

    /// Character index of byte offset `b`.
    fn index_of(&self, b: usize) -> usize {
        if self.ascii {
            b
        } else {
            self.line[..b].chars().count()
        }
    }

    fn last(&self) -> Option<char> {
        self.line.chars().next_back()
    }
}

/// Key of a pattern in upstream's `DD_patternCache`.
fn cache_key(pattern: &str) -> String {
    if pattern.contains('%') {
        pattern.to_string()
    } else {
        pattern.to_uppercase()
    }
}

/// Filter for `add_default_template`: return `true` to keep a template.
pub type TemplateFilter<'a> = &'a dyn Fn(&TemplateInfo<'_>) -> bool;

/// Manages one or more date templates to find a date within a log line.
///
/// Template objects live in an arena; the list order (`templates`) is
/// permuted by hit-reordering. A per-detector pattern cache mirrors upstream's
/// `DD_patternCache` *within* one detector (including its quirks, e.g. keys of
/// patterns without `%` are upper-cased, and a template created for a user
/// pattern is the very object the default-template cache later hands out).
#[derive(Debug, Clone)]
pub struct DateDetector {
    env: DateEnv,
    tre: TimeRe,
    arena: Vec<Template>,
    /// `DD_patternCache`: key -> arena index
    cache: HashMap<String, usize>,
    /// `DateDetectorCache.defaultTemplates` / `.templates` (computed once)
    default_list: Option<Vec<usize>>,
    default_cache_list: Option<Vec<usize>>,
    templates: Vec<Slot>,
    known_names: HashSet<String>,
    /// last known distance (bypass one char collision) and end position:
    /// `(char index, char before, char at)` / `(char index, char before end, char at end)`
    last_pos: (usize, Option<char>, Option<char>),
    last_end_pos: (usize, Option<char>, Option<char>),
    last_templ_idx: usize,
    first_unused: usize,
    default_tz: Option<i64>,
}

impl DateDetector {
    /// An empty detector (`DateDetector()`); the default templates are added
    /// on the first `match_time` if none were appended.
    pub fn new(env: DateEnv) -> Self {
        let tre = env.time_re();
        Self {
            env,
            tre,
            arena: Vec::new(),
            cache: HashMap::new(),
            default_list: None,
            default_cache_list: None,
            templates: Vec::new(),
            known_names: HashSet::new(),
            last_pos: (1, None, None),
            last_end_pos: (FAR, None, None),
            last_templ_idx: FAR,
            first_unused: 0,
            default_tz: None,
        }
    }

    /// A detector with the full default template set already added.
    pub fn with_default_templates(env: DateEnv) -> Result<Self, DateError> {
        let mut dd = Self::new(env);
        dd.add_default_template(None, None, true)?;
        Ok(dd)
    }

    /// `Filter.setDatePattern` for a (possibly multi-line) pattern string:
    /// patterns are split at newlines, stripped, empty ones dropped; each is
    /// appended as a template. `tz` is the filter's `logtimezone`.
    pub fn from_date_pattern(
        pattern: &str,
        tz: Option<&str>,
        env: DateEnv,
    ) -> Result<Self, DateError> {
        let list: Vec<&str> = pattern
            .split('\n')
            .map(pychar::strip)
            .filter(|s| !s.is_empty())
            .collect();
        Self::from_date_patterns(&list, tz, env)
    }

    /// `Filter.setDatePattern` for a list of patterns (used as given).
    pub fn from_date_patterns<S: AsRef<str>>(
        patterns: &[S],
        tz: Option<&str>,
        env: DateEnv,
    ) -> Result<Self, DateError> {
        let mut dd = Self::new(env);
        dd.set_default_tz(tz)?;
        for p in patterns {
            dd.append_template(p.as_ref())?;
        }
        Ok(dd)
    }

    /// The environment the detector was built with.
    pub fn env(&self) -> &DateEnv {
        &self.env
    }

    /// `default_tz` as minutes east of UTC (`validateTimeZone` result).
    pub fn default_tz(&self) -> Option<i64> {
        self.default_tz
    }

    /// Set the default time zone for dates without explicit zone
    /// (`default_tz` setter): `UTC`, `CET`, `+0200`, `UTC+02:00`, ... or
    /// `None`. Errors like `validateTimeZone`.
    pub fn set_default_tz(&mut self, tz: Option<&str>) -> Result<(), DateError> {
        self.default_tz = match tz {
            None => None,
            Some(t) => Some(validate_time_zone(t).map_err(|_| DateError::TimeZone(t.to_string()))?),
        };
        Ok(())
    }

    /// Number of templates (`len(dd.templates)`).
    pub fn template_count(&self) -> usize {
        self.templates.len()
    }

    fn tmpl(&self, slot: usize) -> &Template {
        &self.arena[self.templates[slot].tid]
    }

    fn weight(&self, slot: usize) -> f64 {
        let s = &self.templates[slot];
        s.hits as f64 * self.arena[s.tid].weight / s.distance.max(1) as f64
    }

    /// The templates in their current (hit-reordered) order.
    pub fn templates(&self) -> impl ExactSizeIterator<Item = TemplateInfo<'_>> {
        self.templates.iter().map(|s| TemplateInfo {
            hits: s.hits,
            distance: s.distance,
            ..template_info(&self.arena[s.tid])
        })
    }

    /// `Filter.getDatePattern` (for an existing detector): `(pattern, name)`
    /// of the single template, or `(None, "Default Detectors")` if there is
    /// none (yet) or more than two.
    pub fn get_date_pattern(&self) -> DatePatternInfo<'_> {
        if self.templates.is_empty() || self.templates.len() > 2 {
            return (None, "Default Detectors");
        }
        let t = self.tmpl(0);
        (t.pattern(), &t.name)
    }

    /// `_appendTemplate(template, ignoreDup)`.
    fn append_slot(&mut self, tid: usize, ignore_dup: bool) -> Result<(), DateError> {
        let name = &self.arena[tid].name;
        if self.known_names.contains(name) {
            if ignore_dup {
                return Ok(());
            }
            return Err(DateError::DuplicateTemplate(name.clone()));
        }
        self.known_names.insert(name.clone());
        self.templates.push(Slot::new(tid));
        Ok(())
    }

    /// `appendTemplate(str)`: add the template for a date pattern, or expand
    /// the special patterns `{^LN-BEG}`, `{DEFAULT}`, `{NONE}`, patterns
    /// containing `{DATE}`, `EPOCH`, `{^LN-BEG}EPOCH`, `LEPOCH`, `TAI64N`...
    pub fn append_template(&mut self, pattern: &str) -> Result<(), DateError> {
        let key = cache_key(pattern);
        let tid = if let Some(&tid) = self.cache.get(&key) {
            tid
        } else if key == "{^LN-BEG}" || key == "{DEFAULT}" {
            // upstream: the `{DEFAULT}` filter is `... else None`, which rejects
            // every template (the defaults are then added lazily by matchTime)
            let line_begin = key == "{^LN-BEG}";
            return self.add_default_template(
                Some(&move |t| line_begin && t.flags & LINE_BEGIN != 0),
                None,
                true,
            );
        } else if key.contains("{DATE}") {
            return self.add_default_template(None, Some(pattern), false);
        } else if key == "{NONE}" {
            self.pattern_template("{UNB}^", Some(&key))?
        } else {
            self.pattern_template(pattern, Some(&key))?
        };
        self.cache.insert(key, tid);
        self.append_slot(tid, false)
    }

    /// `addDefaultTemplate(filterTemplate, preMatch, allDefaults)`.
    pub fn add_default_template(
        &mut self,
        filter: Option<TemplateFilter<'_>>,
        pre_match: Option<&str>,
        all_defaults: bool,
    ) -> Result<(), DateError> {
        let ignore_dup = !self.templates.is_empty();
        let list = if all_defaults {
            self.default_cache()?
        } else {
            self.default_templates()?
        };
        for tid in list {
            if let Some(f) = filter
                && !f(&template_info(&self.arena[tid]))
            {
                continue;
            }
            // if exact pattern available - create copy of template, contains replaced {DATE}
            // with default regex:
            let tid = match pre_match {
                None => tid,
                Some(pm) => self.anchored_template(tid, &|s: &str| {
                    sub_all(&RE_DATE_PREMATCH, pm, 0, |_, _| unbound_pattern(s))
                })?,
            };
            // append date detector template (ignore duplicate if some was added before default):
            self.append_slot(tid, ignore_dup)?;
        }
        Ok(())
    }

    /// `_getPatternTemplate(pattern, key)`: the cached template for `key`, or a
    /// new one.
    fn pattern_template(&mut self, pattern: &str, key: Option<&str>) -> Result<usize, DateError> {
        let key = key.map_or_else(|| cache_key(pattern), str::to_string);
        if let Some(&tid) = self.cache.get(&key) {
            return Ok(tid);
        }
        let template = 'make: {
            if key.contains("EPOCH") {
                if RE_EPOCH_PATTERN.search(pattern, 0).is_some() {
                    break 'make Template::epoch(false, Some(pattern), key.contains("LEPOCH"))?;
                }
                if matches!(key.as_str(), "EPOCH" | "{^LN-BEG}EPOCH" | "^EPOCH") {
                    break 'make Template::epoch(key != "EPOCH", None, false)?;
                }
                if matches!(key.as_str(), "LEPOCH" | "{^LN-BEG}LEPOCH" | "^LEPOCH") {
                    break 'make Template::epoch(key != "LEPOCH", None, true)?;
                }
            }
            if matches!(key.as_str(), "TAI64N" | "{^LN-BEG}TAI64N" | "^TAI64N") {
                let wb = if key != "TAI64N" {
                    WordBegin::Start
                } else {
                    WordBegin::No
                };
                break 'make Template::tai64n(wb)?;
            }
            Template::from_pattern(pattern, &self.tre)?
        };
        let tid = self.arena.len();
        self.arena.push(template);
        self.cache.insert(key, tid);
        Ok(tid)
    }

    /// `_getAnchoredTemplate(template, wrap)`.
    fn anchored_template(
        &mut self,
        tid: usize,
        wrap: &dyn Fn(&str) -> String,
    ) -> Result<usize, DateError> {
        // wrap name:
        let name = wrap(&self.arena[tid].name);
        // try to find in cache (by name):
        if let Some(&t2) = self.cache.get(&name) {
            return Ok(t2);
        }
        // wrap pattern (or regexp if not pattern template):
        let pattern = self.arena[tid].pattern().map(str::to_string);
        match pattern {
            Some(p) => {
                let regex = wrap(&p);
                // try to find in cache (by pattern):
                if let Some(&t2) = self.cache.get(&regex) {
                    return Ok(t2);
                }
                // make duplicate and set new anchored regex:
                self.pattern_template(&regex, None)
            }
            None => self.pattern_template(&name, None),
        }
    }

    /// `DateDetectorCache.defaultTemplates`.
    fn default_templates(&mut self) -> Result<Vec<usize>, DateError> {
        if let Some(l) = &self.default_list {
            return Ok(l.clone());
        }
        let mut list = Vec::with_capacity(DEFAULT_TEMPLATES.len());
        for dt in DEFAULT_TEMPLATES {
            list.push(self.pattern_template(dt, None)?);
        }
        self.default_list = Some(list.clone());
        Ok(list)
    }

    /// `DateDetectorCache.templates`: line-begin anchored copies (weight 100)
    /// followed by the defaults.
    fn default_cache(&mut self) -> Result<Vec<usize>, DateError> {
        if let Some(l) = &self.default_cache_list {
            return Ok(l.clone());
        }
        let mut anchored = Vec::new();
        let mut all = Vec::new();
        for tid in self.default_templates()? {
            let name = self.arena[tid].name.clone();
            // if not already line-begin anchored, additional template, that prefers datetime
            // at start of a line (safety+performance feature):
            if !name.starts_with("{^LN-BEG}") && !name.starts_with('^') {
                let t2 = self.anchored_template(tid, &|s: &str| format!("{{^LN-BEG}}{s}"))?;
                // prevent to add duplicates:
                if self.arena[t2].name != name {
                    // increase weight of such templates, because they should be always
                    // preferred in template sorting process (bubble up):
                    self.arena[t2].weight = 100.0;
                    anchored.push(t2);
                }
            }
            all.push(tid);
        }
        anchored.extend(all);
        self.default_cache_list = Some(anchored.clone());
        Ok(anchored)
    }

    fn now(&self) -> f64 {
        self.env.clock.time()
    }

    /// `matchTime(line)`: find the date in `line` with the best template.
    pub fn match_time<'a>(&mut self, line: &'a str) -> TimeMatch<'a> {
        // if no templates specified - default templates should be used:
        if self.templates.is_empty() && self.add_default_template(None, None, true).is_err() {
            return TimeMatch {
                line,
                caps: None,
                template: 0,
            };
        }
        let ch = Chars::new(line);
        let mut caps: Option<Caps> = None;
        let mut found: (Option<Caps>, usize, usize, usize) = (None, FAR, FAR, usize::MAX);
        let mut ignore_by_search = FAR;
        let (mut distance, mut endpos) = (0usize, 0usize);
        let mut i = self.last_templ_idx;
        let n_templates = self.templates.len();
        let span = |c: &Caps, ch: &Chars<'_>| -> (usize, usize) {
            let (s, e) = c[0].unwrap_or((0, 0));
            (ch.index_of(s), ch.index_of(e))
        };

        // first try to use last template with same start/end position:
        if i < n_templates {
            let flags = self.tmpl(i).flags;
            if flags & (LINE_BEGIN | LINE_END) != 0 {
                caps = self.search(i, line, 0, line.len());
                ignore_by_search = i;
            } else {
                let (d, e) = (self.last_pos.0, self.last_end_pos.0);
                // check same boundaries left/right, outside fully equal, inside only if not alnum:
                let left = ch.before(d) == self.last_pos.1
                    || (self.last_pos.2.is_some()
                        && ch.at(d) == self.last_pos.2
                        && !self.last_pos.2.is_some_and(is_alnum));
                let right = ch.at(e) == self.last_end_pos.2
                    || (self.last_end_pos.1.is_some()
                        && ch.before(e) == self.last_end_pos.1
                        && !self.last_end_pos.1.is_some_and(is_alnum));
                if left && right {
                    // search in line part only:
                    let (pb, eb) = (ch.byte_of(d), ch.byte_of(e));
                    caps = self.search(i, line, pb, eb);
                } else {
                    caps = self.search(i, line, 0, line.len());
                    ignore_by_search = i;
                }
            }
            if let Some(c) = &caps {
                (distance, endpos) = span(c, &ch);
                // if different position, possible collision/pattern switch:
                if n_templates == 1
                    || flags & (LINE_BEGIN | LINE_END) != 0
                    || (distance == self.last_pos.0 && endpos == self.last_end_pos.0)
                {
                    // matched last time template
                } else {
                    found = (caps.take(), distance, endpos, i); // save current best alternative
                }
            }
        }
        // search template and better match:
        if caps.is_none() {
            i = 0;
            while i < n_templates {
                if i == ignore_by_search {
                    i += 1;
                    continue;
                }
                caps = self.search(i, line, 0, line.len());
                if let Some(c) = &caps {
                    (distance, endpos) = span(c, &ch);
                    let (flags, tmpl_distance) = (self.tmpl(i).flags, self.templates[i].distance);
                    // last (or single) template - fast stop:
                    if i + 1 >= n_templates {
                        break;
                    }
                    // if line-begin/end anchored - stop searching:
                    if flags & (LINE_BEGIN | LINE_END) != 0 {
                        break;
                    }
                    // stop searching if next template still unused, but we had already hits:
                    if distance == 0 && self.templates[i].hits > 0 && self.tmpl(i + 1).hits == 0 {
                        break;
                    }
                    // [grave] if distance changed, possible date-match was found somewhere
                    // in body of message, so save this template, and search further:
                    if distance > tmpl_distance || distance > self.last_pos.0 {
                        // shortest of both:
                        if distance < found.1 {
                            found = (caps.take(), distance, endpos, i);
                        }
                        // search further:
                        caps = None;
                        i += 1;
                        continue;
                    }
                    // winner - stop search:
                    break;
                }
                i += 1;
            }
            // check other template was found (use this one with shortest distance):
            if caps.is_none() && found.0.is_some() {
                let (c, d, e, idx) = found;
                caps = c;
                distance = d;
                endpos = e;
                i = idx;
            }
        }
        // we've winner, incr hits, set distance, usage, reorder, etc:
        if caps.is_some() {
            let now = self.now();
            let slot = &mut self.templates[i];
            slot.hits += 1;
            slot.last_used = now;
            slot.distance = distance;
            if self.first_unused == i {
                self.first_unused += 1;
            }
            self.last_pos = (distance, ch.before(distance), ch.at(distance));
            self.last_end_pos = (
                endpos,
                if endpos == 0 {
                    ch.last()
                } else {
                    ch.at(endpos - 1)
                },
                ch.at(endpos),
            );
            // if not first - try to reorder current template (bubble up), they will be not sorted anymore:
            if i != 0 && i != self.last_templ_idx {
                i = self.reorder_template(i);
            }
            self.last_templ_idx = i;
            return TimeMatch {
                line,
                caps,
                template: i,
            };
        }
        TimeMatch {
            line,
            caps: None,
            template: 0,
        }
    }

    /// `template.matchDate(line, pos, endpos)` with byte offsets, counting
    /// the template hit.
    fn search(&mut self, idx: usize, line: &str, pos: usize, endpos: usize) -> Option<Caps> {
        let tid = self.templates[idx].tid;
        let m = self.arena[tid].match_date(line, pos, endpos);
        if m.is_some() {
            self.arena[tid].hits += 1;
        }
        m
    }

    /// `getTime(line, timeMatch)`: Unix time of a [`match_time`](Self::match_time)
    /// result, `None` if nothing matched or the date is invalid (upstream
    /// `ValueError`). `date_text` is accepted for symmetry with upstream's
    /// `line` argument, which upstream ignores when a match is given.
    ///
    /// Exceptions other than `ValueError` (which upstream lets escape from
    /// `getTime`) are mapped to `None` here; use
    /// [`try_get_time`](Self::try_get_time) to see them.
    pub fn get_time(&self, date_text: &str, tm: &TimeMatch<'_>) -> Option<f64> {
        self.try_get_time(date_text, tm).ok().flatten()
    }

    /// Like [`get_time`](Self::get_time), but reports the Python exceptions
    /// that escape upstream's `getTime` (e.g. `KeyError` for `%Z` = `ERROR`).
    pub fn try_get_time(
        &self,
        _date_text: &str,
        tm: &TimeMatch<'_>,
    ) -> Result<Option<f64>, DateError> {
        let Some(caps) = &tm.caps else {
            return Ok(None);
        };
        let Some(slot) = self.templates.get(tm.template) else {
            return Ok(None);
        };
        let now = || -> Naive { self.env.zone.local_civil(self.env.clock.time()) };
        let ctx = TimeCtx {
            zone: &self.env.zone,
            now: &now,
            default_tz: self.default_tz,
        };
        self.arena[slot.tid]
            .get_date(tm.line, caps, &ctx)
            .map_err(|e| DateError::Time(map_exc(e)))
    }

    /// `getTime(line)` without a previous match: runs `match_time` first.
    pub fn get_time_for_line(&mut self, line: &str) -> Option<f64> {
        let tm = self.match_time(line);
        self.get_time(line, &tm)
    }

    /// `_reorderTemplate(num)`: move a template up if its weight grew enough.
    fn reorder_template(&mut self, num: usize) -> usize {
        if num == 0 {
            return num;
        }
        // current hits and time the template was long unused:
        let untime = self.templates[num].last_used - UNUSED_TIME;
        let weight = self.weight(num);
        // try to move faster (first if unused available, or half of part to current template position):
        let mut pos = if self.first_unused < num {
            self.first_unused
        } else {
            num / 2
        };
        // don't move too often (multiline logs resp. log's with different date patterns),
        // if template not used too long, replace it also :
        let moveable =
            |s: &Self, pos: usize| weight > s.weight(pos) || untime > s.templates[pos].last_used;
        // if not moveable (smaller weight or target position recently used):
        if !moveable(self, pos) {
            // try to move slow (exact 1 position):
            if pos == num - 1 {
                return num;
            }
            pos = num - 1;
            // if still smaller and template at position used, don't move:
            if !moveable(self, pos) {
                return num;
            }
        }
        // move:
        let t = self.templates.remove(num);
        self.templates.insert(pos, t);
        // correct first unused:
        while self.first_unused < self.templates.len() && self.templates[self.first_unused].hits > 0
        {
            self.first_unused += 1;
        }
        pos
    }
}

fn map_exc(e: PyExc) -> TimeError {
    match e {
        PyExc::Type => TimeError::Type,
        PyExc::Key => TimeError::Key,
        PyExc::Index => TimeError::Index,
        PyExc::Attribute => TimeError::Attribute,
        PyExc::Value | PyExc::Overflow => TimeError::Overflow,
    }
}
