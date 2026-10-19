//! Port of `Fail2banRegex` and command-line execution from
//! `fail2ban/client/fail2banregex.py`.

use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Instant;

use f2b_config::{Arg, Fs, JailReader};
use f2b_date::{DateEnv, LocalZone};
use f2b_filter::{FailData, FailEntry, FailVal, Filter};
use f2b_helpers::extract_options;
use f2b_regex::TupleLine;
use f2b_types::{DnsUtils, Ipv6Policy, system_clock};

use crate::console::{err_raw, out};
use crate::optparse::Values;
use crate::pyrepr::{fail_data_repr, fail_val_str, float_repr, repr, str_map_repr};

pub fn shortstr(s: &str, l: usize) -> String {
    if s.chars().count() > l {
        let prefix: String = s.chars().take(l.saturating_sub(3)).collect();
        format!("{prefix}...")
    } else {
        s.to_owned()
    }
}

pub fn pprint_list(list: &[String], header: Option<&str>) {
    if list.is_empty() {
        return;
    }
    let mut s = String::new();
    if let Some(h) = header {
        s.push_str(&format!("|- {h}\n"));
    }
    s.push_str("|  ");
    s.push_str(&list.join("\n|  "));
    s.push_str("\n`-");
    out(&s);
}

#[derive(Clone, Debug)]
pub struct RegexStat {
    pub pattern: String,
    pub hits: usize,
    pub ip_list: Vec<(String, String, f64, bool)>,
}

impl RegexStat {
    pub fn new(pattern: String) -> Self {
        Self {
            pattern,
            hits: 0,
            ip_list: Vec::new(),
        }
    }

    pub fn inc(&mut self) {
        self.hits += 1;
    }

    pub fn append_ip(&mut self, fid: String, time_str: String, ts: f64, multiple: bool) {
        self.ip_list.push((fid, time_str, ts, multiple));
    }
}

#[derive(Clone, Debug, Default)]
pub struct LineStats {
    pub tested: usize,
    pub matched: usize,
    pub matched_lines: Vec<String>,
    pub missed: usize,
    pub missed_lines: Vec<String>,
    pub ignored: usize,
    pub ignored_lines: Vec<String>,
    pub matched_lines_timeextracted: Vec<String>,
    pub missed_lines_timeextracted: Vec<String>,
    pub ignored_lines_timeextracted: Vec<String>,
}

pub struct Fail2banRegex {
    opts: Values,
    filter: Filter,
    local_zone: LocalZone,
    date_pattern_set: bool,
    maxlines_set: bool,
    maxlines: usize,
    pref_re_matched: usize,
    pref_re_groups: Vec<String>,
    failregex: Vec<RegexStat>,
    ignoreregex: Vec<RegexStat>,
    line_stats: LineStats,
    time_elapsed: Option<f64>,
    backend: String,
    fs: Rc<dyn Fs>,
}
impl std::fmt::Debug for Fail2banRegex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fail2banRegex")
            .field("opts", &self.opts)
            .finish_non_exhaustive()
    }
}

impl Fail2banRegex {
    pub fn new(opts: Values, local_zone: LocalZone, fs: Rc<dyn Fs>) -> Result<Self, String> {
        let clock = system_clock();
        let dns = Arc::new(DnsUtils::system(clock.clone()));
        let allow_v6 = opts.str("usedns").is_none_or(|u| u != "no");
        dns.set_ipv6_policy(if allow_v6 {
            Ipv6Policy::Yes
        } else {
            Ipv6Policy::No
        });

        // Fail2BanRegex calls MyTime.setAlternateNow(0) + _updateTimeRE()
        // so every year from 19xx to end of century is accepted
        let date_env =
            DateEnv::new(clock.clone(), local_zone.clone()).with_year_window_now(Some(0.0));
        let mut filter = Filter::with_date_env(clock, dns, date_env);
        filter.check_find_time = false;
        filter.track_pref_match = true;
        filter.keep_processed_line = true;

        if let Some(tz) = opts.str("timezone") {
            filter.set_log_time_zone(tz).map_err(|e| e.to_string())?;
        }
        if let Some(usedns) = opts.str("usedns") {
            filter.set_use_dns(usedns);
        }
        filter.return_raw_host = opts.flag("raw");
        let has_out = opts.str("out").is_some();
        filter.check_all_regex = opts.flag("checkAllRegex") && !has_out;
        filter.ignore_pending = has_out;

        let maxlines_arg = opts.int("maxlines").unwrap_or(0);
        let maxlines = if maxlines_arg > 0 {
            maxlines_arg as usize
        } else {
            20
        };

        let mut app = Self {
            opts,
            filter,
            local_zone,
            date_pattern_set: false,
            maxlines_set: false,
            maxlines,
            pref_re_matched: 0,
            pref_re_groups: Vec::new(),
            failregex: Vec::new(),
            ignoreregex: Vec::new(),
            line_stats: LineStats::default(),
            time_elapsed: None,
            backend: "auto".to_owned(),
            fs,
        };

        if maxlines_arg > 0 {
            app.set_max_lines(maxlines_arg)?;
        }
        if let Some(dp) = app.opts.str("datepattern").map(str::to_owned) {
            app.set_date_pattern(&dp)?;
        }

        Ok(app)
    }

    fn output_suppressed(&self) -> bool {
        self.opts.str("out").is_some()
    }

    fn print(&self, s: &str) {
        if !self.output_suppressed() {
            out(s);
        }
    }

    fn set_date_pattern(&mut self, pattern: &str) -> Result<(), String> {
        if !self.date_pattern_set {
            self.filter
                .set_date_pattern(Some(pattern))
                .map_err(|e| e.to_string())?;
            self.date_pattern_set = true;
            let label = self
                .filter
                .date_detector()
                .map_or("Custom", |d| d.get_date_pattern().1);
            self.print(&format!("Use      datepattern : {pattern} : {label}"));
        }
        Ok(())
    }

    fn set_max_lines(&mut self, v: i64) -> Result<(), String> {
        if !self.maxlines_set {
            self.filter.set_max_lines(v).map_err(|e| e.to_string())?;
            self.maxlines_set = true;
            self.print(&format!(
                "Use         maxlines : {}",
                self.filter.max_lines()
            ));
        }
        Ok(())
    }

    pub fn start(&mut self, args: &[String]) -> Result<bool, String> {
        let (cmd_log, cmd_regex) = (&args[0], &args[1]);
        if cmd_log.starts_with("systemd-journal") {
            self.backend = "systemd".to_owned();
        }

        if !self.read_regex(cmd_regex, "fail")? {
            return Ok(false);
        }
        if args.len() == 3 && !self.read_regex(&args[2], "ignore")? {
            return Ok(false);
        }

        let test_lines: Vec<String> = if self.fs.is_file(cmd_log) {
            let enc = self.opts.str("encoding").unwrap_or("utf-8");
            self.print(&format!("Use         log file : {cmd_log}"));
            self.print(&format!("Use         encoding : {enc}"));
            let data = self
                .fs
                .read_to_string(cmd_log)
                .map_err(|e| format!("cannot read log file: {e}"))?;
            data.split('\n')
                .map(|l| l.trim_end_matches('\r').to_owned())
                .collect()
        } else if cmd_log.starts_with("systemd-journal") {
            err_raw("systemd journal backend is not available in this build\n");
            return Ok(false);
        } else if self.filter.max_lines() <= 1 && !cmd_log.contains('\n') {
            self.print(&format!(
                "Use      single line : {}",
                shortstr(&cmd_log.replace('\n', "\\n"), 53)
            ));
            vec![cmd_log.clone()]
        } else {
            let parts: Vec<&str> = cmd_log.split('\n').collect();
            self.print(&format!("Use      multi line : {} line(s)", parts.len()));
            for (i, l) in parts.iter().enumerate() {
                if i >= 5 {
                    self.print("| ...");
                    break;
                }
                self.print(&format!("| {:2}: {}", i + 1, shortstr(l, 53)));
            }
            self.print("`-");
            parts.into_iter().map(str::to_owned).collect()
        };

        self.print("");
        self.process(&test_lines);
        self.print_stats();
        Ok(true)
    }

    fn read_regex(&mut self, value: &str, regextype: &str) -> Result<bool, String> {
        let basedir_opt = self.opts.str("config").unwrap_or("/etc/fail2ban");
        let mut reader_commands: Option<Vec<f2b_config::Command>> = None;

        if regextype == "fail" {
            let re_cand = regex::Regex::new(r"(?ms)^/{0,3}[\w/_\-.]+(?:\[.*\])?$").unwrap();
            if re_cand.is_match(value) {
                if let Ok((flt_name, flt_opt)) = extract_options(value) {
                    let is_file_like = flt_name.contains('/')
                        || flt_name.ends_with(".conf")
                        || flt_name.ends_with(".local");

                    let share = Rc::new(std::cell::RefCell::new(std::collections::HashMap::new()));
                    // Check if it is a jail
                    let mut jail_cand = None;
                    if !is_file_like {
                        let mut jr = JailReader::standalone(
                            self.fs.clone(),
                            share.clone(),
                            basedir_opt,
                            &flt_name,
                            true,
                        );
                        if jr.read().is_ok() {
                            jail_cand = Some(jr);
                        }
                    }

                    if let Some(mut jr) = jail_cand {
                        self.print(&format!("Use             jail : {flt_name}"));
                        if !flt_opt.is_empty() {
                            self.print(&format!(
                                "Use jail/flt options : {}",
                                str_map_repr(&flt_opt)
                            ));
                        }
                        let mut add_opts = flt_opt.clone();
                        add_opts.insert("backend".to_owned(), self.backend.clone());
                        let ok = jr.get_options_with(&add_opts).map_err(|e| e.to_string())?;
                        if !ok {
                            out(&format!("ERROR: Failed to get jail for {value:?}"));
                            return Ok(false);
                        }
                        reader_commands = Some(jr.convert(true, true).map_err(|e| e.to_string())?);
                    } else {
                        // Check if it is a filter file
                        let try_names =
                            if flt_name.ends_with(".conf") || flt_name.ends_with(".local") {
                                vec![flt_name.clone()]
                            } else {
                                vec![
                                    flt_name.clone(),
                                    format!("{flt_name}.conf"),
                                    format!("{flt_name}.local"),
                                ]
                            };
                        let mut found_path = None;
                        let mut search_basedir = basedir_opt.to_owned();
                        for cand in try_names {
                            let p = Path::new(&cand);
                            let resolved = if p.parent() == Some(Path::new("filter.d")) {
                                Path::new(&search_basedir).join(p)
                            } else if !cand.contains('/') {
                                if Path::new(&search_basedir).file_name()
                                    == Some(std::ffi::OsStr::new("filter.d"))
                                {
                                    Path::new(&search_basedir).join(p)
                                } else {
                                    Path::new(&search_basedir).join("filter.d").join(p)
                                }
                            } else {
                                if let Some(parent) = p.parent() {
                                    search_basedir = parent.to_str().unwrap().to_owned();
                                }
                                p.to_path_buf()
                            };
                            if self.fs.is_file(resolved.to_str().unwrap()) {
                                found_path = Some(resolved);
                                break;
                            }
                        }

                        if let Some(fpath) = found_path {
                            let stem = fpath.file_stem().unwrap().to_str().unwrap();
                            let bdir = if Path::new(&search_basedir).file_name()
                                == Some(std::ffi::OsStr::new("filter.d"))
                            {
                                Path::new(&search_basedir)
                                    .parent()
                                    .unwrap()
                                    .to_str()
                                    .unwrap()
                            } else {
                                &search_basedir
                            };
                            self.print(&format!("Use      filter file : {stem}, basedir: {bdir}"));
                            if !flt_opt.is_empty() {
                                self.print(&format!(
                                    "Use   filter options : {}",
                                    str_map_repr(&flt_opt)
                                ));
                            }
                            let stream = f2b_config::read_filter_stream(
                                self.fs.clone(),
                                bdir,
                                stem,
                                "fail2ban-regex-jail",
                                flt_opt,
                                Some(&self.backend),
                            )
                            .map_err(|e| e.to_string())?;
                            if let Some(s) = stream {
                                reader_commands = Some(s);
                            } else {
                                out(&format!("ERROR: failed to load filter {value}"));
                                return Ok(false);
                            }
                        }
                    }
                }
            }
        }

        let regex_name = format!("{regextype}regex");
        let mut regex_stats: Vec<RegexStat> = Vec::new();

        if let Some(cmds) = reader_commands {
            for cmd in cmds {
                let (Some(Arg::Str(kind)), Some(Arg::Str(target))) = (cmd.first(), cmd.get(2))
                else {
                    continue;
                };
                let vals: Vec<&Arg> = match kind.as_str() {
                    "multi-set" => match cmd.get(3) {
                        Some(Arg::List(l)) => l.iter().collect(),
                        _ => Vec::new(),
                    },
                    "set" => cmd[3..].iter().collect(),
                    _ => Vec::new(),
                };
                for v in vals {
                    match target.as_str() {
                        "prefregex" => {
                            if let Arg::Str(text) = v {
                                self.filter
                                    .set_pref_regex(Some(text))
                                    .map_err(|e| e.to_string())?;
                            }
                        }
                        "addfailregex" => {
                            if let Arg::Str(text) = v {
                                regex_stats.push(RegexStat::new(text.clone()));
                                self.filter
                                    .add_fail_regex(text)
                                    .map_err(|e| e.to_string())?;
                            }
                        }
                        "addignoreregex" => {
                            if let Arg::Str(text) = v {
                                regex_stats.push(RegexStat::new(text.clone()));
                                self.filter
                                    .add_ignore_regex(text)
                                    .map_err(|e| e.to_string())?;
                            }
                        }
                        "maxlines" => {
                            let n = match v {
                                Arg::Int(n) => Some(*n),
                                Arg::Str(s) => s.parse::<i64>().ok(),
                                _ => None,
                            };
                            if let Some(n) = n {
                                self.set_max_lines(n)?;
                            }
                        }
                        "datepattern" => {
                            if let Arg::Str(text) = v {
                                self.set_date_pattern(text)?;
                            }
                        }
                        _ => {}
                    }
                }
            }
        } else {
            self.print(&format!(
                "Use {:>11} line : {}",
                regex_name,
                shortstr(value, 53)
            ));
            regex_stats.push(RegexStat::new(value.to_owned()));
            if regextype == "fail" {
                self.filter
                    .add_fail_regex(value)
                    .map_err(|e| e.to_string())?;
            } else {
                self.filter
                    .add_ignore_regex(value)
                    .map_err(|e| e.to_string())?;
            }
        }

        if regextype == "fail" {
            self.failregex = regex_stats;
        } else {
            self.ignoreregex = regex_stats;
        }

        Ok(true)
    }

    pub fn process(&mut self, test_lines: &[String]) {
        let t0 = Instant::now();
        let out_fmt = self.opts.str("out");
        let invert = self.opts.flag("invert");

        for line in test_lines {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }

            let mut was_ignored = false;
            let mut matched_entries = Vec::new();

            match self.filter.process_line(line) {
                Ok(found) => {
                    for e in found {
                        if !e.fail.truthy("nofail") {
                            matched_entries.push(e);
                        } else {
                            was_ignored = true;
                        }
                    }
                }
                Err(e) => {
                    out(&format!("ERROR: {e}"));
                    continue;
                }
            }
            if let Some(ign_idx) = self.filter.last_ignored_index {
                was_ignored = true;
                if let Some(stat) = self.ignoreregex.get_mut(ign_idx) {
                    stat.inc();
                }
            }

            if let Some(fmt) = out_fmt {
                let has_match = !matched_entries.is_empty() && !was_ignored;
                if has_match && !invert {
                    self.format_output(fmt, &matched_entries);
                } else if !has_match && invert {
                    // inverted output
                    let fake = FailEntry {
                        regex_index: 0,
                        fid: None,
                        date: self.filter.last_date(),
                        fail: FailData::from_iter([
                            ("fid".to_owned(), FailVal::Str(String::new())),
                            (
                                "matches".to_owned(),
                                FailVal::Lines(vec![TupleLine::new(
                                    String::new(),
                                    String::new(),
                                    line.clone(),
                                )]),
                            ),
                        ]),
                    };
                    self.format_output(fmt, &[fake]);
                }
                continue;
            }

            // Record stats
            for (i, e) in matched_entries.iter().enumerate() {
                let multiple = i > 0;
                let stat = &mut self.failregex[e.regex_index];
                stat.inc();
                let fid_str = e
                    .fid
                    .as_ref()
                    .map_or_else(String::new, |f| f.ntoa().to_string());
                let time_str = e.date.map_or_else(String::new, |t| {
                    let fields = self.local_zone.local_fields(t);
                    const WNAMES: &[&str] = &["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
                    const MNAMES: &[&str] = &[
                        "", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
                        "Nov", "Dec",
                    ];
                    let wname = WNAMES
                        .get(fields.weekday as usize)
                        .copied()
                        .unwrap_or("???");
                    let mname = MNAMES.get(fields.month as usize).copied().unwrap_or("???");
                    format!(
                        "{wname} {mname} {:02} {:02}:{:02}:{:02} {}",
                        fields.day, fields.hour, fields.minute, fields.second, fields.year
                    )
                });
                stat.append_ip(fid_str, time_str, e.date.unwrap_or(0.0), multiple);
            }

            if self.filter.pref_regex().is_some() && self.filter.pref_last_match().is_some() {
                self.pref_re_matched += 1;
                if self.opts.int("verbose").unwrap_or(0) > 0 {
                    if self.pref_re_groups.len() < self.maxlines {
                        let g = self.filter.pref_last_match().unwrap();
                        self.pref_re_groups.push(fail_data_repr(g, &[]));
                    } else if self.pref_re_groups.len() == self.maxlines {
                        self.pref_re_groups.push("...".to_owned());
                    }
                }
            }

            if was_ignored {
                self.line_stats.ignored += 1;
                if !self.opts.flag("print_no_ignored")
                    && (self.opts.flag("print_all_ignored")
                        || self.line_stats.ignored <= self.maxlines + 1)
                {
                    self.line_stats.ignored_lines.push(line.clone());
                }
            } else if !matched_entries.is_empty() {
                self.line_stats.matched += 1;
                if self.opts.flag("print_all_matched") {
                    self.line_stats.matched_lines.push(line.clone());
                }
            } else {
                self.line_stats.missed += 1;
                if !self.opts.flag("print_no_missed")
                    && (self.opts.flag("print_all_missed")
                        || self.line_stats.missed <= self.maxlines + 1)
                {
                    self.line_stats.missed_lines.push(line.clone());
                }
            }
            self.line_stats.tested += 1;
        }

        self.time_elapsed = Some(t0.elapsed().as_secs_f64());
    }

    fn format_output(&self, fmt: &str, entries: &[FailEntry]) {
        match fmt {
            "id" | "fid" => {
                for e in entries {
                    if let Some(fid) = &e.fid {
                        out(&fid.ntoa());
                    } else if let Some(fid) = e.fail.get_str("fid") {
                        out(fid);
                    }
                }
            }
            "ip" => {
                for e in entries {
                    if let Some(FailVal::Ip(ip)) = e.fail.get("ip") {
                        out(&ip.ntoa());
                    } else if let Some(fid) = &e.fid {
                        out(&fid.ntoa());
                    } else if let Some(fid) = e.fail.get_str("fid") {
                        out(fid);
                    }
                }
            }
            "msg" => {
                for e in entries {
                    if let Some(FailVal::Lines(lines)) = e.fail.get("matches") {
                        for l in lines {
                            out(&format!("{}{}{}", l.pre, l.date, l.post));
                        }
                    }
                }
            }
            "row" => {
                for e in entries {
                    let fid_str = e
                        .fid
                        .as_ref()
                        .map_or_else(|| "None".to_owned(), |f| repr(&f.ntoa()));
                    let date_str = e.date.map_or_else(|| "None".to_owned(), float_repr);
                    let dict_str = fail_data_repr(&e.fail, &["matches"]);
                    out(&format!("[{fid_str},\t{date_str},\t{dict_str}],"));
                }
            }
            other => {
                for e in entries {
                    if let Some(v) = e.fail.get(other) {
                        out(&fail_val_str(v));
                    }
                }
            }
        }
    }

    pub fn print_stats(&self) {
        if self.output_suppressed() {
            return;
        }
        out("");
        out("Results");
        out("=======");

        let verbose = self.opts.int("verbose").unwrap_or(0);

        // Print prefregex
        if let Some(pre) = self.filter.pref_regex() {
            let mut out_rows = vec![pre.regex().to_owned()];
            if verbose > 0 {
                out_rows.extend(self.pref_re_groups.iter().cloned());
            }
            out(&format!("\nPrefregex: {} total", self.pref_re_matched));
            pprint_list(&out_rows, None);
        }

        // Failregex table
        let mut fail_total = 0;
        let mut fail_rows = Vec::new();
        for (i, fr) in self.failregex.iter().enumerate() {
            fail_total += fr.hits;
            if fr.hits > 0 || verbose > 0 {
                fail_rows.push(format!("{:2}) [{}] {}", i + 1, fr.hits, fr.pattern));
            }
            if verbose > 0 && !fr.ip_list.is_empty() {
                for (ip, tstr, _, mult) in &fr.ip_list {
                    let mult_str = if *mult {
                        " (multiple regex matched)"
                    } else {
                        ""
                    };
                    fail_rows.push(format!("    {ip}  {tstr}{mult_str}"));
                }
            }
        }
        out(&format!("\nFailregex: {fail_total} total"));
        pprint_list(&fail_rows, Some(" #) [# of hits] regular expression"));

        // Ignoreregex table
        let mut ign_total = 0;
        let mut ign_rows = Vec::new();
        for (i, ir) in self.ignoreregex.iter().enumerate() {
            ign_total += ir.hits;
            if ir.hits > 0 || verbose > 0 {
                ign_rows.push(format!("{:2}) [{}] {}", i + 1, ir.hits, ir.pattern));
            }
        }
        out(&format!("\nIgnoreregex: {ign_total} total"));
        pprint_list(&ign_rows, Some(" #) [# of hits] regular expression"));

        // Date template hits
        if let Some(dd) = self.filter.date_detector() {
            out("\nDate template hits:");
            let mut date_rows = Vec::new();
            let verbose_date = self.opts.flag("verbose_date");
            for tmpl in dd.templates() {
                if verbose > 0 || tmpl.hits > 0 {
                    date_rows.push(format!("[{}] {}", tmpl.hits, tmpl.name));
                    if verbose_date {
                        date_rows.push(format!(
                            "    # weight: {:.3} ({:.3}), pattern: {}",
                            tmpl.template_weight,
                            tmpl.template_weight,
                            tmpl.pattern.unwrap_or("")
                        ));
                        date_rows.push(format!("    # regex:   {}", tmpl.regex));
                    }
                }
            }
            pprint_list(&date_rows, Some("[# of hits] date format"));
        }

        let ls = &self.line_stats;
        out(&format!(
            "\nLines: {} lines, {} ignored, {} matched, {} missed",
            ls.tested, ls.ignored, ls.matched, ls.missed
        ));
        if let Some(sec) = self.time_elapsed {
            out(&format!("[processed in {:.2} sec]", sec));
        }
        out("");

        if self.opts.flag("print_all_matched") {
            self.print_lines("matched");
        }
        if !self.opts.flag("print_no_ignored") {
            self.print_lines("ignored");
        }
        if !self.opts.flag("print_no_missed") {
            self.print_lines("missed");
        }
    }

    fn print_lines(&self, ltype: &str) {
        let (lines, total_count) = match ltype {
            "matched" => (&self.line_stats.matched_lines, self.line_stats.matched),
            "ignored" => (&self.line_stats.ignored_lines, self.line_stats.ignored),
            _ => (&self.line_stats.missed_lines, self.line_stats.missed),
        };
        if total_count == 0 {
            return;
        }
        let header = format!("{} line(s):", capitalize(ltype));
        let flag_all = match ltype {
            "matched" => self.opts.flag("print_all_matched"),
            "ignored" => self.opts.flag("print_all_ignored"),
            _ => self.opts.flag("print_all_missed"),
        };
        if total_count < self.maxlines || flag_all {
            pprint_list(lines, Some(&header));
        } else {
            out(&format!(
                "{} too many to print.  Use --print-all-{} to print all {} lines",
                header, ltype, total_count
            ));
        }
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}
