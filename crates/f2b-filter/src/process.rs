//! `Filter.processLine`: split the date off a log line, apply the find-time
//! sanity rules and hand over to `find_failure`.

use f2b_regex::TupleLine;

use crate::error::{FilterError, Result};
use crate::filter::{FailEntry, Filter};

impl Filter {
    /// `processLine(line)`: detects the date with the filter's date detector.
    pub fn process_line(&mut self, line: &str) -> Result<Vec<FailEntry>> {
        self.process_inner(line, None)
    }

    /// `processLine((pre, datetext, post), date)`: the date is already known
    /// (journal backends). A zero `date` counts as unknown, like Python's
    /// `if date:`.
    pub fn process_line_with_date(
        &mut self,
        line: TupleLine<String>,
        date: f64,
    ) -> Result<Vec<FailEntry>> {
        let full = format!("{}{}{}", line.pre, line.date, line.post);
        if date != 0.0 {
            self.last_time_text.clone_from(&line.date);
            self.last_date = Some(date);
            return self.after_date(&full, line, Some(date), false);
        }
        self.process_inner(&full, None)
    }

    fn recent_last_date(&self, now: f64) -> Option<f64> {
        self.last_date.filter(|d| *d != 0.0 && *d > now - 60.0)
    }

    fn process_inner(&mut self, line: &str, _unused: Option<()>) -> Result<Vec<FailEntry>> {
        let now = self.clock.time();
        let mut date: Option<f64> = None;
        let mut tuple: TupleLine<String>;
        let Some(dd) = self.date_detector.as_mut() else {
            return Err(FilterError::NoDateDetector);
        };
        let tm = dd.match_time(line);
        if tm.is_match() {
            let (s, e) = tm.span().unwrap_or((0, 0));
            let text = &line[s..e];
            tuple = TupleLine::new(line[..s].to_owned(), text.to_owned(), line[e..].to_owned());
            if !text.is_empty() {
                // found and not empty - retrieve date
                match dd.get_time(text, &tm) {
                    Some(d) => {
                        date = Some(d);
                        self.last_time_text = text.to_owned();
                        self.last_date = Some(d);
                    }
                    None => log::error!("findFailure failed to parse timeText: {text}"),
                }
            } else if let Some(last) = self.recent_last_date(now) {
                // matched empty value - date is optional or not available: use last known
                tuple = TupleLine::new(String::new(), self.last_time_text.clone(), line.to_owned());
                date = Some(last);
            } else {
                // set it to now
                date = Some(now);
            }
        } else {
            tuple = TupleLine::new(String::new(), String::new(), line.to_owned());
        }
        // still no date - try to use last known
        let mut no_date = false;
        if date.is_none() {
            no_date = true;
            if let Some(last) = self.recent_last_date(now) {
                tuple = TupleLine::new(String::new(), self.last_time_text.clone(), line.to_owned());
                date = Some(last);
            } else if self.check_find_time && self.in_operation {
                date = Some(now);
            }
        }
        self.after_date(line, tuple, date, no_date)
    }

    /// The find-time checks of `processLine` and the `findFailure` call.
    fn after_date(
        &mut self,
        line: &str,
        tuple: TupleLine<String>,
        mut date: Option<f64>,
        no_date: bool,
    ) -> Result<Vec<FailEntry>> {
        if self.check_find_time {
            if let Some(d) = date {
                let now = self.clock.time();
                if self.in_operation {
                    // weird date - simulate now for timing issue (too large deviation from now)
                    let delta = (d - now) as i64;
                    if delta.abs() > 60 {
                        let kind = if (-3300..0).contains(&delta) {
                            "latency"
                        } else {
                            "timezone"
                        };
                        self.warn_once(
                            "simByTime",
                            &[
                                format!(
                                    "Detected a log entry {}s {} the current time in operation mode. \
                                     This looks like a {kind} problem. Treating such entries as if they just happened.",
                                    delta.abs(),
                                    if delta < 0 { "before" } else { "after" },
                                ),
                                format!("Please check a jail for a timing issue. Line with odd timestamp: {line}"),
                            ],
                        );
                        date = Some(now);
                        self.last_date = date;
                    }
                } else if d < now - self.find_time() {
                    // in initialization (restore) phase, if too old - ignore
                    self.warn_once(
                        "ignByTime",
                        &[
                            format!(
                                "Ignoring all log entries older than {}s; these are probably messages generated while fail2ban was not running.",
                                self.find_time()
                            ),
                            format!("Please check a jail for a timing issue. Line with odd timestamp: {line}"),
                        ],
                    );
                    return Ok(Vec::new());
                }
            }
        }
        self.find_failure(tuple, date, no_date)
    }
}
