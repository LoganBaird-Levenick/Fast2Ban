//! The `systemd` backend of a jail (`FilterSystemd`): journal matches, the
//! reader process and the conversion of entries into filter lines.

use std::io;

use indexmap::IndexMap;

use f2b_date::LocalZone;

use crate::journal::{
    FormattedEntry, JournalMatches, JournalOptions, JournalReader, MatchError, TimestampStyle,
    format_journal_entry_with,
};

/// At most this many entries are handled per [`JournalBackend::poll`]
/// (upstream breaks its read loop after 100 entries to service the jail).
pub const MAX_ENTRIES_PER_POLL: usize = 100;

/// Seconds the process zone was away from UTC at `t` (what python-systemd 235
/// freezes at import time).
fn utc_offset_secs(zone: &LocalZone, t: f64) -> i32 {
    let f = zone.local_fields(t);
    // days since 1970-01-01 of the civil date (Hinnant's days_from_civil)
    let y = if f.month <= 2 { f.year - 1 } else { f.year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (f.month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + f.day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let local = days * 86_400 + f.hour * 3_600 + f.minute * 60 + f.second;
    i32::try_from(local - t.floor() as i64).unwrap_or(0)
}

/// State of a jail with `backend = systemd`.
#[derive(Debug)]
pub struct JournalBackend {
    options: JournalOptions,
    matches: JournalMatches,
    reader: Option<JournalReader>,
    encoding: String,
    /// UTC offset python-systemd would have captured when the daemon started.
    utc_offset: i32,
    /// Time of the most recent entry handed out (epoch seconds, `time`
    /// of [`FormattedEntry`]) and its ISO text, for the database position.
    last: Option<(f64, String)>,
}

impl JournalBackend {
    /// Build from the options of `backend = systemd[journalpath=..., ...]`.
    ///
    /// # Errors
    /// An unknown option name or a malformed value.
    pub fn from_backend_options(opts: &IndexMap<String, String>) -> Result<Self, String> {
        let mut options = JournalOptions::default();
        for (key, value) in opts {
            match key.as_str() {
                "journalpath" => options.journalpath = Some(value.clone()),
                "journalfiles" => options.set_journalfiles(value),
                "journalflags" => {
                    options.journalflags =
                        Some(crate::journal::parse_flags(value).map_err(|e| e.to_string())?);
                }
                "namespace" => options.namespace = Some(value.clone()),
                "rotated" => options.rotated = f2b_helpers::as_bool(value),
                other => return Err(format!("Unknown systemd backend option {other:?}")),
            }
        }
        // fail early on option combinations journalctl cannot express
        options.resolve().map_err(|e| e.to_string())?;
        Ok(Self::new(options))
    }

    pub fn new(options: JournalOptions) -> Self {
        let zone = LocalZone::system();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0.0, |d| d.as_secs_f64());
        Self {
            options,
            matches: JournalMatches::default(),
            reader: None,
            encoding: "utf-8".to_owned(),
            utc_offset: utc_offset_secs(&zone, now),
            last: None,
        }
    }

    pub fn options(&self) -> &JournalOptions {
        &self.options
    }

    pub fn matches(&self) -> &JournalMatches {
        &self.matches
    }

    pub fn set_encoding(&mut self, encoding: &str) {
        encoding.clone_into(&mut self.encoding);
    }

    pub fn is_running(&self) -> bool {
        self.reader.is_some()
    }

    /// `addJournalMatch`. A running reader is restarted behind the last
    /// entry it delivered.
    ///
    /// # Errors
    /// An invalid match (the matches stay unchanged).
    pub fn add_match<S: AsRef<str>>(&mut self, m: &[S]) -> Result<(), MatchError> {
        self.matches.add(m)?;
        self.restart_after_change();
        Ok(())
    }

    /// `delJournalMatch`.
    ///
    /// # Errors
    /// `Match ... not found`.
    pub fn del_match<S: AsRef<str>>(&mut self, m: Option<&[S]>) -> Result<(), MatchError> {
        self.matches.del(m)?;
        self.restart_after_change();
        Ok(())
    }

    fn restart_after_change(&mut self) {
        if self.reader.is_some() {
            let since = self.last.as_ref().map(|(t, _)| *t + 1e-6);
            self.reader = None;
            if let Err(e) = self.spawn(since) {
                log::error!("Unable to restart the journal reader: {e}");
            }
        }
    }

    fn spawn(&mut self, since: Option<f64>) -> io::Result<()> {
        self.reader = Some(JournalReader::spawn(
            &self.options,
            &self.matches,
            since,
            true,
        )?);
        Ok(())
    }

    /// Start reading: entries from `since` (epoch seconds) on, then follow.
    ///
    /// # Errors
    /// The reader process cannot be started.
    pub fn start(&mut self, since: f64) -> io::Result<()> {
        self.last = None;
        self.spawn(Some(since))
    }

    pub fn stop(&mut self) {
        self.reader = None;
    }

    /// Time and ISO text of the last delivered entry (`_pendDBUpdates`).
    pub fn last_entry(&self) -> Option<(f64, &str)> {
        self.last.as_ref().map(|(t, s)| (*t, s.as_str()))
    }

    /// Every entry that matches, oldest first, then the end (a finite read
    /// of the whole journal; `fail2ban-regex systemd-journal`).
    ///
    /// # Errors
    /// The reader process cannot be started.
    pub fn entries(&self) -> io::Result<JournalEntries> {
        Ok(JournalEntries {
            reader: JournalReader::spawn(&self.options, &self.matches, None, false)?,
            encoding: self.encoding.clone(),
            utc_offset: self.utc_offset,
        })
    }

    /// Hand every entry that is ready (up to [`MAX_ENTRIES_PER_POLL`]) to
    /// `on_entry` as a filter line. Entries that cannot be formatted are
    /// skipped with an error message, like upstream's main loop does. A dead
    /// reader process is restarted behind the last entry.
    pub fn poll(&mut self, mut on_entry: impl FnMut(FormattedEntry)) -> usize {
        let mut handled = 0;
        while handled < MAX_ENTRIES_PER_POLL {
            let Some(entry) = self.reader.as_mut().and_then(JournalReader::try_next) else {
                break;
            };
            handled += 1;
            match format_journal_entry_with(
                &entry,
                &self.encoding,
                TimestampStyle::FixedOffset(self.utc_offset),
            ) {
                Ok(f) => {
                    self.last = Some((f.time, f.date.trim_end().to_owned()));
                    on_entry(f);
                }
                Err(e) => log::error!("Caught unhandled exception in main cycle: {e}"),
            }
        }
        if handled == 0 {
            self.revive_dead_reader();
        }
        handled
    }

    /// `_reopenJournal` when the reader is offline: start it again behind the
    /// last entry.
    fn revive_dead_reader(&mut self) {
        let Some(reader) = self.reader.as_mut() else {
            return;
        };
        if reader.is_alive() {
            return;
        }
        let tail = reader.stderr_tail().join("; ");
        log::error!("The journal reader exited unexpectedly ({tail}), restarting it");
        let since = self.last.as_ref().map(|(t, _)| *t + 1e-6);
        self.reader = None;
        if let Err(e) = self.spawn(since.or(Some(0.0))) {
            log::error!("Unable to restart the journal reader: {e}");
        }
    }
}

/// Finite iterator over formatted journal entries ([`JournalBackend::entries`]).
#[derive(Debug)]
pub struct JournalEntries {
    reader: JournalReader,
    encoding: String,
    utc_offset: i32,
}

impl Iterator for JournalEntries {
    type Item = FormattedEntry;

    fn next(&mut self) -> Option<FormattedEntry> {
        loop {
            let entry = match self
                .reader
                .next_timeout(std::time::Duration::from_millis(100))
            {
                Some(e) => e,
                None if self.reader.is_alive() => continue,
                // the stream ended: take what the reader thread queued last
                None => self.reader.try_next()?,
            };
            match format_journal_entry_with(
                &entry,
                &self.encoding,
                TimestampStyle::FixedOffset(self.utc_offset),
            ) {
                Ok(f) => return Some(f),
                Err(e) => log::error!("Caught unhandled exception in main cycle: {e}"),
            }
        }
    }
}
