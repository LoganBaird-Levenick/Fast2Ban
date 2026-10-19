//! `journalmatch` model: upstream `FilterSystemd.addJournalMatch/delJournalMatch/
//! getJournalMatch` as a list of OR-ed groups of journalctl-syntax matches.

use std::fmt;

use f2b_helpers::pychar::repr_str;

/// Error of a match operation; `Display` equals the message of the `ValueError` upstream raises.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchError {
    /// `sd_journal_add_match` rejected a match (python-systemd: `ValueError("Invalid match")`).
    Invalid,
    /// `delJournalMatch(group)`: no identical group is registered
    /// (`ValueError("Match %r not found")`); carries the Python `repr` of the group.
    NotFound(String),
}

impl fmt::Display for MatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid => f.write_str("Invalid match"),
            Self::NotFound(repr) => write!(f, "Match {repr} not found"),
        }
    }
}

impl std::error::Error for MatchError {}

/// libsystemd's `match_is_valid()` (used by `sd_journal_add_match`): at least two characters,
/// not starting with `__`, a non-empty field name of `[A-Z0-9_]` terminated by `=`.
pub fn is_valid_match(m: &str) -> bool {
    let b = m.as_bytes();
    if b.len() < 2 || (b[0] == b'_' && b[1] == b'_') {
        return false;
    }
    for (i, &c) in b.iter().enumerate() {
        match c {
            b'=' => return i > 0,
            b'A'..=b'Z' | b'0'..=b'9' | b'_' => {}
            _ => return false,
        }
    }
    false
}

/// `" ".join(match)`: how upstream prints a match in its log messages and status.
pub fn join_match<S: AsRef<str>>(m: &[S]) -> String {
    m.iter().map(AsRef::as_ref).collect::<Vec<_>>().join(" ")
}

/// Python `repr()` of a list of strings.
fn repr_list<S: AsRef<str>>(m: &[S]) -> String {
    let items: Vec<String> = m.iter().map(|s| repr_str(s.as_ref())).collect();
    format!("[{}]", items.join(", "))
}

/// The journal matches of a filter: groups OR-ed together; inside a group, matches on the same
/// field are OR-ed and different fields AND-ed (libsystemd semantics).
///
/// Groups are kept exactly as upstream keeps them, including empty ones (`["+", "A=b"]` is
/// `[[], ["A=b"]]`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JournalMatches {
    groups: Vec<Vec<String>>,
}

impl JournalMatches {
    /// No matches.
    pub fn new() -> Self {
        Self::default()
    }

    /// `addJournalMatch(match)`: `match` is a flat journalctl-style list where `+` separates
    /// groups. If any element is invalid nothing is added (upstream flushes and restores the
    /// reader) and [`MatchError::Invalid`] is returned.
    pub fn add<S: AsRef<str>>(&mut self, m: &[S]) -> Result<(), MatchError> {
        let mut new_groups: Vec<Vec<String>> = vec![Vec::new()];
        for element in m {
            let element = element.as_ref();
            if element == "+" {
                new_groups.push(Vec::new());
            } else {
                if !is_valid_match(element) {
                    return Err(MatchError::Invalid);
                }
                new_groups
                    .last_mut()
                    .expect("never empty")
                    .push(element.to_owned());
            }
        }
        self.groups.extend(new_groups);
        Ok(())
    }

    /// `delJournalMatch(match)`: `None` clears everything; `Some(group)` removes the first
    /// identical group or fails with [`MatchError::NotFound`].
    pub fn del<S: AsRef<str>>(&mut self, m: Option<&[S]>) -> Result<(), MatchError> {
        match m {
            None => {
                self.groups.clear();
                Ok(())
            }
            Some(group) => {
                let pos = self.groups.iter().position(|g| {
                    g.len() == group.len() && g.iter().zip(group).all(|(a, b)| a == b.as_ref())
                });
                match pos {
                    Some(i) => {
                        self.groups.remove(i);
                        Ok(())
                    }
                    None => Err(MatchError::NotFound(repr_list(group))),
                }
            }
        }
    }

    /// `getJournalMatch()`.
    pub fn get(&self) -> &[Vec<String>] {
        &self.groups
    }

    /// `true` if no group is registered (upstream: `not self.getJournalMatch()`).
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// Upstream's `status()` text: `" + ".join(" ".join(match) for match in matches)`.
    pub fn status_text(&self) -> String {
        self.groups
            .iter()
            .map(|g| join_match(g))
            .collect::<Vec<_>>()
            .join(" + ")
    }

    /// The journalctl match arguments equivalent to the reader state upstream builds with
    /// `add_match`/`add_disjunction`: non-empty groups joined by `+` (libsystemd ignores empty
    /// groups, but `journalctl` rejects a leading, trailing or doubled `+`).
    ///
    /// Values containing a NUL byte cannot be passed as an argument; spawning fails for them.
    pub fn to_journalctl_args(&self) -> Vec<String> {
        let mut out = Vec::new();
        for group in self.groups.iter().filter(|g| !g.is_empty()) {
            if !out.is_empty() {
                out.push("+".to_owned());
            }
            out.extend(group.iter().cloned());
        }
        out
    }
}
