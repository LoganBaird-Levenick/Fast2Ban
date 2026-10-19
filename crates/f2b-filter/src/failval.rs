//! The failure data dictionary (`fail` in upstream's `findFailure`).
//!
//! Upstream keeps a plain Python dict whose keys come from the regex groups
//! (`<F-USER>` => `user`, custom tags, ...) plus internal bookkeeping keys
//! (`matches`, `users`, `nofail`, `mlfpending`, ...). Order and truthiness of
//! values are observable, so the same shape is kept.

use f2b_regex::{GroupValue, TupleLine};
use f2b_types::IPAddr;
use indexmap::IndexMap;

/// A value in the failure dictionary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FailVal {
    /// Python `None` (a group that did not participate in the match).
    None,
    Str(String),
    /// `<F-TUPLE_x>` combination.
    Tuple(Vec<Option<String>>),
    Int(i64),
    /// `matches`, `nofail-matches`: the matched log lines.
    Lines(Vec<TupleLine<String>>),
    /// `users`: set of seen users (insertion ordered, unique).
    Set(Vec<GroupValue<String>>),
    /// `ip`: the address when the failure id is a complex id.
    Ip(IPAddr),
}

impl FailVal {
    /// Python truthiness.
    pub fn truthy(&self) -> bool {
        match self {
            Self::None => false,
            Self::Str(s) => !s.is_empty(),
            Self::Tuple(t) => !t.is_empty(),
            Self::Int(i) => *i != 0,
            Self::Lines(l) => !l.is_empty(),
            Self::Set(s) => !s.is_empty(),
            Self::Ip(_) => true,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }
}

impl From<GroupValue<String>> for FailVal {
    fn from(v: GroupValue<String>) -> Self {
        match v {
            GroupValue::None => Self::None,
            GroupValue::Str(s) => Self::Str(s),
            GroupValue::Tuple(t) => Self::Tuple(t),
        }
    }
}

/// Insertion-ordered failure dictionary.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FailData(IndexMap<String, FailVal>);

impl FailData {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, key: &str) -> Option<&FailVal> {
        self.0.get(key)
    }

    /// `dict.get(key)` truthiness (missing counts as false).
    pub fn truthy(&self, key: &str) -> bool {
        self.0.get(key).is_some_and(FailVal::truthy)
    }

    pub fn get_mut(&mut self, key: &str) -> Option<&mut FailVal> {
        self.0.get_mut(key)
    }

    /// The string value of `key`, if it is a string.
    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(FailVal::as_str)
    }

    /// `dict[key] = value` (an existing key keeps its position).
    pub fn insert(&mut self, key: impl Into<String>, value: FailVal) {
        self.0.insert(key.into(), value);
    }

    /// `dict.pop(key, None)`.
    pub fn pop(&mut self, key: &str) -> Option<FailVal> {
        self.0.shift_remove(key)
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.0.contains_key(key)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &FailVal)> {
        self.0.iter()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// `dict.update((k, v) for k, v in other.items() if v is not None)`.
    pub fn update_non_none(&mut self, other: FailData) {
        for (k, v) in other.0 {
            if !v.is_none() {
                self.0.insert(k, v);
            }
        }
    }
}

impl FromIterator<(String, FailVal)> for FailData {
    fn from_iter<T: IntoIterator<Item = (String, FailVal)>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl IntoIterator for FailData {
    type Item = (String, FailVal);
    type IntoIter = indexmap::map::IntoIter<String, FailVal>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
