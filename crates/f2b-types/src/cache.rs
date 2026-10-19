//! Port of upstream `Utils.Cache` (`fail2ban/server/utils.py`): a FIFO cache
//! with a per-entry TTL and a size limit.

use indexmap::IndexMap;

use crate::clock::SharedClock;

/// Insertion-ordered cache with TTL and size bound.
///
/// Quirk kept from upstream: when the cache holds `max_count` entries, `set`
/// first evicts from the front (oldest first) until at least one *unexpired*
/// entry has been dropped and a slot is free - even when the key being set
/// already exists.
#[derive(Debug)]
pub struct TtlCache<K, V> {
    map: IndexMap<K, (V, f64)>,
    max_count: usize,
    max_time: f64,
    clock: SharedClock,
}

impl<K: std::hash::Hash + Eq, V> TtlCache<K, V> {
    pub fn new(max_count: usize, max_time: f64, clock: SharedClock) -> Self {
        Self {
            map: IndexMap::new(),
            max_count,
            max_time,
            clock,
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Value for `k` if present and not expired (expired entries are removed).
    pub fn get(&mut self, k: &K) -> Option<&V> {
        let now = self.clock.time();
        let expired = match self.map.get(k) {
            Some((_, until)) => *until <= now,
            None => return None,
        };
        if expired {
            self.map.shift_remove(k);
            return None;
        }
        self.map.get(k).map(|(v, _)| v)
    }

    /// Like [`TtlCache::get`] but mutable (expiry applies; the TTL is not refreshed).
    pub fn get_mut(&mut self, k: &K) -> Option<&mut V> {
        let now = self.clock.time();
        let expired = match self.map.get(k) {
            Some((_, until)) => *until <= now,
            None => return None,
        };
        if expired {
            self.map.shift_remove(k);
            return None;
        }
        self.map.get_mut(k).map(|(v, _)| v)
    }

    pub fn set(&mut self, k: K, v: V) {
        let t = self.clock.time();
        if self.map.len() >= self.max_count {
            while let Some((_, (_, until))) = self.map.shift_remove_index(0) {
                if until > t && self.map.len() < self.max_count {
                    break;
                }
            }
        }
        self.map.insert(k, (v, t + self.max_time));
    }

    pub fn unset(&mut self, k: &K) {
        self.map.shift_remove(k);
    }

    pub fn clear(&mut self) {
        self.map.clear();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::clock::FixedClock;

    #[test]
    fn entries_expire_and_oldest_are_evicted_first() {
        let clock = Arc::new(FixedClock::new(100.0));
        let mut c = TtlCache::new(2, 10.0, clock.clone());
        c.set("a", 1);
        c.set("b", 2);
        c.set("c", 3); // full: evicts oldest unexpired ("a")
        assert_eq!(c.get(&"a"), None);
        assert_eq!(c.get(&"b"), Some(&2));
        clock.set(111.0);
        assert_eq!(c.get(&"b"), None, "expired");
        assert_eq!(c.len(), 1);
    }
}
