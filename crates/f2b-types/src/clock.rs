//! Injectable time source (upstream `MyTime.time()` / `MyTime.setTime`).
//!
//! Everything that depends on "now" (date year inference, find-time checks,
//! ban expiry) takes a [`SharedClock`], so tests and the sample harness can
//! pin time deterministically.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// A source of the current Unix time in seconds (with fraction).
pub trait Clock: fmt::Debug + Send + Sync {
    fn time(&self) -> f64;
}

/// Shared handle to a clock.
pub type SharedClock = Arc<dyn Clock>;

/// Wall clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn time(&self) -> f64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0.0, |d| d.as_secs_f64())
    }
}

/// A clock that stands still until [`FixedClock::set`] moves it.
#[derive(Debug)]
pub struct FixedClock(AtomicU64);

impl FixedClock {
    pub fn new(t: f64) -> Self {
        Self(AtomicU64::new(t.to_bits()))
    }

    pub fn set(&self, t: f64) {
        self.0.store(t.to_bits(), Ordering::Relaxed);
    }
}

impl Clock for FixedClock {
    fn time(&self) -> f64 {
        f64::from_bits(self.0.load(Ordering::Relaxed))
    }
}

/// `SharedClock` for the wall clock.
pub fn system_clock() -> SharedClock {
    Arc::new(SystemClock)
}

/// `SharedClock` frozen at `t`.
pub fn fixed_clock(t: f64) -> SharedClock {
    Arc::new(FixedClock::new(t))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_clock_moves_only_when_set() {
        let c = FixedClock::new(10.5);
        assert_eq!(c.time(), 10.5);
        c.set(20.0);
        assert_eq!(c.time(), 20.0);
    }
}
