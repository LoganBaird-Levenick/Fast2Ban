//! Configuration and evaluation for `bantime.increment` and related extra options.

use f2b_expr::{BanTimeIncrement, BanTimeOptions, Num, str2seconds};
use std::sync::atomic::{AtomicU64, Ordering};

pub fn rand_float() -> f64 {
    static SEED: AtomicU64 = AtomicU64::new(0x853c49e6748fea9b);
    let mut x = SEED.load(Ordering::Relaxed);
    if x == 0 {
        x = 0x853c49e6748fea9b;
    }
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    SEED.store(x, Ordering::Relaxed);
    (x as f64) / (u64::MAX as f64)
}

/// Dynamic options governing ban time increment formulas and multipliers.
#[derive(Clone, Debug, Default)]
pub struct BanExtra {
    pub increment: bool,
    pub factor: Option<String>,
    pub formula: Option<String>,
    pub multipliers: Option<String>,
    pub maxtime: Option<i64>,
    pub maxtime_raw: Option<String>,
    pub rndtime: Option<i64>,
    pub rndtime_raw: Option<String>,
    pub overalljails: bool,
    pub compiled_formula: Option<BanTimeIncrement>,
}

impl BanExtra {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_opt(&mut self, opt: &str, val: Option<&str>) -> Result<(), String> {
        let val = val.filter(|s| !s.is_empty());
        match opt {
            "increment" => {
                self.increment = val
                    .map(|v| {
                        v.eq_ignore_ascii_case("true") || v == "1" || v.eq_ignore_ascii_case("yes")
                    })
                    .unwrap_or(false);
            }
            "overalljails" => {
                self.overalljails = val
                    .map(|v| {
                        v.eq_ignore_ascii_case("true") || v == "1" || v.eq_ignore_ascii_case("yes")
                    })
                    .unwrap_or(false);
            }
            "factor" => {
                self.factor = val.map(|v| v.to_owned());
            }
            "formula" => {
                self.formula = val.map(|v| v.to_owned());
            }
            "multipliers" => {
                self.multipliers = val.map(|v| v.to_owned());
            }
            "maxtime" => {
                self.maxtime_raw = val.map(|v| v.to_owned());
                if let Some(v) = val {
                    let num = str2seconds(v).map_err(|e| format!("Invalid maxtime: {e}"))?;
                    self.maxtime = Some(num.as_i64().unwrap_or(24 * 3600));
                } else {
                    self.maxtime = None;
                }
            }
            "rndtime" => {
                self.rndtime_raw = val.map(|v| v.to_owned());
                if let Some(v) = val {
                    let num = str2seconds(v).map_err(|e| format!("Invalid rndtime: {e}"))?;
                    self.rndtime = Some(num.as_i64().unwrap_or(0));
                } else {
                    self.rndtime = None;
                }
            }
            _ => return Err(format!("Unknown bantime option: {opt}")),
        }

        self.recompile_formula()
    }

    pub fn recompile_formula(&mut self) -> Result<(), String> {
        let opts = BanTimeOptions {
            factor: self.factor.as_deref(),
            formula: self.formula.as_deref(),
            multipliers: self.multipliers.as_deref(),
            maxtime: self.maxtime_raw.as_deref(),
            rndtime: self.rndtime_raw.as_deref(),
        };
        match BanTimeIncrement::new(&opts) {
            Ok(compiled) => {
                self.compiled_formula = Some(compiled);
                Ok(())
            }
            Err(e) => Err(format!("Failed to compile bantime formula: {e}")),
        }
    }

    pub fn get_opt(&self, opt: &str) -> Option<String> {
        match opt {
            "increment" => Some(self.increment.to_string()),
            "overalljails" => Some(self.overalljails.to_string()),
            "factor" => self.factor.clone(),
            "formula" => self.formula.clone(),
            "multipliers" => self.multipliers.clone(),
            "maxtime" => self.maxtime.map(|m| m.to_string()),
            "rndtime" => self.rndtime.map(|r| r.to_string()),
            _ => None,
        }
    }

    /// Calculate incremented ban time given base ban time and current ban count.
    pub fn calc_ban_time(
        &self,
        base_ban_time: f64,
        ban_count: i64,
        rand: impl FnOnce() -> f64,
    ) -> Result<Num, String> {
        if let Some(cf) = &self.compiled_formula {
            let num = if base_ban_time.fract() == 0.0
                && base_ban_time >= (i64::MIN as f64)
                && base_ban_time <= (i64::MAX as f64)
            {
                Num::Int(base_ban_time as i64)
            } else {
                Num::Float(base_ban_time)
            };
            cf.calc(num, ban_count, rand).map_err(|e| e.to_string())
        } else {
            Ok(Num::Float(base_ban_time))
        }
    }

    /// Returns max possible ban-time of jail.
    pub fn max_ban_time(&self, default_ban_time: i64) -> i64 {
        if self.increment {
            self.maxtime.unwrap_or(-1)
        } else {
            default_ban_time
        }
    }
}
