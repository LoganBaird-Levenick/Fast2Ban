//! Ban-time increment (`Jail.setBanTimeExtra` + `BanTimeIncr`/`calcBanTime`).

use crate::error::ExprError;
use crate::expr::{Env, Expr, Scope, Value, parse};
use crate::mytime::{py_isspace, str2seconds};
use crate::num::Num;
use std::cmp::Ordering;

/// Upstream default of `bantime.formula`.
pub const DEFAULT_FORMULA: &str = "ban.Time * (1<<(ban.Count if ban.Count<20 else 20)) * banFactor";

/// Jail options `bantime.factor|formula|multipliers|maxtime|rndtime`, exactly
/// as strings from the configuration. `None` and `Some("")` both mean "not
/// set" (upstream deletes the option when given an empty value).
#[derive(Clone, Copy, Debug, Default)]
pub struct BanTimeOptions<'a> {
    /// Evaluated like Python `eval`; default `"1"`.
    pub factor: Option<&'a str>,
    /// Default [`DEFAULT_FORMULA`]; ignored when `multipliers` is set.
    pub formula: Option<&'a str>,
    /// Space-separated integers (single spaces only, as upstream splits on `' '`).
    pub multipliers: Option<&'a str>,
    /// Passed through [`str2seconds`].
    pub maxtime: Option<&'a str>,
    /// Passed through [`str2seconds`].
    pub rndtime: Option<&'a str>,
}

#[derive(Clone, Debug)]
enum Kind {
    Multipliers(Vec<i64>),
    Formula(Expr),
}

/// Compiled equivalent of upstream's `be['evformula']` lambda.
#[derive(Clone, Debug)]
pub struct BanTimeIncrement {
    factor: Value,
    kind: Kind,
    maxtime: Option<Num>,
    rndtime: Option<Num>,
}

/// Python `int(str)` restricted to ASCII digits.
fn py_int(s: &str) -> Result<i64, ExprError> {
    let t = s.trim_matches(py_isspace);
    let (neg, body) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let b = body.as_bytes();
    let well_formed = b.first().is_some_and(u8::is_ascii_digit)
        && b.last().is_some_and(u8::is_ascii_digit)
        && b.iter().all(|c| c.is_ascii_digit() || *c == b'_')
        && !body.contains("__");
    if !well_formed {
        return Err(ExprError::Value("invalid literal for int()"));
    }
    let digits: String = body.chars().filter(|c| *c != '_').collect();
    let v: i128 = digits
        .parse()
        .map_err(|_| ExprError::Overflow("multiplier does not fit in 64 bits"))?;
    i64::try_from(if neg { -v } else { v })
        .map_err(|_| ExprError::Overflow("multiplier does not fit in 64 bits"))
}

fn set(o: Option<&str>) -> Option<&str> {
    o.filter(|s| !s.is_empty())
}

impl BanTimeIncrement {
    /// Build from option strings, doing at construction what upstream does
    /// when the options are set (`eval(factor)`, `int()` of each multiplier,
    /// `compile(formula)`, `str2seconds`), plus resolving names.
    ///
    /// # Errors
    /// Any of those steps failing, or the formula using anything outside the
    /// grammar in the crate docs (including unknown names and bad arities,
    /// which Python would only raise when the formula is first evaluated).
    pub fn new(opts: &BanTimeOptions<'_>) -> Result<Self, ExprError> {
        let factor =
            parse(set(opts.factor).unwrap_or("1"), Scope::Calls, true)?.eval(&Env::EMPTY)?;
        let kind = if let Some(m) = set(opts.multipliers) {
            Kind::Multipliers(m.split(' ').map(py_int).collect::<Result<_, _>>()?)
        } else {
            Kind::Formula(parse(
                set(opts.formula).unwrap_or(DEFAULT_FORMULA),
                Scope::Formula,
                false,
            )?)
        };
        Ok(Self {
            factor,
            kind,
            maxtime: set(opts.maxtime).map(str2seconds).transpose()?,
            rndtime: set(opts.rndtime).map(str2seconds).transpose()?,
        })
    }

    /// `be['evformula'](BanTimeIncr(ban_time, ban_count))`.
    ///
    /// `rand` stands for `random.random()`; it is called at most once, and only
    /// if `rndtime` is set, after the rest of the formula was evaluated.
    ///
    /// Boolean results of the formula are returned as `Int` 0/1.
    ///
    /// # Errors
    /// Wherever Python would raise during evaluation (zero division, negative
    /// shift, `math` domain errors, multiplier index out of range for a
    /// negative count, ...) or integer overflow beyond `i64`.
    pub fn calc(
        &self,
        ban_time: Num,
        ban_count: i64,
        rand: impl FnOnce() -> f64,
    ) -> Result<Num, ExprError> {
        let mut v = match &self.kind {
            Kind::Multipliers(m) => {
                let len = i64::try_from(m.len()).unwrap_or(i64::MAX);
                let idx = if ban_count < len { ban_count } else { -1 };
                let idx = if idx < 0 { idx + len } else { idx };
                let mult = usize::try_from(idx)
                    .ok()
                    .and_then(|i| m.get(i))
                    .ok_or(ExprError::Value("multiplier index out of range"))?;
                ban_time.mul(self.factor.num())?.mul(Num::Int(*mult))?
            }
            Kind::Formula(e) => {
                let env = Env {
                    ban_time: Value::from_num(ban_time),
                    ban_count,
                    ban_factor: self.factor,
                };
                let f = e.eval(&env)?.num();
                // max(ban.Time, f): keeps ban.Time unless f is strictly greater
                if f.py_cmp(ban_time) == Some(Ordering::Greater) {
                    f
                } else {
                    ban_time
                }
            }
        };
        if let Some(max) = self.maxtime {
            if max.py_cmp(v) == Some(Ordering::Less) {
                v = max;
            }
        }
        if let Some(rnd) = self.rndtime {
            v = v.add(Num::Float(rand()).mul(rnd)?)?;
        }
        Ok(v)
    }
}
