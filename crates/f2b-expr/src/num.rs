//! Python numeric semantics on `i64` / `f64`.

use crate::error::ExprError;
use std::cmp::Ordering;
use std::fmt;

/// A Python `int` or `float` result.
///
/// Python integers are unbounded; this type is not. Every operation whose
/// exact result does not fit `i64` returns [`ExprError::Overflow`] instead of
/// widening.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Num {
    /// A Python `int`.
    Int(i64),
    /// A Python `float`.
    Float(f64),
}

impl From<i64> for Num {
    fn from(v: i64) -> Self {
        Self::Int(v)
    }
}

impl From<f64> for Num {
    fn from(v: f64) -> Self {
        Self::Float(v)
    }
}

impl Num {
    /// Python `float(n)`.
    #[must_use]
    pub fn as_f64(self) -> f64 {
        match self {
            Self::Int(i) => i as f64,
            Self::Float(f) => f,
        }
    }

    /// Python `int(n)`: truncates floats toward zero.
    ///
    /// # Errors
    /// NaN, infinities and values outside `i64` (Python would produce a
    /// bignum, `ValueError` or `OverflowError`).
    pub fn as_i64(self) -> Result<i64, ExprError> {
        match self {
            Self::Int(i) => Ok(i),
            Self::Float(f) => f64_to_i64(f.trunc()),
        }
    }

    /// Python truthiness (`bool(n)`); NaN is truthy.
    #[must_use]
    pub fn is_truthy(self) -> bool {
        match self {
            Self::Int(i) => i != 0,
            Self::Float(f) => f != 0.0,
        }
    }

    pub(crate) fn add(self, o: Self) -> Result<Self, ExprError> {
        match (self, o) {
            (Self::Int(a), Self::Int(b)) => a
                .checked_add(b)
                .map(Self::Int)
                .ok_or(ExprError::Overflow("integer addition")),
            _ => Ok(Self::Float(self.as_f64() + o.as_f64())),
        }
    }

    pub(crate) fn sub(self, o: Self) -> Result<Self, ExprError> {
        match (self, o) {
            (Self::Int(a), Self::Int(b)) => a
                .checked_sub(b)
                .map(Self::Int)
                .ok_or(ExprError::Overflow("integer subtraction")),
            _ => Ok(Self::Float(self.as_f64() - o.as_f64())),
        }
    }

    pub(crate) fn mul(self, o: Self) -> Result<Self, ExprError> {
        match (self, o) {
            (Self::Int(a), Self::Int(b)) => a
                .checked_mul(b)
                .map(Self::Int)
                .ok_or(ExprError::Overflow("integer multiplication")),
            _ => Ok(Self::Float(self.as_f64() * o.as_f64())),
        }
    }

    /// Python `/`: always a float.
    pub(crate) fn truediv(self, o: Self) -> Result<Self, ExprError> {
        match (self, o) {
            (Self::Int(a), Self::Int(b)) => int_truediv(a, b).map(Self::Float),
            _ => {
                let d = o.as_f64();
                if d == 0.0 {
                    Err(ExprError::ZeroDivision("float division by zero"))
                } else {
                    Ok(Self::Float(self.as_f64() / d))
                }
            }
        }
    }

    /// Python `//`.
    pub(crate) fn floordiv(self, o: Self) -> Result<Self, ExprError> {
        match (self, o) {
            (Self::Int(a), Self::Int(b)) => {
                if b == 0 {
                    return Err(ExprError::ZeroDivision(
                        "integer division or modulo by zero",
                    ));
                }
                let q = a
                    .checked_div(b)
                    .ok_or(ExprError::Overflow("integer floor division"))?;
                // `%` cannot overflow here: b != 0 and a / b did not.
                let r = a % b;
                Ok(Self::Int(if r != 0 && ((r < 0) != (b < 0)) {
                    q - 1
                } else {
                    q
                }))
            }
            _ => float_floordiv(self.as_f64(), o.as_f64()).map(Self::Float),
        }
    }

    /// Python `%` (result takes the sign of the divisor).
    pub(crate) fn modulo(self, o: Self) -> Result<Self, ExprError> {
        match (self, o) {
            (Self::Int(a), Self::Int(b)) => {
                if b == 0 {
                    return Err(ExprError::ZeroDivision(
                        "integer division or modulo by zero",
                    ));
                }
                if b == -1 {
                    return Ok(Self::Int(0));
                }
                let r = a % b;
                Ok(Self::Int(if r != 0 && ((r < 0) != (b < 0)) {
                    r + b
                } else {
                    r
                }))
            }
            _ => {
                let (vx, wx) = (self.as_f64(), o.as_f64());
                if wx == 0.0 {
                    return Err(ExprError::ZeroDivision("float modulo by zero"));
                }
                let mut m = vx % wx;
                if m != 0.0 {
                    if (wx < 0.0) != (m < 0.0) {
                        m += wx;
                    }
                } else {
                    m = 0.0f64.copysign(wx);
                }
                Ok(Self::Float(m))
            }
        }
    }

    /// Python `**`.
    pub(crate) fn pow(self, o: Self) -> Result<Self, ExprError> {
        match (self, o) {
            (Self::Int(a), Self::Int(b)) if b >= 0 => int_pow(a, b).map(Self::Int),
            _ => float_pow(self.as_f64(), o.as_f64()).map(Self::Float),
        }
    }

    pub(crate) fn neg(self) -> Result<Self, ExprError> {
        match self {
            Self::Int(a) => a
                .checked_neg()
                .map(Self::Int)
                .ok_or(ExprError::Overflow("integer negation")),
            Self::Float(f) => Ok(Self::Float(-f)),
        }
    }

    /// Exact Python comparison between ints and floats; `None` if unordered (NaN).
    pub(crate) fn py_cmp(self, o: Self) -> Option<Ordering> {
        match (self, o) {
            (Self::Int(a), Self::Int(b)) => Some(a.cmp(&b)),
            (Self::Float(a), Self::Float(b)) => a.partial_cmp(&b),
            (Self::Int(a), Self::Float(b)) => int_float_cmp(a, b),
            (Self::Float(a), Self::Int(b)) => int_float_cmp(b, a).map(Ordering::reverse),
        }
    }
}

impl fmt::Display for Num {
    /// Python `str()` / `repr()` of the int or float.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Int(i) => write!(f, "{i}"),
            Self::Float(x) => f.write_str(&float_repr(*x)),
        }
    }
}

const TWO_63: f64 = 9_223_372_036_854_775_808.0;

/// `f` must already be integral (or the caller wants truncation by `as`).
pub(crate) fn f64_to_i64(f: f64) -> Result<i64, ExprError> {
    if f.is_nan() {
        Err(ExprError::Value("cannot convert float NaN to integer"))
    } else if f.is_infinite() {
        Err(ExprError::Overflow(
            "cannot convert float infinity to integer",
        ))
    } else if (-TWO_63..TWO_63).contains(&f) {
        Ok(f as i64)
    } else {
        Err(ExprError::Overflow("integer does not fit in 64 bits"))
    }
}

fn int_float_cmp(i: i64, f: f64) -> Option<Ordering> {
    if f.is_nan() {
        return None;
    }
    if f >= TWO_63 {
        return Some(Ordering::Less);
    }
    if f < -TWO_63 {
        return Some(Ordering::Greater);
    }
    let t = f.trunc();
    match i.cmp(&(t as i64)) {
        Ordering::Equal => {
            let frac = f - t;
            if frac > 0.0 {
                Some(Ordering::Less)
            } else if frac < 0.0 {
                Some(Ordering::Greater)
            } else {
                Some(Ordering::Equal)
            }
        }
        o => Some(o),
    }
}

/// Correctly rounded `a / b` for `i64` operands, like CPython's long true division.
fn int_truediv(a: i64, b: i64) -> Result<f64, ExprError> {
    if b == 0 {
        return Err(ExprError::ZeroDivision("division by zero"));
    }
    const EXACT: u64 = 1 << 53;
    if a.unsigned_abs() <= EXACT && b.unsigned_abs() <= EXACT {
        return Ok(a as f64 / b as f64);
    }
    // |a| or |b| exceeds 2^53 (so a != 0): long division on u128 with a sticky
    // remainder bit, rounded once to 53 bits (ties to even).
    let neg = (a < 0) != (b < 0);
    let n = u128::from(a.unsigned_abs());
    let d = u128::from(b.unsigned_abs());
    let bn = 128 - n.leading_zeros();
    let bd = 128 - d.leading_zeros();
    // n << s has 64 + bd <= 128 bits; the quotient then has 64 or 65 bits.
    let s = 64 + bd - bn;
    let num = n << s;
    let q = num / d;
    let sticky = num % d != 0;
    let qbits = 128 - q.leading_zeros();
    let shift = qbits - 53;
    let mut m = q >> shift;
    let lower = q & ((1u128 << shift) - 1);
    let half = 1u128 << (shift - 1);
    if lower > half || (lower == half && (sticky || m & 1 == 1)) {
        m += 1;
    }
    let exp = i32::try_from(shift).unwrap_or(0) - i32::try_from(s).unwrap_or(0);
    let v = m as f64 * 2.0f64.powi(exp);
    Ok(if neg { -v } else { v })
}

fn int_pow(a: i64, b: i64) -> Result<i64, ExprError> {
    if b == 0 {
        return Ok(1);
    }
    match a {
        0 | 1 => Ok(a),
        -1 => Ok(if b % 2 == 0 { 1 } else { -1 }),
        _ => u32::try_from(b)
            .ok()
            .and_then(|e| a.checked_pow(e))
            .ok_or(ExprError::Overflow("integer exponentiation")),
    }
}

fn is_odd_integer(x: f64) -> bool {
    x.is_finite() && x == x.floor() && (x / 2.0).floor() * 2.0 != x
}

/// CPython `float_pow`; the complex-result case is unsupported.
pub(crate) fn float_pow(iv: f64, iw: f64) -> Result<f64, ExprError> {
    if iw == 0.0 {
        return Ok(1.0);
    }
    if iv.is_nan() {
        return Ok(iv);
    }
    if iw.is_nan() {
        return Ok(if iv == 1.0 { 1.0 } else { iw });
    }
    if iw.is_infinite() {
        let a = iv.abs();
        return Ok(if a == 1.0 {
            1.0
        } else if (iw > 0.0) == (a > 1.0) {
            f64::INFINITY
        } else {
            0.0
        });
    }
    if iv.is_infinite() {
        let odd = is_odd_integer(iw);
        return Ok(if iw > 0.0 {
            if odd { iv } else { iv.abs() }
        } else if odd {
            0.0f64.copysign(iv)
        } else {
            0.0
        });
    }
    let mut iv = iv;
    if iv == 0.0 {
        if iw < 0.0 {
            return Err(ExprError::ZeroDivision("zero raised to a negative power"));
        }
        return Ok(if is_odd_integer(iw) { iv } else { 0.0 });
    }
    let mut negate = false;
    if iv < 0.0 {
        if iw != iw.floor() {
            return Err(ExprError::Unsupported(
                "negative number raised to a fractional power (complex result)".into(),
            ));
        }
        negate = is_odd_integer(iw);
        iv = -iv;
    }
    if iv == 1.0 {
        return Ok(if negate { -1.0 } else { 1.0 });
    }
    let ix = iv.powf(iw);
    if ix.is_infinite() {
        return Err(ExprError::Overflow("numerical result out of range"));
    }
    Ok(if negate { -ix } else { ix })
}

/// CPython `float_floor_div`.
fn float_floordiv(vx: f64, wx: f64) -> Result<f64, ExprError> {
    if wx == 0.0 {
        return Err(ExprError::ZeroDivision("float floor division by zero"));
    }
    let m = vx % wx;
    let mut div = (vx - m) / wx;
    if m != 0.0 && ((wx < 0.0) != (m < 0.0)) {
        div -= 1.0;
    }
    if div != 0.0 {
        let mut fd = div.floor();
        if div - fd > 0.5 {
            fd += 1.0;
        }
        Ok(fd)
    } else {
        Ok(0.0f64.copysign(vx / wx))
    }
}

/// Python `repr(float)` (shortest round-trip digits, `1e+16` style exponents).
pub(crate) fn float_repr(x: f64) -> String {
    if x.is_nan() {
        return "nan".into();
    }
    if x.is_infinite() {
        return if x > 0.0 { "inf" } else { "-inf" }.into();
    }
    let sign = if x.is_sign_negative() { "-" } else { "" };
    if x == 0.0 {
        return format!("{sign}0.0");
    }
    let ax = x.abs();
    let mut sci = format!("{ax:e}");
    // Both are shortest round-trip digit strings, but on a tie between two
    // candidates Python picks the one nearest the exact value (ties to even)
    // and Rust the upper one: prefer the correctly rounded string if it
    // still round-trips.
    let n = sci
        .bytes()
        .take_while(|&c| c != b'e')
        .filter(u8::is_ascii_digit)
        .count();
    let exact = format!("{:.*e}", n - 1, ax);
    if exact.parse::<f64>() == Ok(ax) {
        sci = exact;
    }
    let (mant, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    let nd = digits.len() as i32;
    let decpt = exp + 1;
    let mut out = String::from(sign);
    if decpt <= -4 || decpt > 16 {
        out.push_str(&digits[..1]);
        if nd > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        out.push('e');
        out.push(if exp < 0 { '-' } else { '+' });
        let e = exp.unsigned_abs();
        if e < 10 {
            out.push('0');
        }
        out.push_str(&e.to_string());
    } else if decpt <= 0 {
        out.push_str("0.");
        for _ in 0..(-decpt) {
            out.push('0');
        }
        out.push_str(&digits);
    } else if decpt >= nd {
        out.push_str(&digits);
        for _ in 0..(decpt - nd) {
            out.push('0');
        }
        out.push_str(".0");
    } else {
        out.push_str(&digits[..decpt as usize]);
        out.push('.');
        out.push_str(&digits[decpt as usize..]);
    }
    out
}

/// Python `int << int`.
pub(crate) fn int_lshift(a: i64, b: i64) -> Result<i64, ExprError> {
    if b < 0 {
        return Err(ExprError::Value("negative shift count"));
    }
    if a == 0 {
        return Ok(0);
    }
    if b >= 64 {
        return Err(ExprError::Overflow("integer left shift"));
    }
    let r = a << b;
    if (r >> b) == a {
        Ok(r)
    } else {
        Err(ExprError::Overflow("integer left shift"))
    }
}

/// Python `int >> int`.
pub(crate) fn int_rshift(a: i64, b: i64) -> Result<i64, ExprError> {
    if b < 0 {
        return Err(ExprError::Value("negative shift count"));
    }
    Ok(if b >= 64 {
        if a < 0 { -1 } else { 0 }
    } else {
        a >> b
    })
}

/// Python `round(int, ndigits)` (half to even).
pub(crate) fn round_int(x: i64, ndigits: i64) -> Result<i64, ExprError> {
    if ndigits >= 0 {
        return Ok(x);
    }
    let k = ndigits.unsigned_abs();
    if k > 38 {
        return Ok(0);
    }
    let mut p: i128 = 1;
    for _ in 0..k {
        p *= 10;
    }
    let x = i128::from(x);
    let mut q = x.div_euclid(p);
    let r = x.rem_euclid(p);
    if 2 * r > p || (2 * r == p && q % 2 != 0) {
        q += 1;
    }
    i64::try_from(q * p).map_err(|_| ExprError::Overflow("round() result does not fit in 64 bits"))
}

/// Python `round(float, ndigits)` (correctly rounded, half to even).
pub(crate) fn round_float(x: f64, ndigits: i64) -> Result<f64, ExprError> {
    // CPython: NDIGITS_MAX / NDIGITS_MIN for IEEE doubles.
    const NDIGITS_MAX: i64 = 323;
    const NDIGITS_MIN: i64 = -308;
    if !x.is_finite() || x == 0.0 {
        return Ok(x);
    }
    if ndigits > NDIGITS_MAX {
        return Ok(x);
    }
    if ndigits < NDIGITS_MIN {
        return Ok(0.0 * x);
    }
    let r = if ndigits >= 0 {
        // Rust's precision formatting is exact and rounds ties to even,
        // like dtoa mode 3.
        let s = format!("{:.*}", ndigits as usize, x);
        s.parse::<f64>()
            .map_err(|_| ExprError::Value("round() failed"))?
    } else {
        let ax = x.abs();
        let int_part = format!("{:.0}", ax.trunc());
        let frac_nonzero = ax.fract() != 0.0;
        let k = (-ndigits) as usize;
        let digits = int_part.as_bytes();
        let len = digits.len();
        let v = if k > len {
            0.0
        } else {
            let keep = len - k;
            let first = digits[keep];
            let rest_nonzero = frac_nonzero || digits[keep + 1..].iter().any(|&c| c != b'0');
            let last_odd = keep > 0 && (digits[keep - 1] - b'0') % 2 == 1;
            let up = first > b'5' || (first == b'5' && (rest_nonzero || last_odd));
            let mut kept: Vec<u8> = digits[..keep].to_vec();
            if up {
                let mut i = kept.len();
                loop {
                    if i == 0 {
                        kept.insert(0, b'1');
                        break;
                    }
                    i -= 1;
                    if kept[i] == b'9' {
                        kept[i] = b'0';
                    } else {
                        kept[i] += 1;
                        break;
                    }
                }
            }
            kept.extend(std::iter::repeat_n(b'0', k));
            if kept.is_empty() {
                0.0
            } else {
                std::str::from_utf8(&kept)
                    .ok()
                    .and_then(|s| s.parse::<f64>().ok())
                    .ok_or(ExprError::Value("round() failed"))?
            }
        };
        v.copysign(x)
    };
    if r.is_infinite() {
        return Err(ExprError::Overflow("rounded value too large to represent"));
    }
    Ok(r)
}
