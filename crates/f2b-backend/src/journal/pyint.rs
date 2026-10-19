//! Python's `int(bytes, base)` (bases 0, 10 and 16), as used by python-systemd's integer
//! converters and by `FilterSystemd.formatJournalEntry` (`int(v, 0)`).

/// Python decimal-string conversion limit (`sys.int_info.default_max_str_digits`).
const MAX_DECIMAL_DIGITS: usize = 4300;

/// Magnitude of a parsed integer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Magnitude {
    Fits(u128),
    /// Decimal digits without leading zeros (only produced for base-10 input that exceeds `u128`).
    Huge(String),
}

/// A parsed Python integer: sign and magnitude.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedInt {
    pub negative: bool,
    pub magnitude: Magnitude,
}

fn is_py_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

fn digit_value(b: u8) -> Option<u32> {
    match b {
        b'0'..=b'9' => Some(u32::from(b - b'0')),
        b'a'..=b'z' => Some(u32::from(b - b'a') + 10),
        b'A'..=b'Z' => Some(u32::from(b - b'A') + 10),
        _ => None,
    }
}

/// `int(s, base)` for a `bytes` object; `None` where Python raises `ValueError`.
///
/// Numbers beyond `u128` are only representable for base 10; other bases return `None`
/// there (Python would return a huge integer).
pub(crate) fn parse_int(input: &[u8], base: u32) -> Option<ParsedInt> {
    debug_assert!(base == 0 || base == 10 || base == 16);
    let mut s = input;
    while let [first, rest @ ..] = s {
        if is_py_space(*first) {
            s = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = s {
        if is_py_space(*last) {
            s = rest;
        } else {
            break;
        }
    }
    let mut negative = false;
    match s.first() {
        Some(b'-') => {
            negative = true;
            s = &s[1..];
        }
        Some(b'+') => s = &s[1..],
        _ => {}
    }
    let mut base = base;
    let mut legacy_zero = false;
    if base == 0 {
        if s.first() != Some(&b'0') {
            base = 10;
        } else {
            match s.get(1) {
                Some(b'x' | b'X') => base = 16,
                Some(b'o' | b'O') => base = 8,
                Some(b'b' | b'B') => base = 2,
                _ => {
                    // "old" C-style octal literals are invalid unless the value is zero
                    base = 8;
                    legacy_zero = true;
                }
            }
        }
    }
    let prefixed = matches!(
        (base, s.first(), s.get(1)),
        (16, Some(b'0'), Some(b'x' | b'X'))
            | (8, Some(b'0'), Some(b'o' | b'O'))
            | (2, Some(b'0'), Some(b'b' | b'B'))
    );
    if prefixed {
        s = &s[2..];
        if s.first() == Some(&b'_') {
            s = &s[1..];
        }
    }
    // digits, single underscores allowed between digits
    let mut digits: Vec<u32> = Vec::with_capacity(s.len());
    let mut prev_underscore = true; // a leading underscore is invalid
    for &b in s {
        if b == b'_' {
            if prev_underscore {
                return None;
            }
            prev_underscore = true;
            continue;
        }
        let d = digit_value(b)?;
        if d >= base {
            return None;
        }
        digits.push(d);
        prev_underscore = false;
    }
    if digits.is_empty() || prev_underscore {
        return None;
    }
    if legacy_zero && digits.iter().any(|&d| d != 0) {
        return None;
    }
    if base == 10 && digits.len() > MAX_DECIMAL_DIGITS {
        return None;
    }
    let mut acc: u128 = 0;
    let mut overflow = false;
    for &d in &digits {
        match acc
            .checked_mul(u128::from(base))
            .and_then(|v| v.checked_add(u128::from(d)))
        {
            Some(v) => acc = v,
            None => {
                overflow = true;
                break;
            }
        }
    }
    let magnitude = if !overflow {
        Magnitude::Fits(acc)
    } else if base == 10 {
        let mut text: String = digits.iter().map(|&d| char::from(b'0' + d as u8)).collect();
        let trimmed = text.trim_start_matches('0').len();
        text.drain(..text.len() - trimmed);
        Magnitude::Huge(text)
    } else {
        return None;
    };
    Some(ParsedInt {
        negative,
        magnitude,
    })
}
