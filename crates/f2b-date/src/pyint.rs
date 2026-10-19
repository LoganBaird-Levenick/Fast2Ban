//! Python `int()` / `float()` / `str.isalnum()` on `str` input.
//!
//! Upstream feeds regex groups (which match any Unicode decimal digit via
//! `\d`) to `int()` and `float()`, both of which accept every `Nd` digit, a
//! sign, surrounding whitespace and single underscores between digits.

use f2b_helpers::pychar;

/// Code points of the digit zero of every `Nd` block (Unicode 16.0, as in
/// Python 3.14); each block is ten consecutive code points.
const ZEROS: [u32; 76] = [
    0x30, 0x660, 0x6F0, 0x7C0, 0x966, 0x9E6, 0xA66, 0xAE6, 0xB66, 0xBE6, 0xC66, 0xCE6, 0xD66,
    0xDE6, 0xE50, 0xED0, 0xF20, 0x1040, 0x1090, 0x17E0, 0x1810, 0x1946, 0x19D0, 0x1A80, 0x1A90,
    0x1B50, 0x1BB0, 0x1C40, 0x1C50, 0xA620, 0xA8D0, 0xA900, 0xA9D0, 0xA9F0, 0xAA50, 0xABF0, 0xFF10,
    0x104A0, 0x10D30, 0x10D40, 0x11066, 0x110F0, 0x11136, 0x111D0, 0x112F0, 0x11450, 0x114D0,
    0x11650, 0x116C0, 0x116D0, 0x116DA, 0x11730, 0x118E0, 0x11950, 0x11BF0, 0x11C50, 0x11D50,
    0x11DA0, 0x11F50, 0x16130, 0x16A60, 0x16AC0, 0x16B50, 0x16D70, 0x1CCF0, 0x1D7CE, 0x1D7D8,
    0x1D7E2, 0x1D7EC, 0x1D7F6, 0x1E140, 0x1E2F0, 0x1E4F0, 0x1E5F1, 0x1E950, 0x1FBF0,
];

/// Decimal value of an `Nd` character (`unicodedata.decimal`).
pub(crate) fn digit_value(c: char) -> Option<u32> {
    if c.is_ascii() {
        return c.to_digit(10);
    }
    let cp = u32::from(c);
    let idx = ZEROS.partition_point(|&z| z <= cp).checked_sub(1)?;
    let d = cp - ZEROS[idx];
    (d < 10).then_some(d)
}

/// Python `str.isalnum()` for one character (`\w` without `_`).
pub(crate) fn is_alnum(c: char) -> bool {
    c != '_' && pychar::is_word(c)
}

/// `int(s)`; `None` is a `ValueError`. Values beyond `i128` also give `None`
/// (they would be `OverflowError`/`ValueError` downstream anyway).
pub(crate) fn py_int(s: &str) -> Option<i128> {
    let t = pychar::strip(s);
    let (neg, digits) = match t.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let mut v: i128 = 0;
    let mut prev_digit = false;
    let mut any = false;
    for c in digits.chars() {
        if c == '_' {
            if !prev_digit {
                return None;
            }
            prev_digit = false;
            continue;
        }
        let d = digit_value(c)?;
        v = v.checked_mul(10)?.checked_add(i128::from(d))?;
        prev_digit = true;
        any = true;
    }
    if !any || !prev_digit {
        return None;
    }
    Some(if neg { -v } else { v })
}

/// `float(s)` for the shapes upstream produces from epoch groups (digits with
/// an optional fraction); Unicode digits are converted. `None` is `ValueError`.
pub(crate) fn py_float(s: &str) -> Option<f64> {
    let ascii: String = pychar::strip(s)
        .chars()
        .map(|c| match digit_value(c) {
            Some(d) if !c.is_ascii() => char::from_digit(d, 10).unwrap_or(c),
            _ => c,
        })
        .collect();
    if ascii.contains('_') || ascii.starts_with(['i', 'I', 'n', 'N']) {
        return None;
    }
    ascii.parse::<f64>().ok()
}
