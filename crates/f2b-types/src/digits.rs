//! Unicode decimal digits (general category `Nd`), as Python's `re` `\d` and
//! `int()` see them for `str` input.
//!
//! Upstream's `IP_4_RE` and the `/(\d+)` prefix-length group are Python `str`
//! patterns, so they match every decimal digit of every script
//! (`"١.٢.٣.٤"`), and `int()` converts them (`int("٢٤") == 24`). Rust's std has
//! no `Nd` lookup, so the zero-digit code points are tabulated here; the oracle
//! test checks the table against Python 3.14 (Unicode 16.0) for all code points.

/// Code points of the digit zero of every `Nd` block, ascending. Each block is
/// ten consecutive code points whose values are `0..=9`.
const ZEROS: [u32; 76] = [
    0x30, 0x660, 0x6F0, 0x7C0, 0x966, 0x9E6, 0xA66, 0xAE6, 0xB66, 0xBE6, 0xC66, 0xCE6, 0xD66,
    0xDE6, 0xE50, 0xED0, 0xF20, 0x1040, 0x1090, 0x17E0, 0x1810, 0x1946, 0x19D0, 0x1A80, 0x1A90,
    0x1B50, 0x1BB0, 0x1C40, 0x1C50, 0xA620, 0xA8D0, 0xA900, 0xA9D0, 0xA9F0, 0xAA50, 0xABF0, 0xFF10,
    0x104A0, 0x10D30, 0x10D40, 0x11066, 0x110F0, 0x11136, 0x111D0, 0x112F0, 0x11450, 0x114D0,
    0x11650, 0x116C0, 0x116D0, 0x116DA, 0x11730, 0x118E0, 0x11950, 0x11BF0, 0x11C50, 0x11D50,
    0x11DA0, 0x11F50, 0x16130, 0x16A60, 0x16AC0, 0x16B50, 0x16D70, 0x1CCF0, 0x1D7CE, 0x1D7D8,
    0x1D7E2, 0x1D7EC, 0x1D7F6, 0x1E140, 0x1E2F0, 0x1E4F0, 0x1E5F1, 0x1E950, 0x1FBF0,
];

/// The decimal value (`0..=9`) of `c` if it is an `Nd` character.
pub(crate) fn digit_value(c: char) -> Option<u32> {
    if c.is_ascii() {
        return c.to_digit(10);
    }
    let cp = u32::from(c);
    let idx = ZEROS.partition_point(|&z| z <= cp).checked_sub(1)?;
    let d = cp - ZEROS[idx];
    (d < 10).then_some(d)
}

/// `true` for characters Python's `\d` matches in a `str` pattern.
pub(crate) fn is_decimal(c: char) -> bool {
    digit_value(c).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The table equals Python 3.14's `unicodedata.decimal` for every code
    /// point (`testdata/f2b-types/unicode_digits.json`: `[[codepoint, value], ...]`).
    #[test]
    fn matches_python_decimal_property() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/f2b-types/unicode_digits.json"
        );
        let text = std::fs::read_to_string(path).expect("unicode_digits fixture");
        let mut nums = Vec::new();
        let mut cur: Option<u32> = None;
        for b in text.bytes() {
            match (b.is_ascii_digit(), cur) {
                (true, c) => cur = Some(c.unwrap_or(0) * 10 + u32::from(b - b'0')),
                (false, Some(v)) => {
                    nums.push(v);
                    cur = None;
                }
                (false, None) => {}
            }
        }
        let expected: std::collections::HashMap<u32, u32> =
            nums.chunks_exact(2).map(|p| (p[0], p[1])).collect();
        assert_eq!(expected.len(), 760);
        for cp in 0..=0x10FFFFu32 {
            if let Some(c) = char::from_u32(cp) {
                assert_eq!(digit_value(c), expected.get(&cp).copied(), "U+{cp:04X}");
            }
        }
    }
}
