//! Ports of glibc's `inet_pton(3)` / `inet_ntop(3)` for `AF_INET` and
//! `AF_INET6`.
//!
//! Upstream `IPAddr` delegates parsing and formatting to Python's
//! `socket.inet_pton` / `socket.inet_ntop`, which call the C library. The
//! accepted grammar (no leading zeros in IPv4 octets, `::` rules, embedded
//! IPv4 tail) and the canonical IPv6 text form (longest zero run of length >= 2
//! compressed, `::a.b.c.d` / `::ffff:a.b.c.d` for the embedded-IPv4 forms) are
//! therefore the C library's; these functions reproduce the glibc behaviour
//! (the platform upstream is normally deployed on).

use std::fmt::{self, Write};

fn hex_digit(c: u8) -> Option<u32> {
    char::from(c).to_digit(16)
}

/// `inet_pton(AF_INET, ..)`: exactly four decimal octets, each `0..=255`, no
/// leading zeros, no other characters.
pub(crate) fn pton4(src: &[u8]) -> Option<u32> {
    let mut octets = [0u32; 4];
    let mut idx = 0usize; // octet being parsed
    let mut count = 0usize; // octets that saw at least one digit
    let mut saw_digit = false;
    for &ch in src {
        if ch.is_ascii_digit() {
            let cur = &mut octets[idx];
            let new = *cur * 10 + u32::from(ch - b'0');
            if saw_digit && *cur == 0 {
                return None;
            }
            if new > 255 {
                return None;
            }
            *cur = new;
            if !saw_digit {
                count += 1;
                if count > 4 {
                    return None;
                }
                saw_digit = true;
            }
        } else if ch == b'.' && saw_digit {
            if count == 4 {
                return None;
            }
            idx += 1;
            saw_digit = false;
        } else {
            return None;
        }
    }
    if count < 4 {
        return None;
    }
    Some(octets.iter().fold(0, |acc, &o| (acc << 8) | o))
}

/// `inet_pton(AF_INET6, ..)`.
pub(crate) fn pton6(src: &[u8]) -> Option<u128> {
    let mut tmp = [0u8; 16];
    let mut tp = 0usize;
    let mut colonp: Option<usize> = None;
    let mut i = 0usize;

    if src.is_empty() {
        return None;
    }
    // Leading "::" requires some special handling.
    if src[0] == b':' {
        i = 1;
        if i == src.len() || src[i] != b':' {
            return None;
        }
    }
    let mut curtok = i;
    let mut xdigits_seen = 0usize;
    let mut val = 0u32;
    while i < src.len() {
        let ch = src[i];
        i += 1;
        if let Some(digit) = hex_digit(ch) {
            if xdigits_seen == 4 {
                return None;
            }
            val = (val << 4) | digit;
            xdigits_seen += 1;
            continue;
        }
        if ch == b':' {
            curtok = i;
            if xdigits_seen == 0 {
                if colonp.is_some() {
                    return None;
                }
                colonp = Some(tp);
                continue;
            } else if i == src.len() {
                return None;
            }
            if tp + 2 > 16 {
                return None;
            }
            tmp[tp] = (val >> 8) as u8;
            tmp[tp + 1] = val as u8;
            tp += 2;
            xdigits_seen = 0;
            val = 0;
            continue;
        }
        if ch == b'.' && tp + 4 <= 16 {
            if let Some(v4) = pton4(&src[curtok..]) {
                tmp[tp..tp + 4].copy_from_slice(&v4.to_be_bytes());
                tp += 4;
                xdigits_seen = 0;
                break; // the whole tail was consumed by pton4
            }
        }
        return None;
    }
    if xdigits_seen > 0 {
        if tp + 2 > 16 {
            return None;
        }
        tmp[tp] = (val >> 8) as u8;
        tmp[tp + 1] = val as u8;
        tp += 2;
    }
    if let Some(c) = colonp {
        // "::" would expand to a zero-width field.
        if tp == 16 {
            return None;
        }
        let n = tp - c;
        tmp.copy_within(c..tp, 16 - n);
        tmp[c..16 - n].fill(0);
        tp = 16;
    }
    if tp != 16 {
        return None;
    }
    Some(u128::from_be_bytes(tmp))
}

/// `inet_ntop(AF_INET, ..)`.
pub(crate) fn ntop4(addr: u32, out: &mut impl Write) -> fmt::Result {
    let [a, b, c, d] = addr.to_be_bytes();
    write!(out, "{a}.{b}.{c}.{d}")
}

/// `inet_ntop(AF_INET6, ..)`.
pub(crate) fn ntop6(addr: u128, out: &mut impl Write) -> fmt::Result {
    let bytes = addr.to_be_bytes();
    let mut words = [0u16; 8];
    for (w, pair) in words.iter_mut().zip(bytes.chunks_exact(2)) {
        *w = u16::from_be_bytes([pair[0], pair[1]]);
    }
    // Find the longest run of zero words (the first one on ties); a run is
    // only compressed when it is at least two words long.
    let mut best: Option<(usize, usize)> = None; // (base, len)
    let mut cur: Option<(usize, usize)> = None;
    for (i, &w) in words.iter().enumerate() {
        if w == 0 {
            cur = match cur {
                Some((base, len)) => Some((base, len + 1)),
                None => Some((i, 1)),
            };
        } else if let Some(run) = cur.take() {
            if best.is_none_or(|b| run.1 > b.1) {
                best = Some(run);
            }
        }
    }
    if let Some(run) = cur {
        if best.is_none_or(|b| run.1 > b.1) {
            best = Some(run);
        }
    }
    let best = best.filter(|&(_, len)| len >= 2);

    for (i, &w) in words.iter().enumerate() {
        if let Some((base, len)) = best {
            if i >= base && i < base + len {
                if i == base {
                    out.write_char(':')?;
                }
                continue;
            }
        }
        if i != 0 {
            out.write_char(':')?;
        }
        // An encapsulated IPv4 address?
        if i == 6 {
            if let Some((0, len)) = best {
                if len == 6 || (len == 5 && words[5] == 0xffff) {
                    let v4 = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
                    return ntop4(v4, out);
                }
            }
        }
        write!(out, "{w:x}")?;
    }
    // A trailing run of zeros.
    if let Some((base, len)) = best {
        if base + len == 8 {
            out.write_char(':')?;
        }
    }
    Ok(())
}
