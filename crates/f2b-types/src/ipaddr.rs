//! Port of the pure-value parts of upstream `fail2ban/server/ipdns.py`:
//! [`IPAddr`], [`IPAddrSet`], `searchIP` and the address regex sources.
//!
//! # Fidelity
//!
//! The port reproduces upstream behaviour observably, including its quirks:
//!
//! * **Parsing.** `IPAddr(str)` strips one pair of enclosing `[...]`, splits an
//!   optional `/prefix` or `/netmask` using the exact `IP_W_CIDR_CRE` shape
//!   (Unicode decimal digits included, a trailing `"\n"` tolerated as `$`
//!   does), and converts with the C library's `inet_pton` grammar (glibc, see
//!   below). Text that is not an address is *not* an
//!   error: it yields an invalid [`IPAddr`] (family [`Family::Unspec`]) that
//!   remembers the text, exactly like upstream. The only errors are the two
//!   `ValueError`s upstream can raise: an embedded NUL and a netmask that is
//!   not a run of leading ones ([`IPAddrError`]).
//! * **IPv4-mapped.** An IPv6 address inside `::ffff:0:0/96` that was given
//!   without a prefix becomes an IPv4 address.
//! * **Prefix lengths** are not validated: `1.2.3.4/33` is a valid IPv4 object
//!   with `plen == 33` (no masking, no `/n` in `ntoa`). `/0` prints without a
//!   suffix (`ntoa` only appends `/n` for `0 < plen < 32|128`).
//! * **Equality and ordering** are the upstream ones, not a total order:
//!   [`IPAddr::lt`] is `family < family || addr < addr`, which is not a strict
//!   weak order, so `IPAddr` deliberately implements `PartialEq`/`Eq`/`Hash`
//!   but not `PartialOrd`/`Ord`. Two [`Family::Raw`] objects always compare
//!   equal.
//! * **`getPTR`** for an IPv4 subnet keeps the `/n` glued to the last octet
//!   (`0/24.3.2.1.in-addr.arpa.`) because upstream splits `ntoa`.
//!
//! # Intentional differences from upstream
//!
//! * `inet_pton`/`inet_ntop` are ported from glibc (Linux). Python on other
//!   C libraries can differ on rare inputs.
//! * Prefix lengths larger than `u32::MAX` saturate at `u32::MAX` (Python
//!   keeps an arbitrary-precision int); all such values behave identically
//!   except in `plen()` and equality between two different huge values.
//! * The text of a *valid* address is not stored: [`IPAddr::raw_text`]
//!   returns `""` for valid addresses (upstream documents `raw` as meaningful
//!   only for addresses that failed conversion or were created raw).
//! * `hash(IPAddr)` is not `hash(str(ip))`: Python needs that to look an
//!   `IPAddr` up in a `dict` keyed by `str`; Rust has no such coupling. The
//!   [`Hash`] impl is consistent with [`PartialEq`].
//! * DNS: upstream's `isInNet` resolves a non-IP "network" through
//!   `DNSUtils.dnsToIp`. Resolution is out of scope here; the `*_with` methods
//!   take a resolver callback and the plain forms use a resolver that finds
//!   nothing.
//! * Upstream memoises objects by `(text, cidr)` *after* wrapping, which makes
//!   results history-dependent (e.g. `IPAddr("[[::1]]")` poisons the cache
//!   entry for `"[::1]"`, which then yields an invalid object). This port has
//!   no cache and always behaves like a cold cache; the oracle is generated
//!   the same way.
//! * Python-only plumbing is not ported: the object cache (`CACHE_OBJ`),
//!   `__reduce__` pickling, `__repr__`, `__add__`/`__radd__` string
//!   concatenation, duck-typed `asip` (use [`IPAddr::new`] / `str::parse`),
//!   `DNSUtils`, `FileIPAddrSet` (file I/O; only its name regex is ported as
//!   [`file_ignore_ip_name`]), `getfqdn` and `_NetworkInterfacesAddrs`.

use std::borrow::Cow;
use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use crate::digits::{digit_value, is_decimal};
use crate::inet::{ntop4, ntop6, pton4, pton6};

/// `IPAddr.IP_4_RE`: regex source matching a dotted-quad IPv4 address
/// (Python `str` pattern: `\d` is any Unicode decimal digit).
pub const IP_4_RE: &str = r"(?:\d{1,3}\.){3}\d{1,3}";

/// `IPAddr.IP_6_RE`: regex source matching an IPv6 address (loose shape;
/// validity is decided by `inet_pton`). Contains a lookbehind.
pub const IP_6_RE: &str = r"(?:[0-9a-fA-F]{1,4}::?|:){1,7}(?:[0-9a-fA-F]{1,4}|(?<=:):)";

/// Source of `IPAddr.IP_4_6_CRE`: a whole-string IPv4 (group `IPv4`) or
/// optionally bracketed IPv6 (group `IPv6`).
pub const IP_4_6_CRE: &str = r"^(?:(?P<IPv4>(?:\d{1,3}\.){3}\d{1,3})|\[?(?P<IPv6>(?:[0-9a-fA-F]{1,4}::?|:){1,7}(?:[0-9a-fA-F]{1,4}|(?<=:):))\]?)$";

/// Source of `IPAddr.IP_W_CIDR_CRE`: address, `/`, then a prefix length
/// (group 2) or a netmask (group 3).
pub const IP_W_CIDR_CRE: &str = r"^((?:\d{1,3}\.){3}\d{1,3}|(?:[0-9a-fA-F]{1,4}::?|:){1,7}(?:[0-9a-fA-F]{1,4}|(?<=:):))/(?:(\d+)|((?:\d{1,3}\.){3}\d{1,3}|(?:[0-9a-fA-F]{1,4}::?|:){1,7}(?:[0-9a-fA-F]{1,4}|(?<=:):)))$";

/// Address family of an [`IPAddr`], ordered as upstream orders the numeric
/// `family` values (`CIDR_RAW` < `AF_UNSPEC` < `AF_INET` < `AF_INET6`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Family {
    /// `CIDR_RAW`: the text is kept verbatim, nothing was parsed.
    Raw,
    /// `AF_UNSPEC`: the text is not an IP address (e.g. a host name).
    Unspec,
    /// `AF_INET`.
    Inet4,
    /// `AF_INET6`.
    Inet6,
}

impl Family {
    fn rank(self) -> u8 {
        match self {
            Family::Raw => 0,
            Family::Unspec => 1,
            Family::Inet4 => 2,
            Family::Inet6 => 3,
        }
    }
}

/// The `cidr` argument of upstream `IPAddr(ipstr, cidr)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Cidr {
    /// `CIDR_UNSPEC` (the default): detect the family, split `/prefix` or
    /// `/netmask` off the string.
    Unspec,
    /// `CIDR_RAW`: keep the text as is (no parsing, family [`Family::Raw`]).
    Raw,
    /// `FAM_IPv4`: the text must be an IPv4 address; no prefix handling.
    Inet4,
    /// `FAM_IPv6`: the text must be an IPv6 address; no prefix handling.
    Inet6,
    /// `cidr=None`: detect the family, no prefix handling.
    NoMask,
    /// A prefix length `>= 0`: detect the family and mask the address to it.
    /// Not range-checked (as upstream).
    Prefix(u32),
}

/// The errors upstream `IPAddr` raises as `ValueError`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IPAddrError {
    /// The address text contains a NUL character (`inet_pton` argument).
    EmbeddedNul,
    /// A netmask that is not a contiguous run of leading ones; carries
    /// `str()` of the mask address, as upstream's message does.
    InvalidMask(String),
}

impl fmt::Display for IPAddrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IPAddrError::EmbeddedNul => f.write_str("embedded null character"),
            IPAddrError::InvalidMask(mask) => {
                write!(f, "invalid mask '{mask}', no plen representation")
            }
        }
    }
}

impl Error for IPAddrError {}

/// An IPv4/IPv6 address or network (port of upstream `IPAddr`), or the raw
/// text of something that is not an address.
#[derive(Clone, Debug)]
pub struct IPAddr {
    family: Family,
    addr: u128,
    plen: u32,
    /// Text of an invalid / raw object; empty for valid addresses.
    raw: String,
}

/// Mask `addr` (a `bits`-wide address) to its leading `plen` bits; a prefix of
/// `bits` or more leaves it untouched (Python's `~(ALL >> plen)` is `-1`).
fn mask_addr(addr: u128, bits: u32, plen: u32) -> u128 {
    if plen >= bits {
        return addr;
    }
    let all = if bits == 32 {
        u128::from(u32::MAX)
    } else {
        u128::MAX
    };
    addr & !(all >> plen)
}

/// Full match of [`IP_4_RE`].
fn is_ip4_re(s: &str) -> bool {
    let mut parts = 0;
    for part in s.split('.') {
        parts += 1;
        let mut n = 0;
        for c in part.chars() {
            n += 1;
            if n > 3 || !is_decimal(c) {
                return false;
            }
        }
        if n == 0 {
            return false;
        }
    }
    parts == 4
}

/// Full match of [`IP_6_RE`] (hand-written backtracking over its two-level
/// structure: up to seven `hex{1,4}::?` / `:` tokens, then `hex{1,4}` or a
/// final `:`).
fn is_ip6_re(s: &str) -> bool {
    // 7 tokens of at most 6 characters plus a final group of at most 4.
    if s.len() > 46 {
        return false;
    }
    fn hex_run(b: &[u8]) -> bool {
        (1..=4).contains(&b.len()) && b.iter().all(u8::is_ascii_hexdigit)
    }
    fn rec(s: &[u8], pos: usize, tokens: usize) -> bool {
        let rest = &s[pos..];
        // The tail: only valid after at least one token (the lookbehind needs
        // the previous token's trailing colon).
        if tokens >= 1 && (hex_run(rest) || rest == b":") {
            return true;
        }
        if tokens == 7 || rest.is_empty() {
            return false;
        }
        if rest[0] == b':' {
            return rec(s, pos + 1, tokens + 1);
        }
        for k in 1..=4.min(rest.len().saturating_sub(1)) {
            if !rest[k - 1].is_ascii_hexdigit() {
                break;
            }
            if rest[k] == b':' {
                if rec(s, pos + k + 1, tokens + 1) {
                    return true;
                }
                if rest.get(k + 1) == Some(&b':') && rec(s, pos + k + 2, tokens + 1) {
                    return true;
                }
            }
        }
        false
    }
    rec(s.as_bytes(), 0, 0)
}

/// Parse `\d+` into a prefix length (saturating at `u32::MAX`).
fn parse_decimal(s: &str) -> Option<u32> {
    if s.is_empty() {
        return None;
    }
    let mut v = 0u32;
    for c in s.chars() {
        v = v.saturating_mul(10).saturating_add(digit_value(c)?);
    }
    Some(v)
}

/// `IPAddr.__wrap_ipstr`: strip enclosing brackets and split `/prefix` or
/// `/netmask`. Returns the (possibly shortened) text and the prefix to use.
fn wrap_ipstr(ipstr: &str) -> Result<(&str, Cidr), IPAddrError> {
    let mut s = ipstr;
    let b = s.as_bytes();
    if b.len() > 2 && b[0] == b'[' && b[b.len() - 1] == b']' {
        s = &s[1..s.len() - 1];
    }
    if !s.contains('/') {
        return Ok((s, Cidr::Unspec));
    }
    // `$` also matches before one trailing newline.
    let t = s.strip_suffix('\n').unwrap_or(s);
    let Some((addr, rest)) = t.split_once('/') else {
        return Ok((s, Cidr::Unspec));
    };
    if !(is_ip4_re(addr) || is_ip6_re(addr)) {
        return Ok((s, Cidr::Unspec));
    }
    if let Some(plen) = parse_decimal(rest) {
        return Ok((addr, Cidr::Prefix(plen)));
    }
    if is_ip4_re(rest) || is_ip6_re(rest) {
        return Ok((addr, Cidr::Prefix(IPAddr::masktoplen(rest)?)));
    }
    Ok((s, Cidr::Unspec))
}

impl IPAddr {
    /// `IPAddr.IP6_4COMPAT`: `::ffff:0:0/96`, the IPv4-mapped IPv6 network.
    pub const IP6_4COMPAT: IPAddr = IPAddr {
        family: Family::Inet6,
        addr: 0xffff_0000_0000,
        plen: 96,
        raw: String::new(),
    };

    /// `IPAddr(ipstr)` (`CIDR_UNSPEC`).
    ///
    /// # Errors
    /// [`IPAddrError`] where upstream raises `ValueError`; text that is merely
    /// not an address yields an invalid object, not an error.
    pub fn new(ipstr: &str) -> Result<IPAddr, IPAddrError> {
        IPAddr::with_cidr(ipstr, Cidr::Unspec)
    }

    /// `IPAddr(ipstr, cidr)`.
    ///
    /// # Errors
    /// See [`IPAddr::new`].
    pub fn with_cidr(ipstr: &str, cidr: Cidr) -> Result<IPAddr, IPAddrError> {
        match cidr {
            Cidr::Raw => Ok(IPAddr::raw(ipstr)),
            Cidr::Unspec => {
                let (s, cidr) = wrap_ipstr(ipstr)?;
                IPAddr::convert(s, cidr)
            }
            other => IPAddr::convert(ipstr, other),
        }
    }

    /// `IPAddr(text, CIDR_RAW)`: keep `text` verbatim (family [`Family::Raw`]).
    pub fn raw(text: &str) -> IPAddr {
        IPAddr {
            family: Family::Raw,
            addr: 0,
            plen: 0,
            raw: text.to_owned(),
        }
    }

    /// `IPAddr.__init` for a non-raw `cidr` (already wrapped).
    fn convert(ipstr: &str, cidr: Cidr) -> Result<IPAddr, IPAddrError> {
        let bytes = ipstr.as_bytes();
        if bytes.contains(&0) {
            return Err(IPAddrError::EmbeddedNul);
        }
        let prefix = match cidr {
            Cidr::Prefix(p) => Some(p),
            _ => None,
        };
        let v4 = if cidr == Cidr::Inet6 {
            None
        } else {
            pton4(bytes)
        };
        if let Some(a) = v4 {
            let plen = prefix.unwrap_or(32);
            let addr = mask_addr(u128::from(a), 32, prefix.unwrap_or(u32::MAX));
            return Ok(IPAddr {
                family: Family::Inet4,
                addr,
                plen,
                raw: String::new(),
            });
        }
        let v6 = if cidr == Cidr::Inet4 {
            None
        } else {
            pton6(bytes)
        };
        if let Some(a) = v6 {
            return Ok(match prefix {
                Some(p) => IPAddr {
                    family: Family::Inet6,
                    addr: mask_addr(a, 128, p),
                    plen: p,
                    raw: String::new(),
                },
                // An IPv4-compatible IPv6 address becomes an IPv4 one.
                None if a >> 32 == 0xffff => IPAddr {
                    family: Family::Inet4,
                    addr: a & u128::from(u32::MAX),
                    plen: 32,
                    raw: String::new(),
                },
                None => IPAddr {
                    family: Family::Inet6,
                    addr: a,
                    plen: 128,
                    raw: String::new(),
                },
            });
        }
        Ok(IPAddr {
            family: Family::Unspec,
            addr: 0,
            plen: 0,
            raw: ipstr.to_owned(),
        })
    }

    /// `addr`: the address as an integer (network order value; IPv4 fits in
    /// 32 bits). `0` for invalid and raw objects.
    pub fn addr(&self) -> u128 {
        self.addr
    }

    /// `family`.
    pub fn family(&self) -> Family {
        self.family
    }

    /// `familyStr`: `inet4`, `inet6`, or `None`.
    pub fn family_str(&self) -> Option<&'static str> {
        match self.family {
            Family::Inet4 => Some("inet4"),
            Family::Inet6 => Some("inet6"),
            _ => None,
        }
    }

    /// `instanceType`: `"ip"` if [`is_valid`](Self::is_valid), else `"dns"`.
    pub fn instance_type(&self) -> &'static str {
        if self.is_valid() { "ip" } else { "dns" }
    }

    /// `plen`: the prefix length (`32`/`128` for a single address, `0` for
    /// invalid and raw objects).
    pub fn plen(&self) -> u32 {
        self.plen
    }

    /// `raw`: the text of an invalid or raw object, `""` for valid addresses
    /// (see the module docs).
    pub fn raw_text(&self) -> &str {
        &self.raw
    }

    /// `isValid`: anything but [`Family::Unspec`] (raw objects count as valid).
    pub fn is_valid(&self) -> bool {
        self.family != Family::Unspec
    }

    /// `isSingle`: IPv4 with `plen == 32` or IPv6 with `plen == 128`.
    pub fn is_single(&self) -> bool {
        match self.family {
            Family::Inet4 => self.plen == 32,
            Family::Inet6 => self.plen == 128,
            _ => false,
        }
    }

    /// `isIPv4`.
    pub fn is_ipv4(&self) -> bool {
        self.family == Family::Inet4
    }

    /// `isIPv6`.
    pub fn is_ipv6(&self) -> bool {
        self.family == Family::Inet6
    }

    /// `hexdump`: `%08x` (IPv4) or `%032x` (IPv6) of the address, else `""`.
    pub fn hexdump(&self) -> String {
        match self.family {
            Family::Inet4 => format!("{:08x}", self.addr),
            Family::Inet6 => format!("{:032x}", self.addr),
            _ => String::new(),
        }
    }

    fn write_ntoa(&self, out: &mut impl fmt::Write) -> fmt::Result {
        match self.family {
            Family::Inet4 => {
                ntop4(self.addr as u32, out)?;
                if self.plen != 0 && self.plen < 32 {
                    write!(out, "/{}", self.plen)?;
                }
                Ok(())
            }
            Family::Inet6 => {
                ntop6(self.addr, out)?;
                if self.plen != 0 && self.plen < 128 {
                    write!(out, "/{}", self.plen)?;
                }
                Ok(())
            }
            _ => out.write_str(&self.raw),
        }
    }

    /// `ntoa` (also `str()`): the canonical text; the raw text for invalid
    /// and raw objects. A subnet carries `/plen` when `0 < plen < 32|128`.
    pub fn ntoa(&self) -> Cow<'_, str> {
        match self.family {
            Family::Inet4 | Family::Inet6 => {
                let mut s = String::with_capacity(43);
                let _ = self.write_ntoa(&mut s); // writing to a String cannot fail
                Cow::Owned(s)
            }
            _ => Cow::Borrowed(&self.raw),
        }
    }

    /// `getPTR(suffix)`: the reverse-DNS name. `suffix` defaults to
    /// `in-addr.arpa.` / `ip6.arpa.`; the `ip-rev` action tag uses
    /// `Some("")`. Empty string for non-IP objects. An IPv4 subnet keeps its
    /// `/plen` attached to the last octet (upstream splits `ntoa`).
    pub fn get_ptr(&self, suffix: Option<&str>) -> String {
        let mut out = String::new();
        let default = match self.family {
            Family::Inet4 => {
                for (i, label) in self.ntoa().rsplit('.').enumerate() {
                    if i > 0 {
                        out.push('.');
                    }
                    out.push_str(label);
                }
                "in-addr.arpa."
            }
            Family::Inet6 => {
                for (i, nibble) in self.hexdump().chars().rev().enumerate() {
                    if i > 0 {
                        out.push('.');
                    }
                    out.push(nibble);
                }
                "ip6.arpa."
            }
            _ => return out,
        };
        out.push('.');
        out.push_str(suffix.unwrap_or(default));
        out
    }

    /// `maskplen`: this address read as a netmask, as a prefix length.
    ///
    /// # Errors
    /// [`IPAddrError::InvalidMask`] unless the value is a run of leading ones
    /// (32 bits wide if it fits, else 128). Invalid objects have address `0`
    /// and so give `0`.
    pub fn maskplen(&self) -> Result<u32, IPAddrError> {
        let a = self.addr;
        let plen = if a == 0 {
            Some(0)
        } else if a <= u128::from(u32::MAX) {
            let a = a as u32;
            (a.leading_ones() + a.trailing_zeros() == 32).then(|| a.leading_ones())
        } else {
            (a.leading_ones() + a.trailing_zeros() == 128).then(|| a.leading_ones())
        };
        plen.ok_or_else(|| IPAddrError::InvalidMask(self.ntoa().into_owned()))
    }

    /// `IPAddr.masktoplen(mask)`: prefix length of a netmask string.
    ///
    /// # Errors
    /// See [`IPAddr::new`] and [`IPAddr::maskplen`].
    pub fn masktoplen(mask: &str) -> Result<u32, IPAddrError> {
        IPAddr::new(mask)?.maskplen()
    }

    /// `__lt__`: `family < other.family || addr < other.addr`. Not a strict
    /// weak order (see the module docs); do not use it to sort with
    /// `sort_by` expecting a stable total order.
    pub fn lt(&self, other: &IPAddr) -> bool {
        self.family.rank() < other.family.rank() || self.addr < other.addr
    }

    /// `__eq__` against a `str`: a raw object compares its text, any other
    /// object compares equal to the parsed `other`.
    ///
    /// # Errors
    /// [`IPAddrError`] if parsing `other` raises.
    pub fn eq_str(&self, other: &str) -> Result<bool, IPAddrError> {
        if self.family == Family::Raw {
            return Ok(self.raw == other);
        }
        Ok(*self == IPAddr::new(other)?)
    }

    /// `isInNet(net)` without DNS: a non-IP `net` contains nothing.
    pub fn is_in_net(&self, net: &IPAddr) -> bool {
        self.is_in_net_with(net, |_| Vec::new())
    }

    /// `isInNet(net)`. When `net` is not an IP address but has text, upstream
    /// resolves that text and tests membership in the result; `resolve` stands
    /// in for `DNSUtils.dnsToIp` (exact-equality membership).
    pub fn is_in_net_with(
        &self,
        net: &IPAddr,
        mut resolve: impl FnMut(&str) -> Vec<IPAddr>,
    ) -> bool {
        self.in_net(net, &mut resolve)
    }

    fn in_net(&self, net: &IPAddr, resolve: &mut impl FnMut(&str) -> Vec<IPAddr>) -> bool {
        if !net.is_valid() && !net.raw.is_empty() {
            return resolve(&net.raw).iter().any(|r| Member::same(self, r));
        }
        if self.family != net.family {
            return false;
        }
        match self.family {
            Family::Inet4 => mask_addr(self.addr, 32, net.plen) == net.addr,
            Family::Inet6 => mask_addr(self.addr, 128, net.plen) == net.addr,
            _ => false,
        }
    }

    /// `contains(ip)`: whether `ip` equals this object or lies in it as a
    /// network (no DNS, see [`IPAddr::is_in_net`]).
    pub fn contains(&self, ip: &IPAddr) -> bool {
        self.contains_with(ip, |_| Vec::new())
    }

    /// `contains(ip)` with a DNS stand-in (see [`IPAddr::is_in_net_with`]).
    pub fn contains_with(&self, ip: &IPAddr, mut resolve: impl FnMut(&str) -> Vec<IPAddr>) -> bool {
        self.contains_dyn(ip, &mut resolve)
    }

    fn contains_dyn(&self, ip: &IPAddr, resolve: &mut impl FnMut(&str) -> Vec<IPAddr>) -> bool {
        ip == self || ip.in_net(self, resolve)
    }
}

impl PartialEq for IPAddr {
    /// Upstream `__eq__` between two `IPAddr`: same family and, for invalid
    /// objects the same text, else same address and prefix length. All
    /// [`Family::Raw`] objects are equal to each other.
    fn eq(&self, other: &IPAddr) -> bool {
        if self.family != other.family {
            return false;
        }
        if self.family == Family::Unspec {
            return self.raw == other.raw;
        }
        self.addr == other.addr && self.plen == other.plen
    }
}

impl Eq for IPAddr {}

impl Hash for IPAddr {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.family.hash(state);
        match self.family {
            Family::Raw => {}
            Family::Unspec => self.raw.hash(state),
            _ => {
                self.addr.hash(state);
                self.plen.hash(state);
            }
        }
    }
}

impl fmt::Display for IPAddr {
    /// `str(ip)` = [`ntoa`](IPAddr::ntoa).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_ntoa(f)
    }
}

impl FromStr for IPAddr {
    type Err = IPAddrError;

    fn from_str(s: &str) -> Result<IPAddr, IPAddrError> {
        IPAddr::new(s)
    }
}

/// `IPAddr.searchIP(text)`: if `text` as a whole is an IPv4 address or an
/// (optionally bracketed) IPv6 address *by shape* (`IP_4_6_CRE`), return the
/// address part (without brackets and one trailing newline). The result may
/// still be an invalid address (`999.1.1.1`).
pub fn search_ip(text: &str) -> Option<&str> {
    // `$` also matches before one trailing newline.
    let t = text.strip_suffix('\n').unwrap_or(text);
    if is_ip4_re(t) {
        return Some(t);
    }
    let s = t.strip_prefix('[').unwrap_or(t);
    let s = s.strip_suffix(']').unwrap_or(s);
    is_ip6_re(s).then_some(s)
}

/// `FileIPAddrSet.RE_FILE_IGN_IP`
/// (`^file:(?:/{0,2}(?=/(?!/|.{1,2}/))|/{0,2})(.*)$`): if `s` is a
/// `file:`-style ignore entry, return the file name (`file:/abs`,
/// `file:///abs` and `file:rel` forms).
pub fn file_ignore_ip_name(s: &str) -> Option<&str> {
    let t = s.strip_prefix("file:")?;
    // `(.*)$`: `.` excludes newlines, `$` also matches before a final one.
    let body_end = match t.find('\n') {
        None => t.len(),
        Some(i) if i + 1 == t.len() => i,
        Some(_) => return None,
    };
    let slashes = t.bytes().take(2).take_while(|&b| b == b'/').count();
    // First alternative: greedy slashes followed by a `/` that does not start
    // `/` or `.{1,2}/` ...
    let lookahead = |n: usize| -> bool {
        let Some(after) = t[n..].strip_prefix('/') else {
            return false;
        };
        // Negative lookahead `(?!/|.{1,2}/)` right after that slash.
        let ordinary = |c: Option<char>| c.is_some_and(|c| c != '\n');
        let mut it = after.chars();
        let c1 = it.next();
        if c1 == Some('/') {
            return false;
        }
        if !ordinary(c1) {
            return true;
        }
        let c2 = it.next();
        if c2 == Some('/') {
            return false;
        }
        !(ordinary(c2) && it.next() == Some('/'))
    };
    let n = (0..=slashes)
        .rev()
        .find(|&n| lookahead(n))
        .unwrap_or(slashes);
    Some(&t[n..body_end])
}

/// Set member compared the way a Python `set` of `IPAddr` does (hash of
/// `ntoa`, then `__eq__`), which for objects of the same text is plain
/// structural equality.
#[derive(Clone, Debug)]
struct Member(IPAddr);

impl Member {
    fn same(a: &IPAddr, b: &IPAddr) -> bool {
        a.family == b.family && a.addr == b.addr && a.plen == b.plen && a.raw == b.raw
    }
}

impl PartialEq for Member {
    fn eq(&self, other: &Member) -> bool {
        Member::same(&self.0, &other.0)
    }
}

impl Eq for Member {}

impl Hash for Member {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.family.hash(state);
        self.0.addr.hash(state);
        self.0.plen.hash(state);
        self.0.raw.hash(state);
    }
}

/// Port of upstream `IPAddrSet`: a set of addresses and networks supporting
/// containment tests (`ip in set`).
#[derive(Clone, Debug, Default)]
pub struct IPAddrSet {
    members: HashSet<Member>,
    has_subnet: bool,
}

impl IPAddrSet {
    /// `IPAddrSet()`: an empty set.
    pub fn new() -> IPAddrSet {
        IPAddrSet::default()
    }

    /// `instanceType`.
    pub fn instance_type(&self) -> &'static str {
        "ip-set"
    }

    /// `IPAddrSet(ips)`: the set of `ips`. Entries that are not
    /// [single](IPAddr::is_single) addresses (networks and names) enable the
    /// subnet scan in [`contains`](Self::contains).
    pub fn from_addrs(ips: impl IntoIterator<Item = IPAddr>) -> IPAddrSet {
        let mut set = IPAddrSet::new();
        set.set(ips);
        set
    }

    /// `IPAddrSet([str, ...])`: parse each entry with [`IPAddr::new`].
    ///
    /// # Errors
    /// The first [`IPAddrError`] any entry raises.
    pub fn parse<I, S>(ips: I) -> Result<IPAddrSet, IPAddrError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut set = IPAddrSet::new();
        for s in ips {
            set.add(IPAddr::new(s.as_ref())?);
        }
        Ok(set)
    }

    /// `set(ips)`: replace the contents.
    pub fn set(&mut self, ips: impl IntoIterator<Item = IPAddr>) {
        self.members.clear();
        self.has_subnet = false;
        for ip in ips {
            self.add(ip);
        }
    }

    /// `add(ip)`.
    pub fn add(&mut self, ip: IPAddr) {
        self.has_subnet |= !ip.is_single();
        self.members.insert(Member(ip));
    }

    /// Number of distinct members.
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Whether the set has no members.
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// The members, in arbitrary order.
    pub fn iter(&self) -> impl Iterator<Item = &IPAddr> {
        self.members.iter().map(|m| &m.0)
    }

    /// Whether any member is a network or name (upstream `hasSubNet`
    /// truthiness).
    pub fn has_subnet(&self) -> bool {
        self.has_subnet
    }

    /// `ip in set` without DNS (see [`IPAddr::is_in_net`]).
    pub fn contains(&self, ip: &IPAddr) -> bool {
        self.contains_with(ip, |_| Vec::new())
    }

    /// `ip in set`: found directly, or inside any member network. `resolve`
    /// stands in for `DNSUtils.dnsToIp` for name members.
    pub fn contains_with(&self, ip: &IPAddr, mut resolve: impl FnMut(&str) -> Vec<IPAddr>) -> bool {
        // Cloning a valid address does not allocate (its `raw` is empty).
        self.members.contains(&Member(ip.clone()))
            || (self.has_subnet
                && self
                    .members
                    .iter()
                    .any(|m| m.0.contains_dyn(ip, &mut resolve)))
    }
}
