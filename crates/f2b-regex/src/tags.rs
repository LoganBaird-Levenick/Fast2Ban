//! Tag expansion of `failregex.py`: `<HOST>`, `<ADDR>`, `<F-ID/>`, `<F-NAME>...`
//! (`Regex._resolveHostTag`), and the global-to-local flag rewrite
//! (`R_GLOB2LOCFLAGS`).

use std::sync::LazyLock;

use f2b_helpers::pychar::is_word;
use f2b_types::ipaddr::{IP_4_RE, IP_6_RE};

/// The static expansions of `R_HOST` (`failregex.py`).
struct HostTags {
    ip4: String,
    ip6: String,
    addr: String,
    host: String,
    subnet: String,
}

const R_DNS: &str = r"(?P<dns>[\w\-.^_]*\w)";
const R_CIDR: &str = r"(?P<cidr>\d+)";

static HOST_TAGS: LazyLock<HostTags> = LazyLock::new(|| {
    let ip4 = format!("(?:::f{{4,6}}:)?(?P<ip4>{IP_4_RE})");
    let ip6 = format!("(?P<ip6>{IP_6_RE})");
    let addr = format!(r"\[?(?:{ip4}|{ip6})\]?");
    let host = format!("(?:{addr}|{R_DNS})");
    let subnet = format!(r"\[?(?:{ip4}|{ip6})(?:/{R_CIDR})?\]?");
    HostTags {
        ip4,
        ip6,
        addr,
        host,
        subnet,
    }
});

/// How `<HOST>` expands, `useDns` of upstream's `Regex._resolveHostTag`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum UseDns {
    /// `yes`: `<HOST>` is address or DNS name.
    #[default]
    Yes,
    /// `warn` (upstream's default): same as `yes` for the pattern.
    Warn,
    /// `no`: `<HOST>` expands to `<ADDR>` (no DNS group).
    No,
    /// `raw`: same as `yes` for the pattern.
    Raw,
}

impl UseDns {
    /// Maps a `usedns` setting; anything except `no` selects `<HOST>` like
    /// upstream's `useDns not in ("no",)`.
    #[must_use]
    pub fn from_setting(value: &str) -> UseDns {
        match value {
            "no" => UseDns::No,
            "warn" => UseDns::Warn,
            "raw" => UseDns::Raw,
            _ => UseDns::Yes,
        }
    }
}

/// `R_MAP` / `mapTag2Opt`: group names for customisable tags.
#[must_use]
pub fn map_tag_to_option(tag: &str) -> String {
    let lower = tag.to_lowercase();
    match lower.as_str() {
        "id" => "fid".to_owned(),
        "port" => "fport".to_owned(),
        _ => lower,
    }
}

fn static_tag(tn: &str) -> Option<&'static str> {
    Some(match tn {
        "IP4" | "F-IP4/" => &HOST_TAGS.ip4,
        "IP6" | "F-IP6/" => &HOST_TAGS.ip6,
        "ADDR" | "F-ADDR/" => &HOST_TAGS.addr,
        "CIDR" | "F-CIDR/" => R_CIDR,
        "SUBNET" | "F-SUBNET/" => &HOST_TAGS.subnet,
        "DNS" | "F-DNS/" => R_DNS,
        "F-ID/" => r"(?P<fid>\S+)",
        "F-PORT/" => r"(?P<fport>\w+)",
        _ => return None,
    })
}

/// `FCUSTNAME_CRE`: `^(/?)F-([A-Z0-9_\-]+)$` -> (is_close, name).
fn custom_name(tn: &str) -> Option<(bool, &str)> {
    let (close, rest) = match tn.strip_prefix('/') {
        Some(r) => (true, r),
        None => (false, tn),
    };
    let name = rest.strip_prefix("F-")?;
    if !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
    {
        Some((close, name))
    } else {
        None
    }
}

/// `Regex._resolveHostTag(regex, useDns)`: replaces the Fail2Ban tags.
///
/// `FTAG_CRE` (`</?[\w\-]+/?>`) finds the tags; `<HOST>`, `<SKIPLINES>` and the
/// static tags are replaced, `<F-NAME>` / `</F-NAME>` become `(?P<name>` / `)`
/// (a closing tag only if its opening tag was seen), everything else is left.
#[must_use]
pub fn resolve_host_tag(regex: &str, use_dns: UseDns) -> String {
    let mut out = String::with_capacity(regex.len() + 64);
    let mut open_tags: Vec<&str> = Vec::new();
    let mut skiplines = 0usize;
    let bytes = regex.as_bytes();
    let mut i = 0;
    let mut copied = 0;
    while i < bytes.len() {
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }
        let Some(end) = tag_end(regex, i) else {
            i += 1;
            continue;
        };
        let tag = &regex[i..end];
        let tn = &tag[1..tag.len() - 1];
        let replacement: Option<std::borrow::Cow<'_, str>> = if tn == "HOST" {
            Some(
                match use_dns {
                    UseDns::No => &HOST_TAGS.addr,
                    _ => &HOST_TAGS.host,
                }
                .into(),
            )
        } else if tn == "SKIPLINES" {
            let n = skiplines;
            skiplines += 1;
            Some(format!("\\n(?P<skiplines{n}>(?:(?:.*\\n)*?))").into())
        } else if let Some(s) = static_tag(tn) {
            Some(s.into())
        } else if let Some((close, name)) = custom_name(tn) {
            if close {
                if open_tags.contains(&name) {
                    Some(")".into())
                } else {
                    None
                }
            } else {
                if !open_tags.contains(&name) {
                    open_tags.push(name);
                }
                Some(format!("(?P<{}>", map_tag_to_option(name)).into())
            }
        } else {
            None
        };
        if let Some(r) = replacement {
            out.push_str(&regex[copied..i]);
            out.push_str(&r);
            copied = end;
        }
        i = end;
    }
    out.push_str(&regex[copied..]);
    out
}

/// End of the `FTAG_CRE` match starting at `start` (a `<`), if any.
fn tag_end(s: &str, start: usize) -> Option<usize> {
    let mut chars = s[start + 1..].char_indices().peekable();
    let mut pos = start + 1;
    if let Some(&(_, '/')) = chars.peek() {
        chars.next();
        pos += 1;
    }
    let mut name_len = 0;
    while let Some(&(_, c)) = chars.peek() {
        if is_word(c) || c == '-' {
            chars.next();
            pos += c.len_utf8();
            name_len += 1;
        } else {
            break;
        }
    }
    if name_len == 0 {
        return None;
    }
    if let Some(&(_, '/')) = chars.peek() {
        chars.next();
        pos += 1;
    }
    match chars.next() {
        Some((_, '>')) => Some(pos + 1),
        _ => None,
    }
}

/// `R_GLOB2LOCFLAGS`: `re.sub(r"(?<!\\)\((?:\?:)?(\(\?[a-z]+)\)", r"\1:")`
/// rewrites `((?i)x)` and `(?:(?i)x)` to the scoped `(?i:x)`.
#[must_use]
pub fn global_to_local_flags(regex: &str) -> String {
    let b = regex.as_bytes();
    let mut out = String::with_capacity(regex.len());
    let mut copied = 0;
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'(' && (i == 0 || b[i - 1] != b'\\') {
            let mut j = i + 1;
            if b[j..].starts_with(b"?:") {
                j += 2;
            }
            // group 1: `(?` + one or more [a-z]
            if b[j..].starts_with(b"(?") {
                let flags_start = j + 2;
                let mut k = flags_start;
                while k < b.len() && b[k].is_ascii_lowercase() {
                    k += 1;
                }
                if k > flags_start && k < b.len() && b[k] == b')' {
                    out.push_str(&regex[copied..i]);
                    out.push_str(&regex[j..k]);
                    out.push(':');
                    copied = k + 1;
                    i = k + 1;
                    continue;
                }
            }
        }
        i += 1;
    }
    out.push_str(&regex[copied..]);
    out
}
