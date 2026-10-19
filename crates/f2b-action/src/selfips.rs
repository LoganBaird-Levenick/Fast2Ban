//! Own IP addresses (`DNSUtils.getSelfIPs`) and hostname resolution used by
//! `ignoreself` and `ignoreip` entries that are host names.

use std::net::ToSocketAddrs;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use f2b_types::IPAddr;

/// How long the own-address set is reused (interface addresses may change).
const CACHE_TTL: Duration = Duration::from_secs(60);

type Cache = Mutex<Option<(Instant, Arc<Vec<IPAddr>>)>>;
static SELF_IPS: Cache = Mutex::new(None);

/// `DNSUtils.getSelfIPs()`: interface addresses plus the addresses of
/// `localhost` and of the host name, cached for a minute.
pub fn self_ips() -> Arc<Vec<IPAddr>> {
    let mut guard = SELF_IPS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((at, ips)) = guard.as_ref() {
        if at.elapsed() < CACHE_TTL {
            return ips.clone();
        }
    }
    let mut ips = interface_ips();
    for name in ["localhost", hostname().as_str()] {
        if name.is_empty() {
            continue;
        }
        for ip in resolve_host(name) {
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        }
    }
    let ips = Arc::new(ips);
    *guard = Some((Instant::now(), ips.clone()));
    ips
}

/// Resolve a host name to addresses (empty on failure).
pub fn resolve_host(host: &str) -> Vec<IPAddr> {
    let Ok(addrs) = (host, 0u16).to_socket_addrs() else {
        return Vec::new();
    };
    let mut out: Vec<IPAddr> = Vec::new();
    for sa in addrs {
        if let Ok(ip) = IPAddr::new(&sa.ip().to_string()) {
            if !out.contains(&ip) {
                out.push(ip);
            }
        }
    }
    out
}

fn hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: `buf` is valid for `buf.len()` bytes; gethostname NUL-terminates
    // or truncates within the buffer we pass.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if rc != 0 {
        return String::new();
    }
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

fn interface_ips() -> Vec<IPAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr};

    let mut out: Vec<IPAddr> = Vec::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: on success `head` points to a list that is released below with
    // `freeifaddrs`; nodes are only read while the list is alive.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return out;
    }
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is a node of the list returned by getifaddrs.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_addr.is_null() {
            continue;
        }
        // SAFETY: `ifa_addr` is non-null and points to a sockaddr whose
        // `sa_family` selects the concrete type read below.
        let text = unsafe {
            match i32::from((*ifa.ifa_addr).sa_family) {
                libc::AF_INET => {
                    let sin = &*ifa.ifa_addr.cast::<libc::sockaddr_in>();
                    Some(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)).to_string())
                }
                libc::AF_INET6 => {
                    let sin6 = &*ifa.ifa_addr.cast::<libc::sockaddr_in6>();
                    Some(Ipv6Addr::from(sin6.sin6_addr.s6_addr).to_string())
                }
                _ => None,
            }
        };
        if let Some(ip) = text.and_then(|t| IPAddr::new(&t).ok()) {
            if !out.contains(&ip) {
                out.push(ip);
            }
        }
    }
    // SAFETY: `head` came from a successful getifaddrs and is freed once.
    unsafe { libc::freeifaddrs(head) };
    out
}
