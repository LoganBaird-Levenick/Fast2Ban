//! Port of the resolution part of upstream `DNSUtils` (`ipdns.py`):
//! `dnsToIp`, `textToIp` and the IPv6-allowed switch, with name-to-IP caching.
//!
//! Resolution goes through the [`Resolver`] trait so tests (and the sample
//! harness, which never resolves) control it. [`SystemResolver`] uses the
//! platform `getaddrinfo`.

use std::io;
use std::net::{IpAddr, TcpListener, ToSocketAddrs};
use std::sync::Mutex;

use crate::cache::TtlCache;
use crate::clock::SharedClock;
use crate::ipaddr::{Cidr, IPAddr, search_ip};

/// Name resolution backend.
pub trait Resolver: std::fmt::Debug + Send + Sync {
    /// Addresses of `name` for the given family (`ipv6 == false`: IPv4).
    fn lookup(&self, name: &str, ipv6: bool) -> io::Result<Vec<IpAddr>>;
}

/// `getaddrinfo` based resolver.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn lookup(&self, name: &str, ipv6: bool) -> io::Result<Vec<IpAddr>> {
        Ok((name, 0)
            .to_socket_addrs()?
            .map(|a| a.ip())
            .filter(|ip| ip.is_ipv6() == ipv6)
            .collect())
    }
}

/// Whether to return IPv6 addresses from lookups (`DNSUtils._IPv6IsAllowed`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6Policy {
    /// Detect (`allowipv6 = auto`).
    Auto,
    Yes,
    No,
}

#[derive(Debug)]
pub struct DnsUtils {
    resolver: Box<dyn Resolver>,
    name_to_ip: Mutex<TtlCache<String, Vec<IPAddr>>>,
    ipv6: Mutex<(Ipv6Policy, Option<bool>)>,
}

impl DnsUtils {
    /// `CACHE_nameToIp = Cache(maxCount=1000, maxTime=5*60)`
    pub fn new(resolver: Box<dyn Resolver>, clock: SharedClock) -> Self {
        Self {
            resolver,
            name_to_ip: Mutex::new(TtlCache::new(1000, 300.0, clock)),
            ipv6: Mutex::new((Ipv6Policy::Auto, None)),
        }
    }

    pub fn system(clock: SharedClock) -> Self {
        Self::new(Box::new(SystemResolver), clock)
    }

    /// `DNSUtils.setIPv6IsAllowed`.
    pub fn set_ipv6_policy(&self, policy: Ipv6Policy) {
        if let Ok(mut g) = self.ipv6.lock() {
            *g = (policy, None);
        }
    }

    /// `DNSUtils.IPv6IsAllowed`: explicit setting, else detection (sysctl,
    /// falling back to binding an IPv6 socket). Undetectable counts as off
    /// (upstream then inspects interface addresses, a later phase).
    pub fn ipv6_is_allowed(&self) -> bool {
        let Ok(mut g) = self.ipv6.lock() else {
            return false;
        };
        match g.0 {
            Ipv6Policy::Yes => true,
            Ipv6Policy::No => false,
            Ipv6Policy::Auto => *g.1.get_or_insert_with(ipv6_supported_by_system),
        }
    }

    /// `DNSUtils.dnsToIp`: resolve a name (cached; failures cache as empty).
    pub fn dns_to_ip(&self, dns: &str) -> Vec<IPAddr> {
        if let Ok(mut c) = self.name_to_ip.lock() {
            if let Some(v) = c.get(&dns.to_owned()) {
                return v.clone();
            }
        }
        let mut ips: Vec<IPAddr> = Vec::new();
        let families: &[bool] = if self.ipv6_is_allowed() {
            &[false, true]
        } else {
            &[false]
        };
        for &v6 in families {
            let Ok(found) = self.resolver.lookup(dns, v6) else {
                continue;
            };
            for a in found {
                let cidr = if v6 { Cidr::Inet6 } else { Cidr::Inet4 };
                if let Ok(ip) = IPAddr::with_cidr(&a.to_string(), cidr) {
                    if ip.is_valid() && !ips.contains(&ip) {
                        ips.push(ip);
                    }
                }
            }
        }
        if let Ok(mut c) = self.name_to_ip.lock() {
            c.set(dns.to_owned(), ips.clone());
        }
        ips
    }

    /// `DNSUtils.textToIp`: the IP in `text`, else (for `use_dns` `yes` /
    /// `warn`) the addresses its DNS name resolves to.
    pub fn text_to_ip(&self, text: &str, use_dns: &str) -> Vec<IPAddr> {
        let mut list: Vec<IPAddr> = Vec::new();
        if let Some(plain) = search_ip(text) {
            if let Ok(ip) = IPAddr::new(plain) {
                if ip.is_valid() {
                    list.push(ip);
                }
            }
        }
        if matches!(use_dns, "yes" | "warn") && list.is_empty() {
            list = self.dns_to_ip(text);
        }
        list
    }
}

fn ipv6_supported_by_system() -> bool {
    if let Ok(s) = std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/disable_ipv6") {
        if let Ok(v) = s.trim().parse::<i64>() {
            return v == 0;
        }
    }
    TcpListener::bind("[::]:0").is_ok()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::clock::fixed_clock;

    #[derive(Debug, Default)]
    struct Table(HashMap<&'static str, Vec<IpAddr>>);

    impl Resolver for Table {
        fn lookup(&self, name: &str, ipv6: bool) -> io::Result<Vec<IpAddr>> {
            self.0
                .get(name)
                .map(|v| v.iter().copied().filter(|a| a.is_ipv6() == ipv6).collect())
                .ok_or_else(|| io::Error::other("nxdomain"))
        }
    }

    fn dns(ipv6: Ipv6Policy) -> DnsUtils {
        let mut t = Table::default();
        t.0.insert(
            "host.example",
            vec!["192.0.2.7".parse().unwrap(), "2001:db8::7".parse().unwrap()],
        );
        let d = DnsUtils::new(Box::new(t), fixed_clock(0.0));
        d.set_ipv6_policy(ipv6);
        d
    }

    #[test]
    fn plain_ip_wins_over_dns_and_dns_is_policy_gated() {
        let d = dns(Ipv6Policy::Yes);
        let ips = d.text_to_ip("192.0.2.1", "yes");
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0].ntoa(), "192.0.2.1");
        assert!(d.text_to_ip("host.example", "no").is_empty());
        assert!(d.text_to_ip("host.example", "raw").is_empty());
        assert_eq!(d.text_to_ip("host.example", "warn").len(), 2);
    }

    #[test]
    fn ipv6_results_dropped_when_not_allowed() {
        let d = dns(Ipv6Policy::No);
        let ips = d.text_to_ip("host.example", "yes");
        assert_eq!(ips.len(), 1);
        assert!(ips[0].is_ipv4());
    }

    #[test]
    fn unresolvable_names_yield_nothing() {
        assert!(
            dns(Ipv6Policy::Yes)
                .text_to_ip("nope.example", "yes")
                .is_empty()
        );
    }
}
