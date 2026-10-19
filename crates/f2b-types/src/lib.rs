//! Core shared types for Fast2Ban.

pub mod cache;
pub mod clock;
mod digits;
pub mod dns;
mod inet;
pub mod ipaddr;

pub use cache::TtlCache;
pub use clock::{Clock, FixedClock, SharedClock, SystemClock, fixed_clock, system_clock};
pub use dns::{DnsUtils, Ipv6Policy, Resolver, SystemResolver};
pub use ipaddr::{Cidr, Family, IPAddr, IPAddrError, IPAddrSet};

/// Upstream Fail2Ban version this build is wire/config compatible with.
///
/// Exposed to configs as the `fail2ban_version` interpolation variable and
/// returned by the `version` client command, as upstream does.
pub const UPSTREAM_COMPAT_VERSION: &str = "1.1.2.dev1";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compat_version_matches_vendored_upstream() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fail2ban/fail2ban/version.py"
        );
        let Ok(src) = std::fs::read_to_string(path) else {
            return; // upstream checkout not present (e.g. packaged build)
        };
        let line = src
            .lines()
            .find(|l| l.starts_with("version = "))
            .expect("version assignment in upstream version.py");
        assert_eq!(line, format!("version = \"{UPSTREAM_COMPAT_VERSION}\""));
    }
}
