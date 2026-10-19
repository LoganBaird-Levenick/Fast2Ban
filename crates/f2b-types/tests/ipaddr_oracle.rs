//! Oracle tests: every expected value in `testdata/f2b-types/*.json` was
//! produced by upstream `fail2ban/server/ipdns.py`
//! (`tools/gen_f2b_types_fixtures.py`); nothing is hand-written.

mod common;

use common::{Json, load};
use f2b_types::ipaddr::{
    IP_4_6_CRE, IP_4_RE, IP_6_RE, IP_W_CIDR_CRE, file_ignore_ip_name, search_ip,
};
use f2b_types::{Cidr, Family, IPAddr, IPAddrError, IPAddrSet};

/// Collects mismatches so one run reports many of them.
#[derive(Default)]
struct Report(Vec<String>);

impl Report {
    fn check<T: PartialEq + std::fmt::Debug>(&mut self, what: &str, got: T, want: T) {
        if got != want {
            self.0.push(format!("{what}: got {got:?}, want {want:?}"));
        }
    }

    fn finish(self, total: usize) {
        assert!(
            self.0.is_empty(),
            "{} mismatches over {total} checks; first ones:\n{}",
            self.0.len(),
            self.0
                .iter()
                .take(30)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}

fn cidr_of(spec: &Json) -> Cidr {
    match spec {
        Json::Int(p) => Cidr::Prefix(u32::try_from(*p).unwrap()),
        Json::Str(s) => match s.as_str() {
            "unspec" => Cidr::Unspec,
            "raw" => Cidr::Raw,
            "inet4" => Cidr::Inet4,
            "inet6" => Cidr::Inet6,
            "none" => Cidr::NoMask,
            other => panic!("unknown cidr spec {other:?}"),
        },
        other => panic!("bad cidr spec {other:?}"),
    }
}

fn family_name(f: Family) -> &'static str {
    match f {
        Family::Raw => "raw",
        Family::Unspec => "unspec",
        Family::Inet4 => "inet4",
        Family::Inet6 => "inet6",
    }
}

/// `"ValueError: msg"` expected by the oracle for a raised error.
fn py_error(e: &IPAddrError) -> String {
    format!("ValueError: {e}")
}

#[test]
fn construct_matches_upstream() {
    let cases = load("ipaddr_construct.json");
    let mut rep = Report::default();
    let mut n = 0;
    for case in cases.arr() {
        let input = case.field("in").str();
        let cidr = cidr_of(case.field("cidr"));
        let tag = format!("{input:?} / {:?}", case.field("cidr"));
        let r = IPAddr::with_cidr(input, cidr);
        if let Some(e) = case.get("error") {
            n += 1;
            rep.check(
                &format!("{tag} error"),
                r.as_ref().map(|_| ()).map_err(py_error),
                Err(e.str().to_owned()),
            );
            continue;
        }
        let ip = match r {
            Ok(ip) => ip,
            Err(e) => {
                rep.0.push(format!("{tag}: unexpected error {e}"));
                continue;
            }
        };
        n += 1;
        rep.check(
            &format!("{tag} addr"),
            format!("{:x}", ip.addr()),
            case.field("addr").str().to_owned(),
        );
        rep.check(
            &format!("{tag} family"),
            family_name(ip.family()),
            case.field("family").str(),
        );
        rep.check(
            &format!("{tag} familyStr"),
            ip.family_str(),
            case.field("familyStr").opt_str(),
        );
        rep.check(
            &format!("{tag} hexdump"),
            ip.hexdump(),
            case.field("hexdump").str().to_owned(),
        );
        rep.check(
            &format!("{tag} instanceType"),
            ip.instance_type(),
            case.field("instanceType").str(),
        );
        rep.check(
            &format!("{tag} isIPv4"),
            ip.is_ipv4(),
            case.field("isIPv4").bool(),
        );
        rep.check(
            &format!("{tag} isIPv6"),
            ip.is_ipv6(),
            case.field("isIPv6").bool(),
        );
        rep.check(
            &format!("{tag} isSingle"),
            ip.is_single(),
            case.field("isSingle").bool(),
        );
        rep.check(
            &format!("{tag} isValid"),
            ip.is_valid(),
            case.field("isValid").bool(),
        );
        let mp = case.field("maskplen");
        let got_mp = ip.maskplen().map(i64::from).map_err(|e| py_error(&e));
        let want_mp = match mp.get("error") {
            Some(e) => Err(e.str().to_owned()),
            None => Ok(mp.int()),
        };
        rep.check(&format!("{tag} maskplen"), got_mp, want_mp);
        rep.check(
            &format!("{tag} ntoa"),
            ip.ntoa().into_owned(),
            case.field("ntoa").str().to_owned(),
        );
        rep.check(
            &format!("{tag} str"),
            ip.to_string(),
            case.field("str").str().to_owned(),
        );
        // Rust saturates prefix lengths at u32::MAX (documented deviation).
        rep.check(
            &format!("{tag} plen"),
            i64::from(ip.plen()),
            case.field("plen").int().min(i64::from(u32::MAX)),
        );
        rep.check(
            &format!("{tag} ptr"),
            ip.get_ptr(None),
            case.field("ptr").str().to_owned(),
        );
        rep.check(
            &format!("{tag} ptr_empty"),
            ip.get_ptr(Some("")),
            case.field("ptr_empty").str().to_owned(),
        );
        rep.check(
            &format!("{tag} ptr_x"),
            ip.get_ptr(Some("x.test.")),
            case.field("ptr_x").str().to_owned(),
        );
        if let Some(raw) = case.field("raw").opt_str() {
            rep.check(&format!("{tag} raw"), ip.raw_text(), raw);
        }
    }
    assert!(n > 1000, "fixture too small: {n}");
    rep.finish(n);
}

#[test]
fn parse_from_str_is_unspec_constructor() {
    let ip: IPAddr = "192.0.2.0/24".parse().unwrap();
    assert_eq!(ip, IPAddr::new("192.0.2.0/24").unwrap());
    assert!("1.2.3.4\0".parse::<IPAddr>().is_err());
}

fn resolver(dns: &Json) -> impl Fn(&str) -> Vec<IPAddr> + '_ {
    move |name: &str| match dns.get(name) {
        Some(list) => list
            .arr()
            .iter()
            .map(|s| IPAddr::new(s.str()).unwrap())
            .collect(),
        None => Vec::new(),
    }
}

#[test]
fn pairs_match_upstream() {
    let fx = load("ipaddr_pairs.json");
    let objs: Vec<IPAddr> = fx
        .field("objects")
        .arr()
        .iter()
        .map(|o| IPAddr::with_cidr(o.field("s").str(), cidr_of(o.field("c"))).unwrap())
        .collect();
    let dns = fx.field("dns");
    let mut rep = Report::default();
    let mut n = 0;
    let matrix = |name: &str| -> Vec<Vec<bool>> {
        fx.field(name)
            .arr()
            .iter()
            .map(|row| row.str().bytes().map(|b| b == b'1').collect())
            .collect()
    };
    let mut check_matrix = |name: &str, f: &dyn Fn(&IPAddr, &IPAddr) -> bool| {
        let m = matrix(name);
        for (i, a) in objs.iter().enumerate() {
            for (j, b) in objs.iter().enumerate() {
                n += 1;
                rep.check(
                    &format!("{name}[{a:?} ({i}), {b:?} ({j})]"),
                    f(a, b),
                    m[i][j],
                );
            }
        }
    };
    check_matrix("eq", &|a, b| a == b);
    check_matrix("lt", &|a, b| a.lt(b));
    check_matrix("in_net_dns", &|a, b| a.is_in_net_with(b, resolver(dns)));
    check_matrix("in_dns", &|a, b| b.contains_with(a, resolver(dns)));
    check_matrix("contains_dns", &|a, b| b.contains_with(a, resolver(dns)));
    check_matrix("in_net_nodns", &|a, b| a.is_in_net(b));
    check_matrix("contains_nodns", &|a, b| b.contains(a));
    for e in fx.field("eq_str").arr() {
        let [i, s, want] = e.arr() else {
            panic!("bad eq_str row")
        };
        let a = &objs[usize::try_from(i.int()).unwrap()];
        let got = a.eq_str(s.str()).map_err(|e| py_error(&e));
        let want = match want {
            Json::Bool(b) => Ok(*b),
            other => Err(other.field("error").str().to_owned()),
        };
        n += 1;
        rep.check(&format!("eq_str[{a:?}, {:?}]", s.str()), got, want);
    }
    rep.finish(n);
}

#[test]
fn eq_is_consistent_with_hash() {
    use std::hash::BuildHasher;
    let fx = load("ipaddr_pairs.json");
    let objs: Vec<IPAddr> = fx
        .field("objects")
        .arr()
        .iter()
        .map(|o| IPAddr::with_cidr(o.field("s").str(), cidr_of(o.field("c"))).unwrap())
        .collect();
    let rs = std::hash::RandomState::new();
    for a in &objs {
        for b in &objs {
            if a == b {
                assert_eq!(
                    rs.hash_one(a),
                    rs.hash_one(b),
                    "{a:?} == {b:?} but hashes differ"
                );
            }
        }
    }
}

#[test]
fn sets_match_upstream() {
    let fx = load("ipaddr_sets.json");
    let dns = fx.field("dns");
    let probes: Vec<IPAddr> = fx
        .field("probes")
        .arr()
        .iter()
        .map(|p| IPAddr::new(p.str()).unwrap())
        .collect();
    let mut rep = Report::default();
    let mut n = 0;
    for case in fx.field("cases").arr() {
        let init: Vec<&str> = case.field("init").arr().iter().map(Json::str).collect();
        let adds: Vec<&str> = case.field("add").arr().iter().map(Json::str).collect();
        let tag = format!("{init:?} + {adds:?}");
        let built = (|| {
            let mut set = IPAddrSet::parse(init.iter().copied())?;
            for a in &adds {
                set.add(IPAddr::new(a)?);
            }
            Ok::<_, IPAddrError>(set)
        })();
        if let Some(e) = case.get("error") {
            n += 1;
            rep.check(
                &format!("{tag} error"),
                built.map(|_| ()).map_err(|e| py_error(&e)),
                Err(e.str().to_owned()),
            );
            continue;
        }
        let set = match built {
            Ok(s) => s,
            Err(e) => {
                rep.0.push(format!("{tag}: unexpected error {e}"));
                continue;
            }
        };
        n += 1;
        rep.check(
            &format!("{tag} len"),
            i64::try_from(set.len()).unwrap(),
            case.field("len").int(),
        );
        rep.check(
            &format!("{tag} has_subnet"),
            set.has_subnet(),
            case.field("has_subnet").bool(),
        );
        rep.check(
            &format!("{tag} instanceType"),
            set.instance_type(),
            case.field("instanceType").str(),
        );
        let got_dns: String = probes
            .iter()
            .map(|p| {
                if set.contains_with(p, resolver(dns)) {
                    '1'
                } else {
                    '0'
                }
            })
            .collect();
        let got_nodns: String = probes
            .iter()
            .map(|p| if set.contains(p) { '1' } else { '0' })
            .collect();
        rep.check(
            &format!("{tag} dns"),
            got_dns,
            case.field("dns").str().to_owned(),
        );
        rep.check(
            &format!("{tag} nodns"),
            got_nodns,
            case.field("nodns").str().to_owned(),
        );
    }
    rep.finish(n);
}

#[test]
fn search_ip_matches_upstream() {
    let cases = load("ipaddr_search.json");
    let mut rep = Report::default();
    for c in cases.arr() {
        let [text, want] = c.arr() else {
            panic!("bad row")
        };
        rep.check(
            &format!("search_ip({:?})", text.str()),
            search_ip(text.str()),
            want.opt_str(),
        );
    }
    rep.finish(cases.arr().len());
}

#[test]
fn constants_and_helpers_match_upstream() {
    let fx = load("ipaddr_misc.json");
    let consts = fx.field("consts");
    assert_eq!(IP_4_RE, consts.field("IP_4_RE").str());
    assert_eq!(IP_6_RE, consts.field("IP_6_RE").str());
    assert_eq!(IP_4_6_CRE, consts.field("IP_4_6_CRE").str());
    assert_eq!(IP_W_CIDR_CRE, consts.field("IP_W_CIDR_CRE").str());

    let mut rep = Report::default();
    for c in fx.field("masktoplen").arr() {
        let [mask, want] = c.arr() else {
            panic!("bad row")
        };
        let got = IPAddr::masktoplen(mask.str())
            .map(i64::from)
            .map_err(|e| py_error(&e));
        let want = match want.get("error") {
            Some(e) => Err(e.str().to_owned()),
            None => Ok(want.int()),
        };
        rep.check(&format!("masktoplen({:?})", mask.str()), got, want);
    }
    for c in fx.field("file_ign").arr() {
        let [s, want] = c.arr() else {
            panic!("bad row")
        };
        rep.check(
            &format!("file_ignore_ip_name({:?})", s.str()),
            file_ignore_ip_name(s.str()),
            want.opt_str(),
        );
    }
    let compat = fx.field("ip6_4compat");
    let c = &IPAddr::IP6_4COMPAT;
    rep.check(
        "IP6_4COMPAT addr",
        format!("{:x}", c.addr()),
        compat.field("addr").str().to_owned(),
    );
    rep.check(
        "IP6_4COMPAT plen",
        i64::from(c.plen()),
        compat.field("plen").int(),
    );
    rep.check(
        "IP6_4COMPAT ntoa",
        c.ntoa().into_owned(),
        compat.field("ntoa").str().to_owned(),
    );
    rep.check(
        "IP6_4COMPAT family",
        family_name(c.family()),
        compat.field("family").str(),
    );
    rep.check(
        "IP6_4COMPAT == IPAddr(\"::ffff:0:0\", 96)",
        *c == IPAddr::with_cidr("::ffff:0:0", Cidr::Prefix(96)).unwrap(),
        true,
    );
    rep.finish(fx.field("masktoplen").arr().len() + fx.field("file_ign").arr().len() + 5);
}

#[test]
fn ordering_is_upstream_non_total() {
    // `family < family || addr < addr`: a larger family with a smaller address
    // still compares "less" (upstream quirk), in both directions.
    let v4 = IPAddr::new("255.255.255.255").unwrap();
    let v6 = IPAddr::new("::1").unwrap();
    assert!(v4.lt(&v6));
    assert!(v6.lt(&v4));
    assert!(!v4.lt(&v4));
    // two raw objects are always equal, whatever their text
    assert_eq!(IPAddr::raw("a"), IPAddr::raw("b"));
    assert_ne!(IPAddr::new("a").unwrap(), IPAddr::new("b").unwrap());
}
