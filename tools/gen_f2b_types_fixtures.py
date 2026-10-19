#!/usr/bin/env python3
"""Generate oracle fixtures for crates/f2b-types (IPAddr / IPAddrSet) from
the real upstream implementation in fail2ban/server/ipdns.py.

Usage (from the repository root):

    PYTHONPATH=fail2ban python3 tools/gen_f2b_types_fixtures.py

Writes testdata/f2b-types/*.json (sorted keys, deterministic; running it twice
yields byte-identical files). Every expected value is produced by upstream;
nothing is hand-written. No network is used: DNSUtils.dnsToIp is replaced by a
fixed table so that `isInNet` against host names is deterministic.
"""
import json
import os
import random
import re
import socket
import sys
import unicodedata

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "fail2ban"))

from fail2ban.server.ipdns import DNSUtils, FileIPAddrSet, IPAddr, IPAddrSet  # noqa: E402

OUT = os.path.join(ROOT, "testdata", "f2b-types")

# --------------------------------------------------------------------------
# DNS stand-in (no network): name -> list of IP strings, anything else -> none.
# --------------------------------------------------------------------------
DNS_TABLE = {
    "test-name-a": ["192.0.2.1", "2001:db8::1", "198.51.100.0/24", "10.0.0.1"],
    "fail2ban.org": ["145.239.69.22", "2001:41d0:303:3d16::1"],
    "localhost": ["127.0.0.1", "::1"],
    "some/path/as/id": ["203.0.113.9"],
}
_dns_enabled = [True]


def _fake_dns_to_ip(name):
    if not _dns_enabled[0]:
        return set()
    return set(IPAddr(s) for s in DNS_TABLE.get(name, ()))


DNSUtils.dnsToIp = staticmethod(_fake_dns_to_ip)


class _NoCache(object):
    """Upstream memoises IPAddr objects by (text, cidr) *after* bracket/prefix
    wrapping, so e.g. IPAddr("[[::1]]") poisons the entry for "[::1]" and the
    result of IPAddr("[::1]") then depends on call history (an upstream bug).
    The Rust port is history-independent, so the oracle must be too: every
    construction is cold."""

    def get(self, *a, **k):
        return None

    def set(self, *a, **k):
        pass

    def unset(self, *a, **k):
        pass

    def clear(self):
        pass


IPAddr.CACHE_OBJ = _NoCache()


def forbid_network(*a, **k):  # any accidental resolver call is a generator bug
    raise AssertionError("network access attempted")


socket.getaddrinfo = forbid_network
socket.gethostbyaddr = forbid_network

FAMILY = {
    socket.AF_INET: "inet4",
    socket.AF_INET6: "inet6",
    socket.AF_UNSPEC: "unspec",
    IPAddr.CIDR_RAW: "raw",
}
CIDR_SPECS = {
    "unspec": IPAddr.CIDR_UNSPEC,
    "raw": IPAddr.CIDR_RAW,
    "inet4": IPAddr.FAM_IPv4,
    "inet6": IPAddr.FAM_IPv6,
    "none": None,
}


def make(s, c="unspec"):
    cidr = CIDR_SPECS[c] if isinstance(c, str) else c
    return IPAddr(s, cidr)


def err(e):
    return "%s: %s" % (type(e).__name__, e)


def tryit(fn):
    try:
        return fn()
    except Exception as e:  # noqa: BLE001 - recorded as the expected outcome
        return {"error": err(e)}


def describe(ip):
    d = {
        "addr": "%x" % ip.addr,
        "family": FAMILY[ip.family],
        "familyStr": ip.familyStr,
        "hexdump": ip.hexdump,
        "instanceType": ip.instanceType,
        "isIPv4": ip.isIPv4,
        "isIPv6": ip.isIPv6,
        "isSingle": bool(ip.isSingle),
        "isValid": ip.isValid,
        "maskplen": tryit(lambda: ip.maskplen),
        "ntoa": ip.ntoa,
        "plen": ip.plen,
        "ptr": ip.getPTR(),
        "ptr_empty": ip.getPTR(""),
        "ptr_x": ip.getPTR("x.test."),
        "raw": ip.raw if not (ip.isIPv4 or ip.isIPv6) else None,
        "str": str(ip),
    }
    return d


# --------------------------------------------------------------------------
# Inputs
# --------------------------------------------------------------------------
V4_BASE = [
    "0.0.0.0", "255.255.255.255", "1.2.3.4", "127.0.0.1", "192.0.2.1", "192.0.2.255",
    "10.0.0.0", "10.0.0.1", "93.184.0.1", "192.168.1.0", "8.8.8.8", "100.64.0.1",
    "224.0.0.1", "169.254.169.254", "172.16.0.1",
    # leading zeros, ranges, wrong part counts
    "192.030.0.6", "192.0.2.01", "01.2.3.4", "1.2.3.04", "00.0.0.0", "0.0.0.00", "001.1.1.1",
    "256.1.1.1", "1.256.1.1", "1.1.256.1", "1.1.1.256", "999.999.999.999", "1000.1.1.1",
    "1.2.3", "1.2", "1", "1.2.3.4.5", "1.2.3.", ".1.2.3", "1..2.3", "1.2.3.4.", "...",
    "1.2.3.-4", "-1.2.3.4", "+1.2.3.4", "0x1.2.3.4", "1.2.3.0x4", "1e1.2.3.4", "1.2.3.4a",
    "a.b.c.d", "1,2,3,4", "1.2.3,4",
    # whitespace / line ends / NUL
    " 1.2.3.4", "1.2.3.4 ", "1.2 .3.4", "1.2.3.4\n", "1.2.3.4\r\n", "1.2.3.4\n\n", "\n1.2.3.4",
    "1.2.3.4\t", "1.2.3.4\x00", "1.2.3.\x004", "\x00",
    # ports, zones, scheme
    "1.2.3.4:80", "1.2.3.4%eth0", "http://1.2.3.4", "1.2.3.4/", "[1.2.3.4]", "[1.2.3.4]:80",
    # Unicode decimal digits (\d in a str pattern) and look-alikes
    "\u0661.\u0662.\u0663.\u0664", "1.2.3.\u0664", "\uff11.\uff12.\uff13.\uff14",
    "1.2.3.4\u00a0", "\u0661\u0662\u0663.1.1.1", "\u00b2.1.1.1", "1.2.3.\u2464",
]
V4_CIDR = [
    "192.0.2.0/24", "192.0.2.1/24", "93.184.0.1/24", "10.0.0.0/8", "10.0.0.1/8", "0.0.0.0/0",
    "1.2.3.4/0", "1.2.3.4/1", "1.2.3.4/31", "1.2.3.4/32", "1.2.3.4/33", "1.2.3.4/64",
    "1.2.3.4/99999", "1.2.3.4/00024", "1.2.3.4/0", "1.2.3.4/4294967295", "1.2.3.4/4294967296",
    "1.2.3.4/99999999999999999999999999999999999999999999999999",
    "127.0.0.1/8", "192.168.0.0/24", "192.168.0.1/24",
    "1.2.3.4/", "/24", "1.2.3.4/-1", "1.2.3.4/+24", "1.2.3.4/24 ", "1.2.3.4/24\n", "1.2.3.4/24\r\n",
    "1.2.3.4/ 24", " 1.2.3.4/24", "1.2.3.4/24x", "1.2.3.4/2 4", "1.2.3.4/24/24", "1.2.3.4//24",
    "1.2.3.4/\u0662\u0664", "1.2.3.4/\uff12\uff14", "1.2.3.4/\u00b2", "\u0661.2.3.4/24",
    "1.2.3.4/path", "other-path/24", "some/path/as/id", "1.2.3.4/24/", "1/24", "1.2.3/24",
    "256.1.1.1/24", "999.1.1.1/24", "01.2.3.4/24", "1.2.3.4\x00/24", "1.2.3.4/24\x00",
    "[1.2.3.4/24]", "[1.2.3.4]/24", "1.2.3.4/[24]",
    # netmask forms
    "192.0.2.0/255.255.255.0", "192.168.1.0/255.255.255.128", "93.184.0.1/255.255.255.255",
    "192.0.2.1/255.255.255.0", "10.0.0.0/255.0.0.0", "10.0.0.0/0.0.0.0", "1.2.3.4/255.255.255.254",
    "1.2.3.4/255.255.255.252", "1.2.3.4/128.0.0.0", "1.2.3.4/192.0.0.0", "1.2.3.4/255.255.255.255",
    "1.2.3.4/255.0.255.0", "1.2.3.4/255.255.0.255", "1.2.3.4/0.255.255.255", "1.2.3.4/255.255.255.1",
    "1.2.3.4/1.1.1.1", "1.2.3.4/0.0.0.1", "1.2.3.4/127.0.0.0", "1.2.3.4/255.255.255.256",
    "1.2.3.4/999.999.999.999", "1.2.3.4/1.2.3", "1.2.3.4/1.2.3.4.5", "1.2.3.4/255.255.255.0\n",
    "1.2.3.4/255.255.255.0 ", "1.2.3.4/255.255.255.00", "1.2.3.4/255.255.255.000",
    "1.2.3.4/\u0662\u0665\u0665.255.255.0",
    # v6 mask on a v4 address and vice versa
    "1.2.3.4/ffff::", "1.2.3.4/::", "1.2.3.4/::1", "1.2.3.4/ffff:ffff::", "1.2.3.4/::ffff:0:0",
    "1.2.3.4/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "1.2.3.4/ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe",
    "1.2.3.4/::ffff:ffff", "1.2.3.4/::ffff:ff00", "1.2.3.4/0:0:0:0:0:0:0:0",
    "2001:db8::/1.2.3.4", "2001:db8::/255.255.255.0", "::/255.255.255.255",
]
V6_BASE = [
    "::", "::1", "1::", "::2", "1::2", "fe80::1", "2001:db8::1", "2001:DB8::", "2001:db8::",
    "2001:0db8:0000:0000:0000:0000:0000:0001", "2001:0db8:0000:0000:0000:0000:0000:0000",
    "2606:2800:220:1:248:1893:25c8:1946", "2606:2800:220:1:248:1893::", "2606:2800:220:1:248:1893:0:0",
    "1:2:3:4:5:6:7:8", "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF", "0:0:0:0:0:0:0:0", "0:0:0:0:0:0:0:1",
    "1:0:0:2:0:0:0:3", "1:0:0:0:2:0:0:3", "1:0:0:2:0:0:3:4", "0:0:1:0:0:0:0:0", "1:2:0:0:3:0:0:4",
    "2001:db8:0:0:1:0:0:1", "0:1:2:3:4:5:6:7", "1:2:3:4:5:6:7:0",
    "2001:db8::0:1", "::ffff", "::ffff:0", "::ffff:ffff", "::1:0", "::1:2", "0::0", "00::00",
    # v4-mapped / compatible / embedded v4
    "::ffff:1.2.3.4", "::FFFF:1.2.3.4", "::ffff:192.0.2.1", "::ffff:10.2.2.1", "::ffff:0.0.0.0",
    "::ffff:255.255.255.255", "::ffff:0:0", "::ffff:0:1", "::ffff:1:2", "0:0:0:0:0:ffff:1.2.3.4",
    "0:0:0:0:0:ffff:102:304", "::ffff:1.2.3.04", "::ffff:1.2.3", "::ffff:1.2.3.4.5", "::ffff:256.1.1.1",
    "::1.2.3.4", "::0.0.0.1", "::0.0.0.2", "::1.2.3.4:5", "::fffe:1.2.3.4", "::1:ffff:1.2.3.4",
    "1::1.2.3.4", "1:2:3:4:5:6:1.2.3.4", "1:2:3:4:5:6:7:1.2.3.4", "1:2:3:4:5:1.2.3.4", "1:2:3:4:5::1.2.3.4",
    "64:ff9b::1.2.3.4", "64:ff9b::102:304", "::a.2.3.4", "::1.2.3.a", "1.2.3.4::", "::1.2.3.4::",
    # structure errors
    ":::", "::::", "1:::2", "1::2::3", "::1::", ":1:2:3:4:5:6:7", "1:2:3:4:5:6:7:", ":", "1:", ":1",
    "1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9", "1::2:3:4:5:6:7:8", "1:2:3:4:5:6:7::", "::1:2:3:4:5:6:7",
    "::1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8::", "12345::", "::12345", "1:12345::", "g::", "::g", "1::x",
    "1:2", "dead:beef", "dead:beef::", "1:2:3:4:5:6:7:8 ", " ::1", "::1 ", "::1\n", "::1\r\n",
    "::1\x00", "\x00::1", "fe80::1%eth0", "fe80::1%1", "fe80::1%", "::1%", "::1/", "::1:", ":::1",
    # brackets
    "[::1]", "[::1", "::1]", "[[::1]]", "[]", "[ ::1]", "[::1] ", "[2001:db8::1]", "[2001:db8::1]:80",
    "[::ffff:1.2.3.4]", "[1:2:3:4:5:6:7:8]", "[::]", "[:]", "[1]", "[xxx]", "[:::]", "[::1]\n",
    # ports / junk
    "::1:80", "::443", "::80", "e::", "a::", "::a", ":::FFFF:", ":::f", "2001:db8::1.2.3.4",
    "\uff11::", "::\u0661", "\u0661::",
    "xxx", "xxx.yyy", "fail2ban.org", "localhost", "www.example.com", "1.2.3.4.example.com", "", " ",
    "test-name-a", "host:port", "1:2:3", "a:b:c", "1.2.3.4:", ":1.2.3.4",
]
V6_CIDR = [
    "2001:db8::/32", "2001:DB8::/32", "2001:db8::1/32", "2001:db8::1/128", "2001:db8::1/127",
    "2001:db8::/0", "::/0", "::/1", "::/32", "::/128", "::/129", "::/255", "::1/128", "::1/0", "::1/64",
    "::1/32", "::1/129", "::1/99999999999999999999999999999999999999999999999999",
    "1::/16", "1:2:3:4:5:6:7:8/64", "ffff::/16", "ffff:ffff::/32", "2606:2800:220:1:248:1893:25c8:0/120",
    "2606:2800:220:1:248:1893:25c8::/120", "2606:28ff:220:1:248:1893:25c8::/25",
    "2606:28ff:220:1:248:1893:25c8::/128", "2606:28ff:220:1:248:1893:25c8::/00128",
    "::ffff:0:0/96", "::ffff:0:0/95", "::ffff:0:0/97", "::ffff:0:0/128", "::ffff:0:0/0", "::ffff:1:2/120",
    "::ffff:1.2.3.4/120", "::ffff:1.2.3.4/96", "::ffff:1.2.3.4/24", "::1.2.3.4/96", "1.2.3.4::/32",
    "2001:db8::/", "/32", "2001:db8::/-1", "2001:db8::/+32", "2001:db8::/32 ", "2001:db8::/32\n",
    "2001:db8::/32\r\n", "2001:db8:: /32", " 2001:db8::/32", "2001:db8::/3 2", "2001:db8::/32/32",
    "2001:db8::/32x", "2001:db8::/\u0663\u0662", "2001:db8::/\uff13\uff12", "\u0661::/32",
    "2001:db8::\x00/32", "2001:db8::/32\x00", "2001:db8:::/32", "2001:db8::g/32", "2001:db8/32",
    "[2001:db8::/32]", "[2001:db8::]/32", "2001:db8::/[32]", "[::1/128]", "[::/0]", "[::1]/128",
    "2606:28ff:220:1:248:1893:25c8::/ffff::/::1", "some/path/as/id", "xxx/24", "dead:beef/24",
    "dead:beef::/24", "1:2:3:4:5:6:7/16",
    # netmask forms
    "2606:28ff:220:1:248:1893:25c8::/ffff:ff80::", "2606:28ff:220:1:248:1893:25c8::/ffff:ffff:ffff:ffff:ffff:ffff:ffff::",
    "2606:28ff:220:1:248:1893:25c8::/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "2001:db8::/ffff:ffff::",
    "2001:db8::/ffff::", "2001:db8::/8000::", "2001:db8::/ffff:fffe::", "2001:db8::/ffff:ff00::",
    "2001:db8::/ffff:0:ffff::", "2001:db8::/::ffff", "2001:db8::/::", "2001:db8::/::1", "2001:db8::/f::",
    "2001:db8::/ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe", "2001:db8::/0:0:0:0:0:0:0:0",
    "2001:db8::/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff\n", "2001:db8::/ffff:ffff:: ",
    "2001:db8::/ffff:ffff:ffff:ffff::", "2001:db8::/ffff:ffff:ffff:ffff:8000::", "::1/ffff::",
    "::1/::ffff:0:0", "::1/::ffff:ffff", "::1/::ffff:ff00", "::1/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    "::1/255.255.255.0", "::1/255.255.255.255", "::1/1.2.3.4",
    "::1/ffff:g::", "::1/12345::",
]
CIDR_INTS = [0, 8, 24, 32, 33, 64, 96, 120, 128, 129]


def harvest_test_inputs():
    """String literals passed as first IPAddr(...) argument in upstream tests."""
    found = []
    tdir = os.path.join(ROOT, "fail2ban", "fail2ban", "tests")
    pat = re.compile(r"""IPAddr\(\s*(['"])((?:(?!\1).)*)\1""")
    for fn in sorted(os.listdir(tdir)):
        if fn.endswith(".py"):
            with open(os.path.join(tdir, fn), encoding="utf-8") as f:
                for m in pat.finditer(f.read()):
                    found.append(m.group(2))
    return found


def fuzz_inputs(rng):
    alphabet = "0123456789abcdefABCDEF:.:/[]x %\n\u0661g-"
    seeds = V4_BASE[:15] + V6_BASE[:60] + V4_CIDR[:30] + V6_CIDR[:30]
    out = []
    for _ in range(400):
        s = list(rng.choice(seeds))
        for _ in range(rng.randint(1, 3)):
            op = rng.randint(0, 2)
            pos = rng.randint(0, len(s))
            if op == 0:
                s.insert(pos, rng.choice(alphabet))
            elif op == 1 and s:
                del s[min(pos, len(s) - 1)]
            elif s:
                s[min(pos, len(s) - 1)] = rng.choice(alphabet)
        out.append("".join(s))
    for _ in range(250):  # random structured IPv6 shapes
        groups = [format(rng.choice([0, 0, 1, 0xA, 0xff, 0xdead, 0xffff, 0x12345 if rng.random() < .05 else 0xbeef]), "x")
                  for _ in range(rng.randint(0, 9))]
        k = rng.randint(0, len(groups))
        parts = groups[:k] + ([""] if rng.random() < .7 else []) + groups[k:]
        s = ":".join(parts)
        if rng.random() < .15:
            s += ":" + ".".join(str(rng.choice([0, 1, 4, 255, 256, 7, 10])) for _ in range(rng.choice([3, 4, 4, 4, 5])))
        if rng.random() < .2:
            s += "/" + rng.choice(["0", "16", "64", "96", "120", "128", "129", "ffff::", "ffff:ffff::", "::ffff"])
        if rng.random() < .1:
            s = "[" + s + "]"
        out.append(s)
    for _ in range(200):  # random v4 shapes
        s = ".".join(rng.choice(["0", "1", "10", "010", "127", "192", "255", "256", "99", "x", ""]) for _ in range(rng.choice([3, 4, 4, 4, 4, 5])))
        if rng.random() < .3:
            s += "/" + rng.choice(["0", "8", "24", "32", "33", "255.255.255.0", "255.0.255.0", "0.0.0.0", "ffff::"])
        out.append(s)
    return out


def dedup(seq):
    seen = set()
    res = []
    for s in seq:
        if s not in seen:
            seen.add(s)
            res.append(s)
    return res


def write_json(name, data):
    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, name)
    if isinstance(data, list):  # one element per line keeps diffs reviewable
        body = "[\n" + ",\n".join(json.dumps(x, sort_keys=True, separators=(",", ":")) for x in data) + "\n]\n"
    else:
        body = json.dumps(data, sort_keys=True, indent=1) + "\n"
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(body)


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------
def gen_construct(inputs):
    cases = []
    for s in inputs:
        c = {"in": s, "cidr": "unspec"}
        c.update(tryit(lambda: describe(make(s))))
        cases.append(c)
    variant_inputs = dedup(V4_BASE[:30] + V6_BASE[:70] + [x for x in V4_CIDR[:8] + V6_CIDR[:8]])
    for s in variant_inputs:
        for spec in ["raw", "inet4", "inet6", "none"] + CIDR_INTS:
            c = {"in": s, "cidr": spec}
            c.update(tryit(lambda: describe(make(s, spec))))
            cases.append(c)
    return cases


def object_specs():
    """Objects for the pair matrices (all must construct without error)."""
    specs = []
    for s in [
        "1.2.3.4", "1.2.3.5", "192.0.2.1", "192.0.2.0/24", "192.0.2.1/24", "192.0.2.128/25", "10.0.0.0/8",
        "10.1.2.3", "0.0.0.0", "0.0.0.0/0", "1.2.3.4/0", "255.255.255.255", "1.2.3.4/33", "1.2.3.4/32",
        "93.184.0.1/24", "93.184.0.255", "93.184.1.0", "127.0.0.1", "127.0.0.1/8", "145.239.69.22",
        "198.51.100.77", "198.51.100.0/24", "203.0.113.9",
        "::", "::1", "::2", "1::", "2001:db8::1", "2001:db8::", "2001:db8::/32", "2001:db8::/125",
        "2001:db8::7", "2001:db8::10", "2001:db8:ffff::1", "2001:db9::", "::/32", "::/0", "::1/128",
        "::ffff:0:0/96", "::ffff:1.2.3.4", "::ffff:192.0.2.1", "::ffff:1.2.3.4/120",
        "::1.2.3.4", "fe80::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        "2001:41d0:303:3d16::1", "2606:2800:220:1:248:1893:25c8:0/120",
        "2606:2800:220:1:248:1893:25c8:ff", "2606:2800:220:1:248:1893:25c8:100",
        "xxx", "fail2ban.org", "localhost", "some/path/as/id", "test-name-a", "other-name", "",
        "999.1.1.1/24", "1.2.3.4/255.0.255.0x", "dead:beef", "[xxx]",
    ]:
        specs.append((s, "unspec"))
    for s in ["xxx", "1.2.3.4", "1::2", "93.184.0.1", "", "fail2ban.org", "2001:db8::1"]:
        specs.append((s, "raw"))
    for s, c in [("192.0.2.1", "inet4"), ("2001:db8::1", "inet6"), ("1.2.3.4", "none"), ("::ffff:1.2.3.4", "inet6"),
                 ("::ffff:1.2.3.4", 120), ("1.2.3.4", 24), ("1.2.3.4", 16), ("2001:db8::1", 64), ("::1", 32),
                 ("1.2.3.4", "inet6"), ("::1", "inet4"), ("2001:db8::7", 125), ("192.0.2.200", 29)]:
        specs.append((s, c))
    out = []
    for s, c in specs:
        make(s, c)  # must not raise
        out.append({"s": s, "c": c})
    return out


def bool_matrix(objs, fn):
    return ["".join("1" if fn(a, b) else "0" for b in objs) for a in objs]


def gen_pairs():
    specs = object_specs()
    objs = [make(o["s"], o["c"]) for o in specs]
    res = {"objects": specs, "dns": DNS_TABLE}
    _dns_enabled[0] = True
    res["eq"] = bool_matrix(objs, lambda a, b: a == b)
    res["lt"] = bool_matrix(objs, lambda a, b: a < b)
    res["in_net_dns"] = bool_matrix(objs, lambda a, b: a.isInNet(b))
    res["contains_dns"] = bool_matrix(objs, lambda a, b: b.contains(a))
    res["in_dns"] = bool_matrix(objs, lambda a, b: a in b)
    _dns_enabled[0] = False
    res["in_net_nodns"] = bool_matrix(objs, lambda a, b: a.isInNet(b))
    res["contains_nodns"] = bool_matrix(objs, lambda a, b: b.contains(a))
    _dns_enabled[0] = True
    # a == str (raises for bad masks)
    strs = ["1.2.3.4", "xxx", "::1", "::ffff:1.2.3.4", "1.2.3.4/24", "192.0.2.0/24", "1.2.3.4/255.0.255.0",
            "", "93.184.0.1", "fail2ban.org", "1::2", "2001:db8::/32", "1.2.3.4\x00"]
    eqs = []
    for i, a in enumerate(objs):
        for s in strs:
            r = tryit(lambda: a == s)
            eqs.append([i, s, r])
    res["eq_str"] = eqs
    return res


SET_SPECS = [
    [],
    ["192.0.2.1"],
    ["192.0.2.1", "192.0.2.2", "2001:db8::1"],
    ["192.0.2.1/27", "2001:DB8::/32"],
    ["127.0.0.1/8", "::1"],
    ["192.0.2.0/29", "2001:db8::0/125"],
    ["192.0.2.16/29", "2001:db8::10/125"],
    ["192.0.2.1", "192.0.2.1", "192.0.2.1/32"],
    ["::ffff:1.2.3.4", "1.2.3.4"],
    ["fail2ban.org"],
    ["localhost", "10.0.0.1"],
    ["test-name-a", "198.51.100.0/24"],
    ["some/path/as/id", "xxx"],
    ["xxx", "xxx", ""],
    ["1.2.3.4/0"],
    ["::/0"],
    ["0.0.0.0/0", "::/0"],
    ["1.2.3.4/33", "::1/129"],
    ["1.2.3.4/255.0.255.0"],
    ["192.0.2.1", "1.2.3.4\x00"],
    ["[::1]", "[2001:db8::]/32", "[2001:db8::/32]"],
    ["2606:2800:220:1:248:1893:25c8:0/120", "93.184.0.1/24"],
    ["fail2ban.org", "other-name", "192.0.2.5"],
]
SET_ADDS = [[], ["192.0.2.9"], ["10.0.0.0/8"], ["fail2ban.org"], ["::1", "bad/mask/x"], ["1.2.3.4/255.0.255.0"], ["xxx"]]
SET_PROBES = [
    "192.0.2.1", "192.0.2.2", "192.0.2.7", "192.0.2.8", "192.0.2.9", "192.0.2.16", "192.0.2.23", "192.0.2.31",
    "192.0.2.32", "192.0.2.200", "127.0.0.1", "127.255.255.255", "128.0.0.1", "1.2.3.4", "1.2.3.5",
    "10.0.0.1", "10.255.0.1", "93.184.0.7", "93.184.1.7", "198.51.100.5", "203.0.113.9", "145.239.69.22",
    "0.0.0.0", "255.255.255.255",
    "::1", "::2", "::", "2001:db8::1", "2001:db8::7", "2001:db8::8", "2001:db8::10", "2001:db8::17",
    "2001:db8:ffff::1", "2001:db9::", "2001:41d0:303:3d16::1", "2606:2800:220:1:248:1893:25c8:ff",
    "2606:2800:220:1:248:1893:25c8:100", "::ffff:1.2.3.4", "fe80::1",
    "xxx", "", "fail2ban.org", "localhost", "test-name-a", "some/path/as/id", "other-name", "1.2.3.4/24",
]


def gen_sets():
    cases = []
    for init in SET_SPECS:
        for adds in SET_ADDS:
            case = {"init": init, "add": adds}
            try:
                s = IPAddrSet(init)
                for a in adds:
                    s.add(a)
            except Exception as e:  # noqa: BLE001
                case["error"] = err(e)
                cases.append(case)
                continue
            case["len"] = len(s)
            case["has_subnet"] = bool(s.hasSubNet)
            case["instanceType"] = s.instanceType
            row = {}
            for dns in (True, False):
                _dns_enabled[0] = dns
                row["dns" if dns else "nodns"] = "".join(
                    "1" if (IPAddr(p) in s) else "0" for p in SET_PROBES
                )
            _dns_enabled[0] = True
            case.update(row)
            cases.append(case)
    return {"cases": cases, "dns": DNS_TABLE, "probes": SET_PROBES}


def gen_search(inputs):
    texts = dedup(inputs + ["1.2.3.4\n", "[::1]\n", "[::1]\n\n", "[1.2.3.4]", "::1\n", "\n", "[", "]", "[]", "[[::1]]",
                            "::1]", "[::1", "1.2.3.4]", "[1.2.3.4", " 1.2.3.4", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7::", "::"])
    return [[t, IPAddr.searchIP(t)] for t in texts]


def gen_misc(masks):
    consts = {
        "IP_4_RE": IPAddr.IP_4_RE,
        "IP_6_RE": IPAddr.IP_6_RE,
        "IP_4_6_CRE": IPAddr.IP_4_6_CRE.pattern,
        "IP_W_CIDR_CRE": IPAddr.IP_W_CIDR_CRE.pattern,
        "RE_FILE_IGN_IP": FileIPAddrSet.RE_FILE_IGN_IP.pattern,
    }
    mask_cases = [[m, tryit(lambda: IPAddr.masktoplen(m))] for m in masks]
    ip6_4compat = describe(IPAddr.IP6_4COMPAT)
    rng = random.Random(7)
    files = [
        "file:/etc/ips", "file:///etc/ips", "file://etc/ips", "file:etc/ips", "file:/./x", "file://./x",
        "file:///", "file:", "file:/", "file://", "file:///x", "file:////x", "file://///x", "file:/a/b", "file://a/b",
        "file:/ab/c", "file:/abc/d", "file:/a/", "file://ab/", "file:/./", "file:///./x", "file:///../x",
        "file://..//x", "file:\n", "file:/x\n", "file:/x\ny", "file:\nx", "file: x", "File:/x", "xfile:/x",
        "file:/\u00e9/x", "file:/\u00e9\u00e9/x", "file:///\u00e9/x", "file://a", "file://a\n", "file:/a\n/",
        "file:///a/b", "file:///ab/c", "file://ab/c", "file://abc/d", "file:/..", "file://..", "file:///..",
        "file:/../x", "file:/.../x", "file://./", "file://.//", "file:/\n/x", "file:/x/\n", "file:", "file:file:/x",
        "/etc/ips", "127.0.0.1", "", "file", "file:/etc/ips ", "file:/ etc",
    ]
    alpha = ["/", "/", "a", ".", "\n", "b", "\u00e9"]
    for _ in range(600):
        files.append("file:" + "".join(rng.choice(alpha) for _ in range(rng.randint(0, 8))))
    files = dedup(files)
    file_cases = []
    for f in files:
        m = FileIPAddrSet.RE_FILE_IGN_IP.match(f)
        file_cases.append([f, m.group(1) if m else None])
    return {"consts": consts, "masktoplen": mask_cases, "file_ign": file_cases, "ip6_4compat": ip6_4compat}


def gen_digits():
    out = []
    for cp in range(0x110000):
        c = chr(cp)
        d = unicodedata.decimal(c, None)
        isd = re.match(r"\d", c) is not None
        assert isd == (d is not None), hex(cp)
        if d is not None:
            assert int(c) == d
            out.append([cp, d])
    return out


def main():
    rng = random.Random(20241019)
    inputs = dedup(V4_BASE + V4_CIDR + V6_BASE + V6_CIDR + harvest_test_inputs() + fuzz_inputs(rng))
    write_json("ipaddr_construct.json", gen_construct(inputs))
    write_json("ipaddr_pairs.json", gen_pairs())
    write_json("ipaddr_sets.json", gen_sets())
    write_json("ipaddr_search.json", gen_search(inputs))
    masks = dedup(
        [s.split("/", 1)[1] for s in inputs if "/" in s and s.count("/") == 1] + V4_BASE[:10] + V6_BASE[:30]
    )
    write_json("ipaddr_misc.json", gen_misc(masks))
    write_json("unicode_digits.json", gen_digits())
    print("constructed %d inputs" % len(inputs))


if __name__ == "__main__":
    main()
