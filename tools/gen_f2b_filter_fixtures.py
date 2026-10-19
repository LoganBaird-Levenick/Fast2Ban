#!/usr/bin/env python3
"""Differential fixtures for f2b-filter's `processLine` state machine.

Drives the REAL upstream `Filter` through scenarios the sample corpus does not
cover: `checkFindTime` / `inOperation` combinations (odd timestamps, obsolete
entries, last-known-date fallback, undated lines), DNS expansion of host names
(`usedns` yes/warn/no/raw with a fixed resolver table) and multi-line
buffering. Records, per input line, the full result list upstream returns.

Output: testdata/f2b-filter/scenarios.json
"""
import json
import logging
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "fail2ban"))
TZ = "CET-01CEST-02,M3.5.0,M10.5.0"
os.environ["TZ"] = TZ
time.tzset()

from fail2ban.client.filterreader import FilterReader  # noqa: E402
from fail2ban.server.filter import Filter  # noqa: E402
from fail2ban.server.ipdns import DNSUtils, IPAddr  # noqa: E402
from fail2ban.server.mytime import MyTime  # noqa: E402

NOW = 1124013600
DNS_TABLE = {
    "host.example": ["192.0.2.7", "2001:db8::7"],
    "v4only.example": ["192.0.2.8"],
}


def fake_dns(dns):
    return set(IPAddr(a) for a in DNS_TABLE.get(dns, []))


logging.disable(logging.CRITICAL)
DNSUtils.dnsToIp = staticmethod(fake_dns)
DNSUtils.setIPv6IsAllowed(True)


def fmt(t):
    return time.strftime("%b %d %H:%M:%S", time.localtime(t))


def ssh(t, host="1.2.3.4", pid=1):
    return f"{fmt(t)} srv sshd[{pid}]: Failed password for root from {host} port 22 ssh2"


UNDATED = "srv sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"
NOISE = f"{fmt(NOW)} srv cron[5]: nothing to see"


def mk_filter(name, opts, scn):
    flt = Filter(None)
    flt.checkFindTime = scn["check_find_time"]
    flt.inOperation = scn["in_operation"]
    flt.checkAllRegex = scn.get("check_all", False)
    flt.returnRawHost = scn.get("raw_host", False)
    flt.ignorePending = scn.get("ignore_pending", True)
    flt.setFindTime(scn["find_time"])
    flt.setUseDns(scn["usedns"])
    fr = FilterReader(name, "jail", dict(opts), basedir=str(ROOT / "fail2ban" / "config"))
    fr.read()
    fr.getOptions({})
    for opt in fr.convert():
        vals = opt[3] if opt[0] == "multi-set" else [opt[3]]
        for v in vals:
            if opt[2] == "prefregex":
                flt.prefRegex = v
            elif opt[2] == "addfailregex":
                flt.addFailRegex(v)
            elif opt[2] == "addignoreregex":
                flt.addIgnoreRegex(v)
            elif opt[2] == "maxlines":
                flt.setMaxLines(v)
            elif opt[2] == "datepattern":
                flt.setDatePattern(v)
    return flt


def simple(v):
    """JSON-able form of a failure dict value."""
    if v is None or isinstance(v, (str, int, float, bool)):
        return v
    if isinstance(v, (set, frozenset)):
        return {"set": sorted(simple(x) for x in v)}
    if isinstance(v, tuple):
        return {"tuple": [simple(x) for x in v]}
    if isinstance(v, list):
        return {"lines": ["".join(x) if isinstance(x, tuple) else str(x) for x in v]}
    return {"repr": str(v)}


def run(scn):
    MyTime.setTime(scn.get("now", NOW))
    flt = mk_filter(scn["filter"], scn.get("filter_options", {}), scn)
    out = []
    for item in scn["lines"]:
        line = item["line"]
        try:
            res = flt.processLine(line)
            row = []
            for idx, fid, date, fail in res:
                row.append({
                    "regex": idx,
                    "fid": None if fid is None else str(fid),
                    "date": date,
                    "fail": {k: simple(v) for k, v in fail.items()},
                })
            # DNS expansion returns a set: order depends on the hash seed
            row.sort(key=lambda r: (r["regex"], r["fid"] or ""))
            out.append({"ok": row})
        except Exception as e:  # noqa: BLE001
            out.append({"err": type(e).__name__})
        if "advance" in item:
            MyTime.setTime(MyTime.time() + item["advance"])
    return out


def L(line, advance=None):
    d = {"line": line}
    if advance is not None:
        d["advance"] = advance
    return d


def scenarios():
    S = []
    base = dict(filter="sshd", check_find_time=True, in_operation=True, find_time=600,
                usedns="warn", raw_host=False)

    def add(name, **kw):
        d = dict(base)
        d.update(kw)
        d["name"] = name
        S.append(d)

    now = NOW
    # in operation, check find time: current, near, odd (latency / timezone), undated
    add("op-timing", lines=[L(ssh(now)), L(ssh(now - 30)), L(ssh(now - 2000)), L(ssh(now - 7200)),
                            L(ssh(now + 7200)), L(UNDATED), L(NOISE), L(ssh(now + 59)),
                            L(ssh(now - 61)), L(ssh(now - 3299)), L(ssh(now - 3300))])
    # not in operation (restore phase): obsolete entries are dropped
    add("restore-obsolete", in_operation=False,
        lines=[L(ssh(now)), L(ssh(now - 599)), L(ssh(now - 601)), L(ssh(now - 100000)),
               L(ssh(now + 100000)), L(UNDATED)])
    add("restore-findtime-large", in_operation=False, find_time=86400,
        lines=[L(ssh(now - 80000)), L(ssh(now - 90000))])
    # no find-time check at all
    add("nocheck", check_find_time=False,
        lines=[L(ssh(now)), L(ssh(now - 100000)), L(UNDATED), L(NOISE), L(ssh(now + 100000))])
    # last known date fallback within 60s, then expiry as the clock advances
    add("lastdate-fallback", lines=[L(ssh(now), advance=10), L(UNDATED, advance=30), L(UNDATED, advance=30),
                                    L(UNDATED, advance=30), L(UNDATED)])
    add("lastdate-fallback-nocheck", check_find_time=False,
        lines=[L(ssh(now), advance=10), L(UNDATED, advance=30), L(UNDATED, advance=100), L(UNDATED)])
    add("undated-first", lines=[L(UNDATED), L(UNDATED), L(ssh(now)), L(UNDATED)])
    add("undated-first-nocheck", check_find_time=False, lines=[L(UNDATED), L(ssh(now)), L(UNDATED)])
    # clock moves between lines
    add("clock-advances", lines=[L(ssh(now), advance=3600), L(ssh(now + 3600), advance=-7200),
                                 L(ssh(now - 3600)), L(ssh(now))])
    # DNS expansion
    for dns in ("yes", "warn", "no", "raw"):
        add(f"dns-{dns}", usedns=dns, check_find_time=False,
            lines=[L(ssh(now, "host.example")), L(ssh(now, "v4only.example")), L(ssh(now, "nope.example")),
                   L(ssh(now, "192.0.2.1")), L(ssh(now, "2001:db8::1")), L(ssh(now, "::ffff:192.0.2.9")),
                   L(ssh(now, "192.0.2.0/24"))])
    add("dns-rawhost", usedns="yes", raw_host=True, check_find_time=False,
        lines=[L(ssh(now, "host.example")), L(ssh(now, "192.0.2.1"))])
    # checkAllRegex and pending handling on a multi-line (mlfid) filter
    add("sshd-aggressive-checkall", check_find_time=False, check_all=True,
        filter_options={"mode": "aggressive"},
        lines=[L(ssh(now)), L(f"{fmt(now)} srv sshd[7]: Connection closed by authenticating user root 5.6.7.8 port 1 [preauth]"),
               L(f"{fmt(now)} srv sshd[8]: Invalid user x from 9.9.9.9 port 5"),
               L(f"{fmt(now)} srv sshd[8]: Connection closed by invalid user x 9.9.9.9 port 5 [preauth]"),
               L(f"{fmt(now)} srv sshd[9]: Disconnecting: Too many authentication failures [preauth]")])
    add("pending-ignored", check_find_time=False, ignore_pending=True,
        lines=[L(f"{fmt(now)} srv sshd[8]: Disconnecting: Too many authentication failures [preauth]")])
    add("pending-kept", check_find_time=False, ignore_pending=False,
        lines=[L(f"{fmt(now)} srv sshd[8]: Disconnecting: Too many authentication failures [preauth]")])
    return S


def main():
    out = []
    for scn in scenarios():
        out.append({"scenario": scn, "results": run(scn)})
    dest = ROOT / "testdata" / "f2b-filter" / "scenarios.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps({"tz": TZ, "now": NOW, "dns": DNS_TABLE, "cases": out},
                               indent=1, sort_keys=True) + "\n")
    n = sum(len(c["results"]) for c in out)
    print(f"{len(out)} scenarios, {n} lines", file=sys.stderr)


if __name__ == "__main__":
    main()
