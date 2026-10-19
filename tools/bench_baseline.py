#!/usr/bin/env python3
"""Measure upstream Fail2Ban filter throughput (the Phase 0 performance baseline).

Feeds sample-corpus log lines through upstream `Filter.processLine` (prefix
regex + date detection + all failregexes), configured exactly as upstream's
sample test does. Reports lines/sec (best of N rounds) and peak RSS.

Usage: tools/bench_baseline.py [--upstream DIR] [--rounds N] [--repeat N] [filter ...]
"""
import argparse
import json
import os
import resource
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def corpus(logs: Path, name: str):
    out = []
    for line in (logs / name).read_text(encoding="utf-8").split("\n"):
        if line and not line.startswith("#"):
            out.append(line)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--upstream", default=str(ROOT / "fail2ban"))
    ap.add_argument("--rounds", type=int, default=5)
    ap.add_argument("--repeat", type=int, default=20, help="times the corpus is repeated per round")
    ap.add_argument("filters", nargs="*", default=["sshd", "apache-auth", "nginx-http-auth", "postfix"])
    a = ap.parse_args()

    up = Path(a.upstream)
    sys.path.insert(0, str(up))
    os.environ["TZ"] = "UTC"
    time.tzset()
    from fail2ban.client.filterreader import FilterReader
    from fail2ban.server.filter import Filter
    from fail2ban.server.mytime import MyTime

    MyTime.setTime(1124013600)
    logs = up / "fail2ban" / "tests" / "files" / "logs"
    results = {}
    for name in a.filters:
        flt = Filter(None)
        flt.returnRawHost = True
        flt.checkFindTime = False
        flt.active = True
        fr = FilterReader(name, "jail", {}, basedir=str(up / "config"))
        fr.read()
        fr.getOptions({})
        for opt in fr.convert():
            vals = opt[3] if opt[0] == "multi-set" else [opt[3]]
            for v in vals:
                {"prefregex": lambda x: setattr(flt, "prefRegex", x),
                 "addfailregex": flt.addFailRegex,
                 "addignoreregex": flt.addIgnoreRegex,
                 "maxlines": flt.setMaxLines,
                 "datepattern": flt.setDatePattern}.get(opt[2], lambda x: None)(v)
        lines = corpus(logs, name) * a.repeat
        best = 0.0
        for _ in range(a.rounds):
            matched = 0
            t0 = time.perf_counter()
            for ln in lines:
                if flt.processLine(ln):
                    matched += 1
            dt = time.perf_counter() - t0
            best = max(best, len(lines) / dt)
        # matched>0 guards against benchmarking a no-op (e.g. unparsed dates)
        results[name] = {"lines": len(lines), "matched": matched, "lines_per_sec": round(best)}
    results["_peak_rss_kib"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    results["_python"] = sys.version.split()[0]
    results["_upstream_version"] = __import__("fail2ban.version", fromlist=["version"]).version
    print(json.dumps(results, indent=1))


if __name__ == "__main__":
    main()
