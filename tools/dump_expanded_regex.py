#!/usr/bin/env python3
"""Dump upstream's fully expanded filter regexes (after <HOST>/<F-*> tag expansion).

One entry per filter-option combination that the sample corpus exercises
(taken from testdata/samples), so the Rust regex layer can be checked against
the exact patterns upstream compiles.

Usage: tools/dump_expanded_regex.py [--upstream DIR] [--samples DIR] [--out FILE]
"""
import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--upstream", default=str(ROOT / "fail2ban"))
    ap.add_argument("--samples", default=str(ROOT / "testdata" / "samples"))
    ap.add_argument("--out", default=str(ROOT / "testdata" / "expanded-regex.json"))
    a = ap.parse_args()
    up = Path(a.upstream)
    sys.path.insert(0, str(up))
    from fail2ban.client.filterreader import FilterReader
    from fail2ban.server.filter import Filter

    basedirs = {"stock": up / "config", "tests-config": up / "fail2ban" / "tests" / "config"}
    out = {}
    for label, basedir in basedirs.items():
        for f in sorted(Path(a.samples, label).glob("*.json")):
            data = json.loads(f.read_text())
            combos = {}
            for r in data["records"]:
                combos.setdefault(r["flt_key"], r["filter_options"])
            if not combos:
                combos = {data["filter"]: {}}
            for key, opts in combos.items():
                flt = Filter(None)
                fr = FilterReader(data["filter"], "jail", dict(opts), basedir=str(basedir))
                fr.read()
                fr.getOptions({})
                entry = {"filter": data["filter"], "basedir": label, "options": opts,
                         "prefregex": None, "failregex": [], "ignoreregex": [],
                         "maxlines": 1, "datepattern": None}
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
                            entry["maxlines"] = int(v)
                        elif opt[2] == "datepattern":
                            entry["datepattern"] = v
                entry["prefregex"] = flt.prefRegex.getRegex() if flt.prefRegex else None
                entry["failregex"] = flt.getFailRegex()
                entry["ignoreregex"] = flt.getIgnoreRegex()
                out[f"{label}/{key}"] = entry
    Path(a.out).write_text(json.dumps(out, indent=1, sort_keys=True) + "\n")
    n = sum(len(e["failregex"]) + len(e["ignoreregex"]) + (1 if e["prefregex"] else 0) for e in out.values())
    print(f"{len(out)} filter configurations, {n} regexes", file=sys.stderr)


if __name__ == "__main__":
    main()
