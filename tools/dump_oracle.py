#!/usr/bin/env python3
"""Generate golden config-resolution fixtures from upstream Fail2Ban.

For every case, runs upstream `fail2ban-client -c <tree> -d` (dump of the
command stream the client would send to the server) and records the parsed
stream. Fast2Ban's config layer must reproduce these streams (Phase 1 gate).

Cases per config tree:
  base            nothing enabled (global fail2ban.conf options only)
  jail/<name>     each section of jail.conf, enabled via a generated jail.local
  filter/<name>   synthetic jail using each filter.d/*.conf
  action/<name>   synthetic jail using each action.d/*.conf

Usage: tools/dump_oracle.py [--upstream DIR] [--out DIR]
Output: <out>/<tree>/<case>.json  {"rc", "commands", "other", "stderr"}
"""
import argparse
import ast
import configparser
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SYNTH_LOG = "/dev/null"


def run_dump(upstream: Path, conf_dir: Path):
    env = dict(os.environ, PYTHONPATH=str(upstream), PYTHONDONTWRITEBYTECODE="1")
    p = subprocess.run(
        [sys.executable, str(upstream / "bin" / "fail2ban-client"), "-c", str(conf_dir), "-d"],
        capture_output=True, text=True, env=env, timeout=120,
    )
    commands, other = [], []
    for line in p.stdout.splitlines():
        if line.startswith("["):
            try:
                commands.append(ast.literal_eval(line))
                continue
            except (ValueError, SyntaxError):
                pass
        other.append(line)
    scrub = lambda s: s.replace(str(conf_dir), "@CONF@")
    # drop volatile "<date> <time> <logger> [<pid>]:" log prefixes
    stamp = re.compile(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d+ (\S+)\s+\[\d+\]:\s+", re.M)
    return {
        "rc": p.returncode,
        "commands": json.loads(scrub(json.dumps(commands))),
        "other": [scrub(x) for x in other],
        "stderr": stamp.sub(r"\1: ", scrub(p.stderr)),
    }


def jail_sections(conf_dir: Path):
    cp = configparser.RawConfigParser(strict=False, interpolation=None)
    cp.optionxform = str
    # jail.conf may carry an [INCLUDES] with before/after; only section names matter here.
    cp.read(conf_dir / "jail.conf", encoding="utf-8")
    return [s for s in cp.sections() if s not in ("INCLUDES", "DEFAULT")]


def names(conf_dir: Path, sub: str):
    d = conf_dir / sub
    return sorted(p.stem for p in d.glob("*.conf")) if d.is_dir() else []


def case(upstream, tree: Path, work: Path, local_text: str):
    if work.exists():
        shutil.rmtree(work)
    shutil.copytree(tree, work)
    if local_text:
        (work / "jail.local").write_text(local_text)
    return run_dump(upstream, work)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--upstream", default=str(ROOT / "fail2ban"))
    ap.add_argument("--out", default=str(ROOT / "testdata" / "config-oracle"))
    a = ap.parse_args()
    upstream, out = Path(a.upstream), Path(a.out)

    trees = {
        "stock": upstream / "config",
        "tests-config": upstream / "fail2ban" / "tests" / "config",
    }
    ok = bad = 0
    with tempfile.TemporaryDirectory(prefix="f2b-oracle-") as tmp:
        work = Path(tmp) / "conf"
        for tname, tree in trees.items():
            cases = {"base": ""}
            if (tree / "jail.conf").exists():
                for j in jail_sections(tree):
                    cases[f"jail/{j}"] = f"[{j}]\nenabled = true\n"
            for f in names(tree, "filter.d"):
                cases[f"filter/{f}"] = (
                    f"[o-f-{f}]\nenabled = true\nfilter = {f}\nlogpath = {SYNTH_LOG}\n"
                    f"backend = polling\naction =\n"
                )
            for ac in names(tree, "action.d"):
                cases[f"action/{ac}"] = (
                    f"[o-a-{ac}]\nenabled = true\nfilter =\nlogpath = {SYNTH_LOG}\n"
                    f"backend = polling\naction = {ac}\n"
                )
            for cname, text in cases.items():
                res = case(upstream, tree, work, text)
                dest = out / tname / (cname + ".json")
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(json.dumps(res, indent=1, sort_keys=True) + "\n")
                if res["rc"] == 0:
                    ok += 1
                else:
                    bad += 1
            print(f"{tname}: {len(cases)} cases", file=sys.stderr)
    print(f"done: rc==0 {ok}, rc!=0 {bad}", file=sys.stderr)


if __name__ == "__main__":
    main()
