#!/usr/bin/env python3
"""Oracle for the stock-jails smoke matrix (crates/f2b-server/tests/stock_jails.rs).

For every (filter, filter options) sample group of testdata/samples/stock (journal
groups excluded: file backend only) this runs the REAL upstream daemon
(`fail2ban/bin/fail2ban-server -f`) on the unmodified stock config tree plus a
generated `jail.local`, appends the group's canned log lines to the jail's log file
and records the set of addresses it bans. The Rust matrix must ban exactly the same
addresses.

The sample metadata alone is not a sufficient oracle: a `match: true` sample may
omit `host` (multi-line failures that recover the address from earlier lines), and
hosts that are not valid addresses must not be banned with `usedns = no`.

The jail.local written here MUST be kept identical to `jail_local()` in the Rust test.

Output: testdata/smoke-oracle/stock.json (sorted, deterministic).
Usage: tools/gen_smoke_oracle.py [--upstream DIR] [--out DIR] [--jobs N] [--only SUBSTR]
"""
import argparse
import concurrent.futures
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def quote_opt(v):
    if v and all(c.isascii() and (c.isalnum() or c in "_-.") for c in v):
        return v
    return '"' + v.replace('"', '\\"') + '"'


def filter_spec(name, opts):
    if not opts:
        return name
    return f"{name}[" + ", ".join(f"{k}={quote_opt(str(opts[k]))}" for k in sorted(opts)) + "]"


def load_groups(samples):
    groups = []
    for f in sorted((samples / "stock").glob("*.json")):
        data = json.loads(f.read_text())
        by_key = {}
        for r in data["records"]:
            key = json.dumps(r["filter_options"], sort_keys=True)
            g = by_key.setdefault(key, {"filter": data["filter"], "opts": r["filter_options"],
                                        "journal": False, "lines": []})
            g["journal"] |= r["logtype"] == "journal"
            g["lines"].append(r["line"])
        groups.extend(by_key.values())
    return groups


def banned_set(csock_cls, sock, jail):
    c = csock_cls(sock)
    try:
        code, val = c.send(["get", jail, "banip"])
        if code != 0:
            raise RuntimeError(f"get banip failed: {val!r}")
        return sorted(val)
    finally:
        c.close()


def run_group(g, up, workdir):
    from fail2ban.client.csocket import CSocket

    jail = "smoke-" + g["filter"]
    spec = filter_spec(g["filter"], g["opts"])
    conf = workdir / "conf"
    shutil.copytree(up / "config", conf)
    (conf / "fail2ban.local").write_text("[Definition]\nlogtarget = %s\ndbfile = None\n" % (workdir / "f2b.log"))
    log = workdir / "jail.log"
    out = workdir / "action.out"
    log.write_text("")
    (conf / "jail.local").write_text(
        f"[{jail}]\n"
        "enabled = true\nbackend = polling\n"
        f"logpath = {log}\n"
        "maxretry = 1\nfindtime = 100y\nbantime = -1\nignoreself = false\nignoreip = \n"
        "ignorecommand = \nusedns = no\n"
        f'action = dummy[target="{out}"]\n'
        f"filter = {spec}\n"
    )
    sock = str(workdir / "s.sock")
    env = dict(os.environ, PYTHONPATH=str(up))
    cli_args = [sys.executable, str(up / "bin/fail2ban-client"), "-c", str(conf), "-s", sock,
                "-p", str(workdir / "p.pid")]
    try:
        # `start` spawns the daemonized server and streams the configuration
        cli = subprocess.run(cli_args + ["start"], env=env, capture_output=True, text=True, timeout=60)
        if cli.returncode != 0:
            raise RuntimeError("client start failed: " + cli.stdout + cli.stderr)
        with open(log, "a") as f:
            f.write("\n".join(g["lines"]) + "\n")
        # stable = unchanged for stable_for seconds, at least min_wait after the append
        stable_for, min_wait, last = 2.5, 3.0, None
        start = since = time.time()
        while True:
            cur = banned_set(CSocket, sock, jail)
            if cur != last:
                last, since = cur, time.time()
            if time.time() - since >= stable_for and time.time() - start >= min_wait:
                return last
            if time.time() - start > 120:
                raise RuntimeError("ban set did not stabilise")
            time.sleep(0.25)
    finally:
        try:
            subprocess.run(cli_args + ["stop"], env=env, capture_output=True, timeout=30)
        except Exception:
            pass


def norm(ip):
    """Canonical text of a valid address; anything else (raw ids such as `192.030.0.6`) as is."""
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return ip


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--upstream", default=str(ROOT / "fail2ban"))
    ap.add_argument("--out", default=str(ROOT / "testdata" / "smoke-oracle"))
    ap.add_argument("--samples", default=str(ROOT / "testdata" / "samples"))
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--only", default="")
    a = ap.parse_args()
    up = Path(a.upstream)
    sys.path.insert(0, str(up))
    groups = [g for g in load_groups(Path(a.samples)) if not g["journal"]]
    groups = [g for g in groups if a.only in filter_spec(g["filter"], g["opts"])]

    def work(g):
        with tempfile.TemporaryDirectory(prefix="f2b-oracle-") as d:
            return g, run_group(g, up, Path(d))

    cases = []
    with concurrent.futures.ThreadPoolExecutor(a.jobs) as ex:
        for g, bans in ex.map(work, groups):
            cases.append({"filter": g["filter"], "filter_options": g["opts"],
                          "expected_bans": sorted(norm(b) for b in bans)})
            print(f"{filter_spec(g['filter'], g['opts'])}: {len(bans)}", file=sys.stderr)
    cases.sort(key=lambda c: (c["filter"], json.dumps(c["filter_options"], sort_keys=True)))
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "stock.json").write_text(json.dumps(
        {"source": "fail2ban-server -f (upstream daemon), tools/gen_smoke_oracle.py", "cases": cases},
        indent=1, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
