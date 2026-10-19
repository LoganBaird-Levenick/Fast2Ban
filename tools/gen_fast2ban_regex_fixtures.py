#!/usr/bin/env python3
"""Generate golden fixtures for `fast2ban-regex` from upstream `fail2ban-regex`.

Runs upstream Python `fail2ban-regex` with various argument combinations, captures
(stdout, stderr, exit_code), normalizes timing lines and paths, and saves the
expected results to `testdata/fast2ban-regex/fixtures.json`.

Usage: python3 tools/gen_fast2ban_regex_fixtures.py
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "fail2ban" / "bin" / "fail2ban-regex"
ENV = dict(
    os.environ,
    PYTHONPATH=str(ROOT / "fail2ban"),
    TZ="UTC",
    PYTHONHASHSEED="0",
    LC_ALL="C.UTF-8",
)

LOG_SSHD_LINE = "Jun 21 16:47:48 host sshd[13709]: error: PAM: Authentication failure for myuser from 192.0.2.1"
LOG_SSHD_FILE = str(ROOT / "fail2ban" / "tests" / "files" / "logs" / "sshd")
LOG_APACHE_FILE = str(ROOT / "fail2ban" / "tests" / "files" / "logs" / "apache-auth")
FILTER_SSHD = "sshd"
FILTER_SSHD_FILE = str(ROOT / "fail2ban" / "config" / "filter.d" / "sshd.conf")
CONFIG_DIR = str(ROOT / "fail2ban" / "config")

CASES = [
    # Help / version
    ["--help"],
    ["-h"],
    ["--version"],
    ["-V"],

    # Error cases
    [],
    ["only_one_arg"],
    ["--print-no-missed", "--print-all-missed", LOG_SSHD_LINE, "^fail <HOST>$"],
    ["--print-no-ignored", "--print-all-ignored", LOG_SSHD_LINE, "^fail <HOST>$"],
    ["-L", "not_a_number", LOG_SSHD_LINE, "^fail <HOST>$"],
    ["--unknown-option"],

    # Literal regex + single line
    [LOG_SSHD_LINE, "^.*Authentication failure for .* from <HOST>$"],
    [LOG_SSHD_LINE, "^.*Authentication failure for <F-USER>.*</F-USER> from <HOST>$"],
    [LOG_SSHD_LINE, "^.*Authentication failure for .* from <HOST>$", "^.*ignore.*$"],
    [LOG_SSHD_LINE, "^.*Authentication failure for .* from <HOST>$", "^.*error.*$"],
    ["non matching line", "^.*Authentication failure for .* from <HOST>$"],

    # Literal regex + multi line
    [LOG_SSHD_LINE + "\n" + LOG_SSHD_LINE, "^.*Authentication failure for .* from <HOST>$"],

    # Flags with literal regex
    ["-r", LOG_SSHD_LINE, "^.*Authentication failure for .* from <HOST>$"],
    ["--usedns=no", LOG_SSHD_LINE, "^.*Authentication failure for .* from <HOST>$"],
    ["--usedns=yes", LOG_SSHD_LINE, "^.*Authentication failure for .* from <HOST>$"],
    ["-d", "{^LN-BEG}", LOG_SSHD_LINE, "^.*Authentication failure for .* from <HOST>$"],
    ["--timezone=UTC+0200", LOG_SSHD_LINE, "^.*Authentication failure for .* from <HOST>$"],
    ["-v", LOG_SSHD_LINE, "^.*Authentication failure for <F-USER>.*</F-USER> from <HOST>$"],
    ["-vv", LOG_SSHD_LINE, "^.*Authentication failure for <F-USER>.*</F-USER> from <HOST>$"],

    # Formatted output (-o)
    ["-o", "id", LOG_SSHD_LINE, "^.*Authentication failure for .* from <HOST>$"],
    ["-o", "fid", LOG_SSHD_LINE, "^.*Authentication failure for .* from <HOST>$"],
    ["-o", "ip", LOG_SSHD_LINE, "^.*Authentication failure for .* from <HOST>$"],
    ["-o", "msg", LOG_SSHD_LINE, "^.*Authentication failure for .* from <HOST>$"],
    ["-o", "row", LOG_SSHD_LINE, "^.*Authentication failure for <F-USER>.*</F-USER> from <HOST>$"],
    ["-o", "user", LOG_SSHD_LINE, "^.*Authentication failure for <F-USER>.*</F-USER> from <HOST>$"],
    ["-o", "id", "-i", "non match line", "^.*Authentication failure for .* from <HOST>$"],

    # Filter by name
    ["-c", CONFIG_DIR, LOG_SSHD_LINE, FILTER_SSHD],
    ["-c", CONFIG_DIR, LOG_SSHD_LINE, "sshd[mode=aggressive]"],
    ["-c", CONFIG_DIR, LOG_SSHD_LINE, "sshd[mode=ddos]"],

    # Filter by file path
    [LOG_SSHD_LINE, FILTER_SSHD_FILE],
    [LOG_SSHD_LINE, FILTER_SSHD_FILE, "^.*error.*$"],

    # Jail by name
    ["-c", CONFIG_DIR, LOG_SSHD_LINE, "sshd"],

    # Print options
    ["--print-all-matched", LOG_SSHD_LINE, "^.*Authentication failure for .* from <HOST>$"],
    ["--print-all-missed", "nomatch1\nnomatch2", "^.*Authentication failure for .* from <HOST>$"],
    ["--print-no-missed", "nomatch1\nnomatch2", "^.*Authentication failure for .* from <HOST>$"],

    # Log files
    ["-c", CONFIG_DIR, LOG_SSHD_FILE, FILTER_SSHD],
    ["-c", CONFIG_DIR, "--print-all-matched", LOG_SSHD_FILE, "sshd[mode=aggressive]"],
    ["-c", CONFIG_DIR, "-o", "ip", LOG_SSHD_FILE, FILTER_SSHD],
    ["-c", CONFIG_DIR, LOG_APACHE_FILE, "apache-auth"],
]


def normalize_output(text: str) -> str:
    # Normalize execution time: `[processed in 0.05 sec]` -> `[processed in X.XX sec]`
    text = re.sub(r"\[processed in \d+\.\d+ sec\]", "[processed in X.XX sec]", text)
    # Normalize repository root path
    text = text.replace(str(ROOT), "@ROOT@")
    return text


def main():
    fixtures = []
    print(f"Generating fixtures for {len(CASES)} cases...")

    for i, args in enumerate(CASES):
        cmd = [sys.executable, str(BIN)] + args
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=ENV)

        fixtures.append({
            "args": [a.replace(str(ROOT), "@ROOT@") for a in args],
            "exit_code": p.returncode,
            "stdout": normalize_output(p.stdout),
            "stderr": normalize_output(p.stderr),
        })

    out_dir = ROOT / "testdata" / "fast2ban-regex"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "fixtures.json"

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(fixtures, f, indent=2, sort_keys=True)
        f.write("\n")

    print(f"Saved {len(fixtures)} fixtures to {out_file}")


if __name__ == "__main__":
    main()
