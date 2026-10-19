#!/usr/bin/env python3
"""Extract filter sample fixtures from upstream Fail2Ban's test corpus.

Mirrors the state machine of upstream `fail2ban/tests/samplestestcase.py`
(directives `failJSON`, `fileOptions`, `filterOptions`, `addFILE`, the
`test.condition` / `constraint` expressions) and flattens it into
self-contained records so the Rust harness needs no Python `eval`.

One record = one (log line x filter-option combination) that upstream checks.
Expected times are resolved to epoch seconds using upstream's pinned test
timezone and clock (see `meta.json`).

Usage: tools/extract_samples.py [--upstream DIR] [--out DIR]
Output: <out>/meta.json, <out>/<basedir>/<filter>.json
"""
import argparse
import datetime
import json
import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Pinned by upstream tests/utils.py (setUpMyTime / TZ setup).
TEST_TZ = "CET-01CEST-02,M3.5.0,M10.5.0"
TEST_NOW = 1124013600

os.environ["TZ"] = TEST_TZ
time.tzset()

DIRECTIVE = re.compile(r"^#+ ?(failJSON|(?:file|filter)Options|addFILE):(.+)$")
# Only forms present in the corpus; anything else is a hard error (never guess).


def safe_eval(expr, name, opts):
    allowed = {
        "name=='sshd'", "name == 'sshd'",
        "opts.get('mode') == 'aggressive'", "opts.get('mode') != 'aggressive'",
    }
    if expr not in allowed:
        raise ValueError(f"unsupported condition expression: {expr!r}")
    return eval(expr, {"__builtins__": {}}, {"name": name, "opts": opts})  # noqa: S307 - allowlisted


def to_epoch(t):
    try:
        local = datetime.datetime.strptime(t, "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        local = datetime.datetime.strptime(t, "%Y-%m-%dT%H:%M:%S.%f")
    return time.mktime(local.timetuple()) + local.microsecond / 1e6


def read_lines(path: Path):
    data = path.read_bytes()
    text = data.decode("utf-8")  # strict: corpus must be valid UTF-8
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def extract_filter(logs_dir: Path, name: str, basedir_label: str):
    records = []
    filenames = [name]
    common_opts = {}
    faildata = {}
    flt_tests = None  # list of (flt_key, flt_opts, opts)
    i = 0
    while i < len(filenames):
        fname = filenames[i]
        i += 1
        lines = read_lines(logs_dir / fname)
        ignore_block = False
        it = iter(enumerate(lines, 1))
        for lnnum, line in it:
            jsonline = None
            m = DIRECTIVE.match(line)
            if m:
                faildata = json.loads(m.group(2))
                kind = m.group(1)
                if kind == "fileOptions":
                    common_opts = faildata
                    continue
                if kind == "filterOptions":
                    flt_tests = []
                    ignore_block = False
                    for item in (faildata if isinstance(faildata, list) else [faildata]):
                        opts = {**common_opts, **item} if common_opts else item
                        assert isinstance(opts, dict)
                        if opts.get("test.condition"):
                            ignore_block = not safe_eval(opts["test.condition"], name, opts)
                        if not ignore_block:
                            flt_opts = {k: v for k, v in opts.items() if not k.startswith("test.")}
                            key = opts.get("test.filter-name") or (str(flt_opts) if flt_opts else "")
                            flt_tests.append((name + key, flt_opts, opts))
                    continue
                if kind == "addFILE":
                    filenames.append(faildata)
                    continue
                # failJSON: the next physical line is the log line under test.
                jsonline = line
                try:
                    lnnum, line = next(it)
                except StopIteration:
                    raise ValueError(f"{fname}: failJSON at EOF")
            elif ignore_block or line.startswith("#") or not line.strip():
                continue
            else:
                faildata = {}  # unannotated line: upstream expects "no match"
            if ignore_block:
                continue
            if not flt_tests:
                flt_tests = [(name, {}, {})]
            line = line.rstrip("\r\n")
            for key, flt_opts, opts in flt_tests:
                c = faildata.get("constraint")
                if c and not safe_eval(c, name, opts):
                    continue
                expect = {k: v for k, v in faildata.items() if k not in ("time", "desc", "constraint")}
                rec = {
                    "flt_key": key,
                    "filter_options": flt_opts,
                    "logtype": opts.get("logtype"),
                    "prefix_line": opts.get("test.prefix-line"),
                    "file": fname,
                    "lineno": lnnum,
                    "line": line,
                    "expect": expect,
                }
                if faildata.get("time") is not None:
                    rec["expect_time"] = to_epoch(faildata["time"])
                if "desc" in faildata:
                    rec["desc"] = faildata["desc"]
                records.append(rec)
    return records


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--upstream", default=str(ROOT / "fail2ban"))
    ap.add_argument("--out", default=str(ROOT / "testdata" / "samples"))
    a = ap.parse_args()
    up, out = Path(a.upstream), Path(a.out)
    tests = up / "fail2ban" / "tests"
    logs_dir = tests / "files" / "logs"

    sets = (
        ("stock", up / "config", lambda x: not x.endswith("common.conf") and x.endswith(".conf")),
        ("tests-config", tests / "config", lambda x: x.startswith("zzz-") and x.endswith(".conf")),
    )
    out.mkdir(parents=True, exist_ok=True)
    (out / "meta.json").write_text(json.dumps(
        {"tz": TEST_TZ, "now": TEST_NOW, "source": "fail2ban/tests/samplestestcase.py"}, indent=1) + "\n")

    total = 0
    for label, basedir, pred in sets:
        for f in sorted(x for x in os.listdir(basedir / "filter.d") if pred(x)):
            name = f.rpartition(".")[0]
            if name.startswith("."):
                continue
            if not (logs_dir / name).is_file():
                sys.exit(f"no sample log for filter {name!r}")
            recs = extract_filter(logs_dir, name, label)
            dest = out / label / f"{name}.json"
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(json.dumps(
                {"filter": name, "basedir": label, "records": recs}, indent=1, sort_keys=True) + "\n")
            total += len(recs)
    print(f"records: {total}", file=sys.stderr)


if __name__ == "__main__":
    main()
