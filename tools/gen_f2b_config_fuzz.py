#!/usr/bin/env python3
"""Differential-fuzz fixtures for f2b-config's INI layer.

Generates random (deliberately odd) config files, reads each with upstream's
`SafeConfigParserWithIncludes.read([...])`, and records what upstream made of
it: the parse result (defaults + sections, or the error class), and for every
option the interpolated value or the error class of `get`.

Usage: tools/gen_f2b_config_fuzz.py [--upstream DIR] [--out FILE] [--n N] [--seed S]
"""
import argparse
import json
import os
import random
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

WS = ["", " ", "  ", "\t", "    ", "\u00a0", "\x0b", "\x1c", "\u2003"]
SECTIONS = ["DEFAULT", "INCLUDES", "a", "b", "c", "Init", "Init?family=inet6", "Definition", "x y",
            "Mixed", "a]b", "known", "KNOWN/a", "ü"]
KEYS = ["k", "key", "Key", "KEY", "a", "b", "c", "x-y", "x.y", "before", "after", "name", "chain",
        "chain?family=inet6", "known/k", "k k", "ü", "__name__", "d"]
ATOMS = ["x", "val", "10m", "a b", "  spaced  ", "http://h;x", "a;b", "a ;b", "a\t;b", "#notcomment",
         "k=v", "a:b", "%%", "100%%", "%(k)s", "%(key)s", "%(KEY)s", "%(a)s", "%(b)s", "%(c)s", "%(d)s",
         "%(name)s", "%(__name__)s", "%(a/k)s", "%(b/key)s", "%(known/k)s", "%(known/key)s",
         "%(default/k)s", "%(DEFAULT/d)s", "%(nosuch)s", "%(a/nosuch)s", "%(nosec/k)s", "%x", "%", "%(",
         "%(k", "%(k)", "<k>", "ü", "\u2003x", "[brackets]", "{}", "\\"]


def rnd_value(rng):
    return "".join(rng.choice(WS[:3]) + rng.choice(ATOMS) for _ in range(rng.randint(0, 4)))


def rnd_file(rng, clean):
    """`clean` files avoid the strict-parser error classes (duplicate sections/options,
    missing header, malformed lines) so the value/interpolation logic gets exercised."""
    lines = []
    seen_sections, seen_keys, cur = set(), set(), None
    if clean:
        cur = rng.choice(["a", "DEFAULT", "b"])
        lines.append("[" + cur + "]")
        seen_sections.add(cur)
    elif rng.random() < .05:
        lines.append(rng.choice(["k = v", "; c", "garbage", "  [a]"]))
    for _ in range(rng.randint(1, 16)):
        r = rng.random()
        if r < .18:
            name = rng.choice(SECTIONS)
            if clean and (name in seen_sections and name != "DEFAULT" or "]" in name):
                continue
            if clean and name == "DEFAULT":
                seen_keys = {k for k in seen_keys if k[0] != "DEFAULT"} if False else seen_keys
            seen_sections.add(name)
            cur = name
            lines.append(rng.choice(WS[:4]) + "[" + name + "]" + rng.choice(["", " ", " ; c"] if clean else ["", " ", " ; c", " junk"]))
        elif r < .55:
            key = rng.choice(KEYS)
            if clean:
                if (cur, key.lower()) in seen_keys or key.lower() != key.strip() or not key.strip() or "=" in key or ":" in key:
                    continue
                seen_keys.add((cur, key.lower()))
            sep = rng.choice(["=", ":", " = ", " : ", "=", " =", "= "])
            lines.append(rng.choice(WS[:3] if clean else WS[:3]) + key + sep + rnd_value(rng) + rng.choice(["", "", " ; cmt", ";cmt", "\t;cmt"]))
        elif r < .70:
            lines.append(rng.choice(["  ", "\t", "    ", " \t"]) + rnd_value(rng))   # continuation
        elif r < .78:
            lines.append("")
        elif r < .84:
            lines.append(rng.choice(["# comment", "; comment", "   # c", "\t; c", "#"]))
        elif r < .88:
            lines.append(rng.choice(WS))
        elif r < .93:
            if not clean:
                lines.append(rng.choice(["=", ":", "= x", "no delimiter", "[unclosed", "]", "[]", "[ ]"]))
        else:
            if not clean:
                lines.append(rnd_value(rng))
    nl = rng.choice(["\n", "\n", "\n", "\r\n", "\r"])
    text = nl.join(lines)
    if rng.random() < .7:
        text += nl
    return text


def run_case(SCPWI, text, tmp):
    path = os.path.join(tmp, "case.conf")
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(text)
    p = SCPWI()
    res = {"error": None}
    try:
        p.read([path])
    except Exception as e:  # noqa: BLE001 - the class name is the oracle
        res["error"] = type(e).__name__
        return res
    res["defaults"] = dict(p._defaults)
    res["sections"] = {k: dict(v) for k, v in p._sections.items()}
    res["order"] = [list(p._sections.keys())] + [list(v.keys()) for v in p._sections.values()]
    gets = {}
    names = ["DEFAULT"] + list(p._sections.keys())
    for sec in names:
        opts = list(p._defaults.keys()) if sec == "DEFAULT" else list(p._sections[sec].keys()) + list(p._defaults.keys())
        for opt in dict.fromkeys(opts):
            try:
                v = p.get(sec, opt)
                gets[f"{sec}\x00{opt}"] = {"v": v}
            except Exception as e:  # noqa: BLE001
                gets[f"{sec}\x00{opt}"] = {"e": type(e).__name__, "m": str(e).replace(path, "@FILE@")}
        # the section/option name syntax and a missing key
        for opt in ("nosuch", "known/k", "a/k", "default/d"):
            try:
                gets[f"{sec}\x00{opt}"] = {"v": p.get_ex(sec, opt)}
            except Exception as e:  # noqa: BLE001
                gets[f"{sec}\x00{opt}"] = {"e": type(e).__name__, "m": str(e).replace(path, "@FILE@")}
    res["gets"] = gets
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--upstream", default=str(ROOT / "fail2ban"))
    ap.add_argument("--out", default=str(ROOT / "testdata" / "f2b-config" / "ini_fuzz.json"))
    ap.add_argument("--n", type=int, default=3000)
    ap.add_argument("--seed", type=int, default=20260102)
    a = ap.parse_args()
    sys.path.insert(0, a.upstream)
    from fail2ban.client.configparserinc import SafeConfigParserWithIncludes as SCPWI

    rng = random.Random(a.seed)
    cases = []
    with tempfile.TemporaryDirectory() as tmp:
        for _ in range(a.n):
            text = rnd_file(rng, clean=rng.random() < .75)
            cases.append({"text": text, "expect": run_case(SCPWI, text, tmp)})
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(cases, sort_keys=True, ensure_ascii=True) + "\n")
    ok = sum(1 for c in cases if c["expect"]["error"] is None)
    print(f"{len(cases)} cases, {ok} parse ok, {len(cases) - ok} parse errors", file=sys.stderr)


if __name__ == "__main__":
    main()
