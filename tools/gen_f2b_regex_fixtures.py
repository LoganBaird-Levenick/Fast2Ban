#!/usr/bin/env python3
"""Generate oracle fixtures for crates/f2b-regex from the real upstream
implementation (fail2ban/server/failregex.py, filter.py, datedetector.py).

Usage (from the repository root):

    PYTHONPATH=fail2ban python3 tools/gen_f2b_regex_fixtures.py

Writes testdata/f2b-regex/*.json (sorted keys, compact, deterministic: running
it twice yields byte-identical files). Every expected value is produced by
upstream's `Regex` / `FailRegex` classes (nothing is hand-written): construction
results (expanded text, group tables, error messages), `search()` results
(match span, `getGroups()`, skipped / matched / unmatched lines, failure id,
host, IP), over

  * the 679 expanded regexes of the 146 stock/test filter configurations,
    built from their *unexpanded* config text, against every sample line of
    testdata/samples (raw and as the filter sees it, date stripped),
  * multi-line buffers of consecutive sample lines (tuple lines),
  * seeded mutations of the sample lines (truncate, insert, digit swaps,
    unicode, CRLF),
  * a pattern x subject grid (hand-written snippets, upstream's tests and a
    seeded grammar fuzz) against Python's `re`, also for patterns Python rejects,
  * the Unicode definitions of \\d \\w \\s.

Environment pinned like upstream's sample tests: TZ=CET-01CEST-02,M3.5.0,M10.5.0,
MyTime fixed at 1124013600.
"""
import json
import os
import random
import re
import signal
import sys
import time
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
os.environ["TZ"] = "CET-01CEST-02,M3.5.0,M10.5.0"
time.tzset()
sys.path.insert(0, str(ROOT / "fail2ban"))

from fail2ban.client.filterreader import FilterReader  # noqa: E402
from fail2ban.helpers import splitwords  # noqa: E402,F401
from fail2ban.server import failregex as FR  # noqa: E402
from fail2ban.server.failregex import FailRegex, Regex, RegexException  # noqa: E402
from fail2ban.server.filter import Filter  # noqa: E402
from fail2ban.server.mytime import MyTime  # noqa: E402

MyTime.setTime(1124013600)
warnings.simplefilter("ignore")  # FutureWarning: possible nested set / set operations

# F2B_REGEX_GEN_SCALE=N enlarges the fuzz sections N-fold (exploratory runs; the
# committed fixtures are generated with the default of 1).
SCALE = int(os.environ.get("F2B_REGEX_GEN_SCALE", "1"))
SEED = os.environ.get("F2B_REGEX_GEN_SEED", "")
OUT = Path(os.environ.get("F2B_REGEX_GEN_OUT", ROOT / "testdata" / "f2b-regex"))
UP = ROOT / "fail2ban"
SAMPLES = ROOT / "testdata" / "samples"
TEST_NOW_STR = "2005-08-14 10:00:00"


def fnv64(s):
    h = 0xCBF29CE484222325
    for b in s.encode("utf-8", "surrogatepass"):
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return "%016x" % h


def dump(name, obj):
    OUT.mkdir(parents=True, exist_ok=True)
    text = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    (OUT / name).write_text(text + "\n")
    print("%-22s %8d bytes" % (name, len(text) + 1), file=sys.stderr)


# --------------------------------------------------------------------------
# result encoding
# --------------------------------------------------------------------------
def enc(v):
    if isinstance(v, tuple):
        return {"t": [enc(x) for x in v]}
    return v


def construct_info(obj, full=True):
    """Group/merge tables of a constructed Regex."""
    info = {
        "names": [[k, v] for k, v in obj._regexObj.groupindex.items()],
        "alt": [list(x) for x in (obj._altValues or [])],
        "tuple": [list(x) for x in (obj._tupleValues or [])],
        "flags": obj._regexObj.flags,
    }
    if full:
        info["repr"] = str(obj._regexObj)
    return info


def construct(kind, src, multiline=False, usedns="warn", pref=None):
    """Build upstream's object; returns (obj, expect-dict)."""
    try:
        if kind == "fail":
            obj = FailRegex(src, prefRegex=pref, multiline=multiline, useDns=usedns)
        else:
            obj = Regex(src, multiline=multiline, useDns=usedns)
    except RegexException as e:
        return None, {"ok": False, "type": "RegexException", "msg": str(e)}
    except Exception as e:  # noqa: BLE001 - e.g. OverflowError, RecursionError
        return None, {"ok": False, "type": type(e).__name__, "msg": str(e)}
    info = construct_info(obj)
    info["ok"] = True
    info["regex"] = obj.getRegex()
    return obj, info


def compact_expect(e):
    """Shrink an expected construct record: keep full text only when short."""
    if e.get("ok"):
        e = dict(e)
        e["regex_fnv"] = fnv64(e["regex"])
        e["regex_len"] = len(e["regex"])
        del e["regex"]
    return e


_ID_COUNTER = 0


def _ids_unusual(obj):
    """Always record ids when a failure id is missing or not a plain address."""
    g = obj._matchCache.groupdict()
    return not (g.get("ip4") or g.get("ip6")) or g.get("cidr") is not None


def match_record(obj, buf, org=None, is_fail=False, ids=False):
    """Result of obj.search(buf[, org]) as a compact JSON-able dict (None = no
    match). Group values are listed in `gv` when the dict has exactly the
    regex's named groups in order, otherwise as `g` pairs."""
    if org is None:
        # `search(str)` without original lines crashes upstream on any match
        # (`str.extend`): run the compiled pattern and install the match cache.
        obj._matchCache = obj._regexObj.search(buf)
    else:
        obj.search(buf, org)
    if not obj.hasMatched():
        return None
    mc = obj._matchCache
    r = {"s": mc.start(), "e": mc.end()}
    groups = obj.getGroups()
    if list(groups.keys()) == list(obj._regexObj.groupindex.keys()):
        r["gv"] = [enc(v) for v in groups.values()]
    else:
        r["g"] = [[k, enc(v)] for k, v in groups.items()]
    sk = obj.getSkippedLines()
    if sk:
        r["sk"] = sk
    if org is not None and len(org) > 1:
        idmap = {id(t): i for i, t in enumerate(org)}
        r["m"] = [idmap[id(t)] for t in obj.getMatchedTupleLines()]
        r["u"] = [idmap[id(t)] for t in obj.getUnmatchedTupleLines()]
    elif org is not None:
        assert len(obj.getMatchedTupleLines()) == 1 and obj.getUnmatchedTupleLines() == []
    global _ID_COUNTER
    _ID_COUNTER += 1
    if is_fail and ids and (_ID_COUNTER % 3 == 0 or not obj.hasMatched() or _ids_unusual(obj)):
        ok = {}
        for key, fn in (("fid", obj.getFailID), ("host", obj.getHost)):
            try:
                ok[key] = fn()
            except RegexException:
                ok[key] = None
        try:
            ip = obj.getIP()
            ok["ip"] = [ip.ntoa, ip.plen, ip.familyStr, ip.isValid]
        except RegexException:
            ok["ip"] = None
        except Exception as e:  # noqa: BLE001
            ok["ip"] = "exc:" + type(e).__name__
        r["id"] = ok
    return r


# --------------------------------------------------------------------------
# filter configurations (unexpanded config text)
# --------------------------------------------------------------------------
def load_configs():
    """Per sample-corpus filter configuration: unexpanded regex texts and the
    upstream Filter holding the constructed objects."""
    out = []
    basedirs = {"stock": UP / "config", "tests-config": UP / "fail2ban" / "tests" / "config"}
    for label, basedir in basedirs.items():
        for f in sorted((SAMPLES / label).glob("*.json")):
            data = json.loads(f.read_text())
            combos = {}
            for r in data["records"]:
                combos.setdefault(r["flt_key"], r["filter_options"])
            if not combos:
                combos = {data["filter"]: {}}
            for key, opts in combos.items():
                for usedns in ("warn", "no"):
                    flt = Filter(None)
                    flt.setUseDns(usedns)
                    fr = FilterReader(data["filter"], "jail", dict(opts), basedir=str(basedir))
                    fr.read()
                    fr.getOptions({})
                    entry = {
                        "id": "%s/%s" % (label, key), "label": label, "key": key,
                        "filter": data["filter"], "usedns": usedns, "maxlines": 1,
                        "pref_src": None, "fail_src": [], "ignore_src": [],
                        "datepattern": None, "flt": flt,
                    }
                    for opt in fr.convert():
                        vals = opt[3] if opt[0] == "multi-set" else [opt[3]]
                        for v in vals:
                            if opt[2] == "prefregex":
                                flt.prefRegex = v
                                entry["pref_src"] = v
                            elif opt[2] == "addfailregex":
                                flt.addFailRegex(v)
                                entry["fail_src"].append(v)
                            elif opt[2] == "addignoreregex":
                                flt.addIgnoreRegex(v)
                                entry["ignore_src"].append(v)
                            elif opt[2] == "maxlines":
                                flt.setMaxLines(v)
                                entry["maxlines"] = int(v)
                            elif opt[2] == "datepattern":
                                flt.setDatePattern(v)
                                entry["datepattern"] = v
                    entry["records"] = data["records"] if usedns == "warn" else []
                    out.append(entry)
    return out


def objs_of(entry):
    flt = entry["flt"]
    pref = flt.prefRegex
    fails = list(flt._Filter__failRegex)
    ignores = list(flt._Filter__ignoreRegex)
    return pref, fails, ignores


def gen_configs(configs):
    """configs.json: unexpanded sources + construction expectations."""
    res = []
    for e in configs:
        pref, fails, ignores = objs_of(e)
        res.append({
            "id": e["id"], "usedns": e["usedns"], "maxlines": e["maxlines"],
            "pref_src": e["pref_src"], "fail_src": e["fail_src"], "ignore_src": e["ignore_src"],
            "pref": compact_expect(dict(construct_info(pref, False), ok=True, regex=pref.getRegex())) if pref else None,
            "fail": [compact_expect(dict(construct_info(o, False), ok=True, regex=o.getRegex())) for o in fails],
            "ignore": [compact_expect(dict(construct_info(o, False), ok=True, regex=o.getRegex())) for o in ignores],
        })
    dump("configs.json", res)


# --------------------------------------------------------------------------
# sample lines -> tuple lines as the filter sees them
# --------------------------------------------------------------------------
def tuple_line(entry, rec):
    flt = entry["flt"]
    line = rec["line"]
    if rec.get("logtype") == "journal":
        if rec.get("prefix_line"):
            line = rec["prefix_line"] + line
        return ("", TEST_NOW_STR, line)
    tm = flt.dateDetector.matchTime(line)
    m = tm[0]
    if m:
        s, e = m.start(1), m.end(1)
        return (line[:s], line[s:e], line[e:])
    return ("", "", line)


def unique_lines(entry):
    seen = {}
    for rec in entry["records"]:
        key = (rec["line"], rec.get("logtype"), rec.get("prefix_line"))
        if key not in seen:
            seen[key] = rec
    return list(seen.values())


def regex_list(entry):
    pref, fails, ignores = objs_of(entry)
    out = []
    if pref:
        out.append(("pref", pref, False))
    out += [("f%d" % i, o, True) for i, o in enumerate(fails)]
    out += [("i%d" % i, o, False) for i, o in enumerate(ignores)]
    return out


def gen_search(configs):
    """search.json: every regex x every sample line (raw str and tuple form)."""
    res = {}
    for e in configs:
        if e["usedns"] != "warn":
            continue
        recs = unique_lines(e)
        tuples = [tuple_line(e, rec) for rec in recs]
        journal = bool(recs) and recs[0].get("logtype") == "journal"
        results = {}
        for rid, obj, is_fail in regex_list(e):
            per = {}
            for i, t in enumerate(tuples):
                org = [t]
                tup = match_record(obj, Regex._tupleLinesBuf(org), org, is_fail, ids=True)
                if tup:
                    per["t%d" % i] = tup
                raw_buf = t[2] if journal else "".join(t)
                raw = match_record(obj, raw_buf, None, is_fail)
                if raw:
                    if tup and raw.get("gv") == tup.get("gv") and raw.get("g") == tup.get("g"):
                        raw.pop("gv", None)
                        raw.pop("g", None)
                        raw["same"] = 1
                    per["r%d" % i] = raw
            results[rid] = per
        res[e["id"]] = {"journal": journal, "tuples": [list(t) for t in tuples], "res": results}
    dump("search.json", res)


NODNS_LINES = 14


def gen_search_nodns(configs):
    """usedns=no variant: only matches over tuple lines (ADDR instead of HOST)."""
    base = {c["id"]: c for c in configs if c["usedns"] == "warn"}
    res = {}
    for e in configs:
        if e["usedns"] != "no":
            continue
        b = base[e["id"]]
        recs = unique_lines(b)[:NODNS_LINES]
        results = {}
        for rid, obj, is_fail in regex_list(e):
            per = {}
            for i, rec in enumerate(recs):
                t = tuple_line(b, rec)
                org = [t]
                m = match_record(obj, Regex._tupleLinesBuf(org), org, is_fail)
                if m:
                    per["t%d" % i] = m
            results[rid] = per
        res[e["id"]] = results
    dump("search_nodns.json", res)


def gen_multi(configs, max_lines_windows=1500):
    """multi.json: windows of 2-4 consecutive lines as tuple lines, regexes
    compiled with multiline=True (as filters with maxlines > 1 do)."""
    res = {}
    for e in configs:
        if e["usedns"] != "warn":
            continue
        recs = unique_lines(e)
        tl = [tuple_line(e, r) for r in recs]
        is_ml = e["maxlines"] > 1
        pref, fails, ignores = objs_of(e)
        # regexes recompiled multiline (what a maxlines > 1 filter holds):
        objs = []
        if e["pref_src"]:
            objs.append(("pref", Regex(e["pref_src"], useDns="warn"), False))
        mp = objs[0][1] if objs else None
        for i, src in enumerate(e["fail_src"]):
            objs.append(("f%d" % i, FailRegex(src, prefRegex=mp, multiline=True, useDns="warn"), True))
        for i, src in enumerate(e["ignore_src"]):
            objs.append(("i%d" % i, Regex(src, useDns="warn"), False))
        n = len(tl)
        windows = []
        step = 1 if is_ml else 3
        for start in range(0, n, step):
            for size in (2, 3, 4):
                if start + size <= n:
                    windows.append((start, size))
        if not is_ml and len(windows) > 16:
            rnd = random.Random("multi/" + e["id"])
            windows = sorted(rnd.sample(windows, 16))
        results = {}
        for rid, _, _ in objs:
            results[rid] = {}
        for wi, (start, size) in enumerate(windows):
            org = [tuple(t) for t in tl[start:start + size]]
            buf = Regex._tupleLinesBuf(org)
            for rid, obj, is_fail in objs:
                m = match_record(obj, buf, org, is_fail)
                if m:
                    results[rid][str(wi)] = m
        res[e["id"]] = {"multiline_cfg": is_ml, "tuples": [list(t) for t in tl],
                        "wins": [list(w) for w in windows], "res": results}
    dump("multi.json", res)


# --------------------------------------------------------------------------
# mutation fuzz
# --------------------------------------------------------------------------
UNICODE_BITS = ["\u00e9", "\u00df", "\u0130", "\u01c5", "\u00b2", "\u00bd", "\u2167", "\u0663",
                "e\u0301", "\u00a0", "\x1c", "\x1f", "\u2028", "\u0085", "\U0001f600", "\u4e2d",
                "\u212a", "\u017f", "\u0345", "\u200b", "\ufeff", "\x00", "\x0b", "\x0c"]


def mutate(rnd, s):
    kind = rnd.randrange(12)
    if not s:
        return s
    if kind == 0:  # truncate
        return s[: rnd.randrange(len(s))]
    if kind == 1:  # drop head
        return s[rnd.randrange(len(s)):]
    if kind == 2:  # insert printable ascii
        i = rnd.randrange(len(s) + 1)
        return s[:i] + chr(rnd.randrange(32, 127)) * rnd.randrange(1, 3) + s[i:]
    if kind == 3:  # swap digits
        idx = [i for i, c in enumerate(s) if c.isdigit()]
        if idx:
            i = rnd.choice(idx)
            return s[:i] + str(rnd.randrange(10)) + s[i + 1:]
        return s + "9"
    if kind == 4:  # unicode insert
        i = rnd.randrange(len(s) + 1)
        return s[:i] + rnd.choice(UNICODE_BITS) + s[i:]
    if kind == 5:  # unicode replace
        i = rnd.randrange(len(s))
        return s[:i] + rnd.choice(UNICODE_BITS) + s[i + 1:]
    if kind == 6:  # CRLF / trailing ws
        return s + rnd.choice(["\r", "\r\n", " ", "\t", "\n", "  \r", "\u00a0", "\x1c"])
    if kind == 7:  # delete char
        i = rnd.randrange(len(s))
        return s[:i] + s[i + 1:]
    if kind == 8:  # duplicate a slice
        i = rnd.randrange(len(s))
        j = rnd.randrange(i, len(s))
        return s[:j] + s[i:j + 1] + s[j:]
    if kind == 9:  # upper/lower case flip
        i = rnd.randrange(len(s))
        return s[:i] + s[i].swapcase() + s[i + 1:]
    if kind == 10:  # replace spaces by other whitespace
        return s.replace(" ", rnd.choice(["\t", "  ", "\u00a0", "\x1d", "\u2003"]), 1)
    # ip-ish swaps
    return s.replace(".", rnd.choice([":", "..", ",", "::"]), 1)


def gen_fuzz(configs, per_config=20 * SCALE):
    res = {}
    for e in configs:
        if e["usedns"] != "warn":
            continue
        rnd = random.Random("fuzz/" + e["id"] + SEED)
        recs = unique_lines(e)
        if not recs:
            continue
        journal = e["records"][0].get("logtype") == "journal"
        lines = []
        for _ in range(per_config):
            rec = rnd.choice(recs)
            s = rec["line"]
            for _ in range(rnd.randrange(1, 4)):
                s = mutate(rnd, s)
            lines.append(s)
        tuples = []
        for s in lines:
            if journal:
                tuples.append(("", TEST_NOW_STR, s))
                continue
            tm = e["flt"].dateDetector.matchTime(s)
            if tm[0]:
                a, b = tm[0].start(1), tm[0].end(1)
                tuples.append((s[:a], s[a:b], s[b:]))
            else:
                tuples.append(("", "", s))
        results = {}
        for rid, obj, is_fail in regex_list(e):
            per = {}
            for i, (s, t) in enumerate(zip(lines, tuples)):
                org = [t]
                tup = match_record(obj, Regex._tupleLinesBuf(org), org, is_fail)
                if tup:
                    per["t%d" % i] = tup
                raw = match_record(obj, s, None, is_fail)
                if raw:
                    if tup and raw.get("gv") == tup.get("gv") and raw.get("g") == tup.get("g"):
                        raw.pop("gv", None)
                        raw.pop("g", None)
                        raw["same"] = 1
                    per["r%d" % i] = raw
            results[rid] = per
        res[e["id"]] = {"journal": journal, "tuples": [list(t) for t in tuples], "res": results}
    dump("fuzz.json", res)


# --------------------------------------------------------------------------
# pattern x subject grid (Python `re` conformance), tag expansion, ids
# --------------------------------------------------------------------------
SUBJECTS = [
    "", "\n", "a", "a\n", "aa", "ab", "abc", "abc\n", "Abc", "ABC", "a b", "a  b\n", "foo bar baz\n",
    "foo\nbar\n", "\nfoo\n", "foo\n\n", "a\nb\nc\n", "a:b::c", "1.2.3.4", "1.2.3.4\n",
    "192.168.0.1 port 22\n", "::1", "2001:db8::1", "[::1]", "::ffff:1.2.3.4", "abc123_x.y-z",
    "x=1,y=2", "a\r\n", "a\rb", "\t a \t", "aaaa", "abab", "aXbXc", "foo(bar)", "[x]", "a-b",
    "a&&b", "a~~b", "a--b", "a{2}", "{", "a.b", "a|b", "a^b", "a$b", "abcabc", "aabb", "ba",
    "user: john from 10.0.0.1 port 22 ssh2\n", "key: value\n", "12:34:56", "Jan  1 00:00:00 host x\n",
    # unicode / classes where Python and Rust definitions could differ
    "\u00e9", "\u00c9", "\u00df", "SS", "\u01c6", "\u01c5", "k", "K", "\u212a", "\u017f", "s", "S",
    "\u00b2", "\u00bd", "\u2167", "\u0663", "e\u0301", "a\u00a0b", "a\x1cb", "a\x1fb", "a\u2028b",
    "a\x85b", "\u65e5\u672c\u8a9e", "\U0001f600", "x\u00e9y", "na\u00efve caf\u00e9", "\u0345",
    "\u03b9", "\u0399", "\u0131", "I", "i", "\u0130", "a\u200bb", "a\ufeffb", "a\x00b", "a\x0bb", "a\x0cb",
]

PATTERNS = [
    # escapes and classes
    r"\d", r"\D+", r"\s", r"\S+", r"\w+", r"\W+", r"[\d]", r"[\w\-.^_]*\w", r"[^\s]", r"[\W\d]",
    r"[^\W]", r"[\S\s]", r"[\d\D]", r"[^\d\D]", r"[[]", r"[^[]*", r"[a-z&&[^b]]", r"[a&&b]",
    r"[a~~b]", r"[a--b]", r"[--a]", r"[a-]", r"[-a]", r"[]a]", r"[^]a]", r"[\]]", r"[\\]",
    r"[\[\]]", r"[a|b]", r"[a-c-e]", r"[\x41-\x5a]", r"[\u00e9]", r"[\U0001F600]", r"\x41",
    r"\101", r"\0", r"\012", r"\u00e9", r"[\b]", r"\a\f\n\r\t\v", r"[a-z]+", r"[A-Za-z0-9_]+",
    r"[^a-z]", "[\u00e9-\u00fc]", r"[\w-]", r"[\w-a]", r"[\d-\w]", r"[a-\d]", r"[z-a]", r"[a-",
    r"[a", r"[", r"]", r"}", r"\x4", r"\xg1", r"\u12", r"\U0010FFFF", r"\U00110000", r"\ud800",
    r"[\ud800]", r"\q", r"\8", r"\9", r"[\8]", r"\400", r"[\400]", r"\777", r"\1", "\\", "a\\",
    r"\N{DIGIT ONE}", r"\N{digit one}", r"\N{NULL}", r"\N{LINE FEED}", r"\N{EM DASH}", r"\N{BELL}",
    r"\N{ZERO WIDTH SPACE}", r"\N{CJK UNIFIED IDEOGRAPH-4E00}", r"\N{HANGUL SYLLABLE GA}",
    r"\N{KATAKANA LETTER AINU P}", r"\N{nonexistent}", r"\N{}", r"\N", r"\N{A", r"\N{LATIN SMALL LETTER A }",
    r"[\N{DIGIT ONE}-\N{DIGIT NINE}]", r"\N{LATIN SMALL LETTER E WITH ACUTE}+", r"\N{ALERT}", r"\N{LF}", r"\N{BEL}",
    r"(?i)\N{LATIN SMALL LETTER K}", r"\N{KELVIN SIGN}", r"\N{DIGIT_ONE}", r"\N{DIGIT-ONE}", r"\N {DIGIT ONE}",
    r"\-", r"\ ", r"\#", r"\&", r"\~", r"\<", r"\>", r"\:", r"\\n", r"\/",
    r"\Z", r"\z", r"\A", r"\B", r"\b", r"\_", r"\p{L}", r"\P{L}", r"\h", r"\e", r"\E", r"\G", r"\k<a>",
    r"[\p]", r"[\e]", r"[\A]", r"[\Z]", r"[\B]",
    # anchors
    r"^a", r"a$", r"^$", r"\Aa", r"a\Z", r"a\z", r"(?m)^a$", r"\bfoo\b", r"\Bfoo", r"a\b",
    r"^", r"$", r"^^", r"$$", r"(^|a)", r"a|^b", r"a$|b", r"^a|b$", r"(?m)$", r"(?m)^",
    r"a$\n", r"a\n$", r"^\s*$", r"\s*$", r"\s+$", r"a\s*$", r".*$", r"(?:a|$)", r"a(?=$)", r"x*$",
    r"$\n^", r"^.*\n", r"^.*$", r"^.+$", r".*\n.*", r"(?s)^.*$", r"(?s).", r"(?s:.)", r".", r"\n", r"a.b",
    # quantifiers
    r"a*", r"a+", r"a?", r"a{2}", r"a{2,}", r"a{,3}", r"a{2,3}", r"a{}", r"a{", r"a{1", r"a{1,",
    r"a{1,2", r"a{x}", r"a{ 1}", r"a{1 }", r"a*?", r"a+?", r"a??", r"a{2,3}?", r"a*+", r"a++",
    r"a?+", r"a{2}+", r"(?:a+|b){2}+", r"(?:a|ab)++c", r"(?:a|ab){1}+c", r"(?:a|ab)*+c", r"(?:a+?|b){2}+", r"(?:a+)*+a",
    r"(a+|b)++", r"(?:ab|a)?+b", r"(?:a*|b){2,3}+c", r"(?:a|b)++b", r"(?:[ab]c?){2}+", r"\d++\d", r"(?:\d+\.)++\d", r"a**", r"a+*", r"a*??", r"a*+?", r"*a", r"+", r"?", r"a|*", r"(?:a*)*",
    r"(a*)*", r"(a*)+", r"(a|b*)*", r"(?:)*", r"()*", r"(?=a)*", r"(?!a)+", r"\b*", r"^*",
    r"$?", r"(?:^)*", r"a{99999999999}", r"a{4294967295}", r"a{4294967294}", r"a{3,2}",
    r"a{0}", r"a{0,0}", r"(a){0}b", r"(?:a|b){2}", r"(a|b){2}c?", r"(a)|b", r"(a)?b", r"(a)*b",
    r"(?:(a)|b)*", r"(?:(a)|(b))+", r"((a)|b)+", r"(a?)*", r"(a?)+?", r"(|a)+", r"(a|)+", r"(?:a?)*?b",
    r"x{2,1}", r"{1}", r"a|{1}", r"a{1}{2}", r"(?i)a{2}",
    # groups
    r"(a)", r"(?:a)", r"(?P<n>a)", r"(?P<n>a)(?P=n)", r"(?P<n>a)\1", r"(a)\1", r"(a)(b)\2\1",
    r"\1(a)", r"(a\1)", r"(?P<1>a)", r"(?P<n-x>a)", "(?P<\u00e9>a)", r"(?P<n>a)(?P<n>b)", r"(?P=x)",
    r"(?P<n>", r"(?P", r"(?P>", r"(?<n>a)", r"(?'n'a)", r"(?#comment)a", r"a(?#c)*", r"(?#unterminated",
    r"(?", r"(?x", r"(?i)a", r"a(?i)", r"(?i)(?m)a", r"(?i:a)b", r"(?-i:a)", r"(?i-m:a)", r"(?i-i:a)",
    r"(?L)a", r"(?a)\w", r"(?u)\w", r"(?au)", r"(?x) a b # c", r"(?x: a b )c", r"(?m)^a", r"(?ims)",
    r"(?z)", r"(?i", r"((?i)a)", r"(?:(?i)a)", r"a|((?i)b)", r"(?>a+)b", r"(?>a)", r"(?>a|ab)c",
    r"(?P<a>x)(?(a)y|z)", r"(x)?(?(1)y|z)", r"(x)?(?(1)y)", r"(x)?(?(2)y)", r"(?(1)a)(b)",
    r"(?(0)a)", r"(?(a)b)", r"(?(1)a|b|c)", r"(?(n)", r"(a)(?(1)b|c)d", r"(?:(a)|b)(?(1)c|d)",
    r"(?P<n>a)?(?(n)b|c)", r"(?()a)", r"(?(1)", r"(?(é)a)", r"(?(\1)a)",
    r"(?-i)a", r"(?i-)a", r"(?-)", r"(?i:", r"(?-i", r"(?s-s:.)", r"(?a:\w)\w", r"(?u:\w)", r"(?a-u:a)",
    r"(?x) a # comment\n b", "(?x)a # comment\n b", "(?x)a\\ b", "(?x)[ a ]", "(?x:a #c\n)b",
    r"()", r"(())", r"((a))", r"(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)\10", r"(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)(k)\11",
    r")", r"(", r"a)", r"(a", r"((a)", r"(a))", r"a(|b)", r"|", r"a|", r"|a", r"||", r"(|)",
    # lookarounds
    r"a(?=b)", r"a(?!b)", r"(?<=a)b", r"(?<!a)b", r"(?<=a|b)c", r"(?<=a|bc)d", r"(?<=a+)b",
    r"(?<=(a))b", r"(?<=\1)(a)", r"(?<=:):", r"(?!)", r"(?<!)", r"(?=)", r"(?<=)a", r"(?<a)",
    r"(?<=a", r"a(?!b)+", r"(?<=\d)x", r"(?<=\bx)y", r"(?<=^a)b", r"(?<=a$)", r"(?<![a-z])\d",
    r"(?=.*a)b", r"^(?=.*\d)(?=.*[a-z]).+$", r"(?<=[:,]) ", r"x(?<=x)", r"(?<=ab|cd)e", r"(?<=a{2})b",
    r"(?<=(?:a|b){2})c", r"(?<=a?)b", r"(?<=a*)b", r"(?<=(?i:a))b", r"(?i)(?<=a)b", r"(?<=\w)(?=\W)",
    r"(?<=:)(?<=:):", r"[a-f]{1,4}(?<=:):", r"(?:[0-9a-fA-F]{1,4}::?|:){1,7}(?:[0-9a-fA-F]{1,4}|(?<=:):)",
    r"(?:a:|:){1,3}(?<=:):", r"(?:a:|:)(?<=:):", r"(?:a:?)(?<=:):", r"(?:a:?|:)(?<=:):", r"b:(?<=:)c",
    r"(?:a|:)(?<=:):",
    # unicode / case
    "\u00e9", r"(?i)\u00e9", "(?i)\u00e9", "(?i)\u00df", "(?i)\u01c6", "(?i)K", "(?i)\u212a",
    "(?i)\u017f", r"(?i)[a-z]+", r"(?i)\w+", r"(?i)[^k]", r"(?i)[^\u00e9]", "(?i)[\u00e0-\u00ff]+",
    r"(?i)ss", r"(?i)i", r"(?i)\u0131", r"(?i)\u03b9", r"(?i)[\u03b9]", r"(?a)(?i)\u017f", r"(?i)(?a)k", r"(?ai)[a-z]+", r"(?ai)[^k]", r"(?ai)[\u212a]", "(?ai)\u00e9", r"(?ai)[A-C]x",
    r"(?i)(?:a)\1", r"(?i)(a)\1", r"(?i:(a))\1", r"(?i)(a)(?-i:\1)", r"(?i)\b", r"\w\b\w", r"\b\w+\b", r"\B\w",
    r"(?a)\b\w+\b", r"(?a)\B", r"\W\b", r"\b\W", r"\b.\b", r"a\Bb", r"\B\B", r"\b\b", r"(?:\b|x)y", r"x(?:\b|\B)y",
    # Fail2Ban tags
    r"<HOST>", r"^<HOST>$", r"<ADDR>", r"<IP4>", r"<IP6>", r"<DNS>", r"<CIDR>", r"<SUBNET>",
    r"<F-ID/>", r"<F-PORT/>", r"<F-USER>\S+</F-USER>", r"</F-USER>", r"<F-A-B>x</F-A-B>",
    r"<F-NOFAIL>x</F-NOFAIL>", r"<F-ALT_USER_1>a</F-ALT_USER_1>|<F-USER>b</F-USER>",
    r"<F-TUPLE_ID_1>a</F-TUPLE_ID_1> <F-ID>b</F-ID>", r"<F-TUPLE_USER_1>a</F-TUPLE_USER_1><F-TUPLE_USER_2>b</F-TUPLE_USER_2>",
    r"<SKIPLINES>", r"^a<SKIPLINES>^b", r"<SKIPLINES>x<SKIPLINES>", r"<F-X/>", r"<F-1>x</F-1>",
    r"<F-MLFID>\d+</F-MLFID>", r"<F-MLFFORGET>x</F-MLFFORGET>", r"<F-CIDR>\d+</F-CIDR>", r"<F-id>a</F-id>",
    r"<F-ID>a</F-ID></F-ID>", r"<F-ID><F-ID>a</F-ID></F-ID>", r"<F-ID>a</F-ID> </F-USER><F-USER>b", r"<f-id>x</f-id>",
    r"<F-\u00e9>x</F-\u00e9>", r"<>", r"</>", r"<a>", r"<a b>", r"<host>", r"<HOST/>", r"< HOST>", r"<<HOST>>",
    r"<HOST><HOST>", r"[<HOST>]", r"<F-USER>(?:\S+|.*?)</F-USER>", r"user (?P<user>\S+) from <HOST>",
    r"<F-ALT_HOST>x</F-ALT_HOST>", r"<F-ALT_ID_1>a</F-ALT_ID_1><F-ID>b</F-ID>", r"<F-ALT_USER_1>a</F-ALT_USER_1>",
    r"<F-ALT_USER_2>a</F-ALT_USER_2><F-ALT_USER_10>b</F-ALT_USER_10><F-ALT_USER_1>c</F-ALT_USER_1>",
    r"<F-ALT_A>a</F-ALT_A>", r"<F-ALT_>a</F-ALT_>", r"<F-ALT_1>a</F-ALT_1>", r"<F-TUPLE_A_1_2>a</F-TUPLE_A_1_2>",
    r"<F-TUPLE_USER_1>a</F-TUPLE_USER_1>", r"<F-USER>x</F-USER><F-TUPLE_USER_1>y</F-TUPLE_USER_1>",
    r"<F-ALT_USER_1>(a)?</F-ALT_USER_1><F-USER>b</F-USER>", r"<F-ALT_USER_1></F-ALT_USER_1><F-USER>b</F-USER>",
    r"<F-ALT_PORT_1>a</F-ALT_PORT_1>", r"<F-TUPLE_PORT_1>a</F-TUPLE_PORT_1>", r"<F-TUPLE_ID_2>a</F-TUPLE_ID_2>",
    # empty / whitespace / misc
    "", " ", "\t", "  \n", "(?:)", r"\s", r"(?# only comment)", r"a(?#x)(?#y)b",
    "a\nb", "a\nb(", "(?x)a\nb(", "\n(", "(?P<n>a)(?P<n>b)\n(",
]


def run_with_timeout(fn, seconds=3):
    def handler(signum, frame):
        raise TimeoutError()
    signal.signal(signal.SIGALRM, handler)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        return fn()
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


def has_empty_loop(regex_text):
    """True when the pattern repeats (more than once) a body that can match the
    empty string. Python stops such a loop after an empty iteration but keeps
    that iteration's captures, which the Rust engines do not emulate."""
    import re._parser as sp
    from re._constants import MAX_REPEAT, MIN_REPEAT, POSSESSIVE_REPEAT, SUBPATTERN, BRANCH, GROUPREF_EXISTS, \
        ASSERT, ASSERT_NOT, ATOMIC_GROUP, MAXREPEAT  # noqa: F401

    def walk(sub):
        for op, av in sub.data:
            if op in (MAX_REPEAT, MIN_REPEAT, POSSESSIVE_REPEAT):
                lo, hi, item = av
                if item.getwidth()[0] == 0 and hi > 1:
                    return True
                if walk(item):
                    return True
            elif op is SUBPATTERN:
                if walk(av[-1]):
                    return True
            elif op is BRANCH:
                if any(walk(a) for a in av[1]):
                    return True
            elif op is GROUPREF_EXISTS:
                if walk(av[1]) or (av[2] is not None and walk(av[2])):
                    return True
            elif op in (ASSERT, ASSERT_NOT):
                if walk(av[1]):
                    return True
            elif op is ATOMIC_GROUP:
                if walk(av):
                    return True
        return False
    try:
        return walk(sp.parse(regex_text))
    except Exception:  # noqa: BLE001
        return False


def grid_entry(pattern, multiline, subjects, extra_subjects=(), usedns="warn", brief=False):
    obj, expect = construct("regex", pattern, multiline, usedns)
    if brief and expect.get("ok"):
        # fuzz entries: the repr is only checked on the hand-written grid
        expect.pop("repr", None)
    if expect.get("ok") and expect["regex"] == pattern:
        del expect["regex"]
        expect["same_regex"] = 1
    rec = {"p": pattern, "ml": multiline, "c": expect}
    if obj is None:
        return rec
    res = {}
    try:
        def go():
            for i, subj in enumerate(list(subjects) + list(extra_subjects)):
                m = match_record(obj, subj, None, False)
                if m:
                    res[str(i)] = m
        run_with_timeout(go)
    except TimeoutError:
        return None
    except RecursionError:
        return None
    rec["r"] = res
    if has_empty_loop(obj.getRegex()):
        rec["el"] = 1
    if extra_subjects:
        rec["xs"] = list(extra_subjects)
    return rec


# -- seeded grammar fuzz ----------------------------------------------------
ALPHA = ["a", "b", "c", "A", "B", "\u00e9", "1", "_", " ", ":", ".", "-", "\n", "k", "K", "\u212a", "\u00df"]
ESC_CATS = [r"\d", r"\w", r"\s", r"\D", r"\W", r"\S"]


class Gen:
    def __init__(self, rnd):
        self.r = rnd
        self.groups = 0
        self.names = []
        self.closed = []

    def lit(self):
        c = self.r.choice(ALPHA)
        return re.escape(c) if self.r.random() < 0.5 else c.replace("\\", "\\\\") if c in "\\" else c

    def cls(self):
        r = self.r
        items = []
        for _ in range(r.randrange(1, 4)):
            k = r.randrange(6)
            if k == 0:
                items.append(r.choice(ESC_CATS))
            elif k == 1:
                lo, hi = sorted(r.sample(["a", "b", "c", "k", "z", "0", "9", "A", "\u00e0", "\u00ff"], 2))
                items.append("%s-%s" % (lo, hi))
            elif k == 2:
                items.append(r.choice(["[", "&&", "~~", "--", "-", "^", "|", "\\]", "\\\\"]))
            else:
                items.append(re.escape(r.choice(ALPHA)) if r.random() < 0.5 else r.choice("abc1_ :.-"))
        neg = "^" if r.random() < 0.3 else ""
        return "[" + neg + "".join(items) + "]"

    def fixed_width(self, depth):
        r = self.r
        k = r.randrange(5)
        if k == 0:
            return self.lit()
        if k == 1:
            return self.cls()
        if k == 2:
            return r.choice(ESC_CATS)
        if k == 3:
            return self.lit() + self.lit()
        return "(?:%s|%s)" % (self.lit(), self.lit())

    def atom(self, depth):
        r = self.r
        k = r.randrange(24)
        if k <= 3:
            return self.lit()
        if k == 4:
            return "."
        if k == 5:
            return self.cls()
        if k == 6:
            return r.choice(ESC_CATS)
        if k == 7:
            return r.choice(["^", "$", r"\b", r"\B", r"\A", r"\Z", r"\z"])
        if depth <= 0:
            return self.lit()
        if k == 8:
            self.groups += 1
            n = self.groups
            body = self.alt(depth - 1)
            self.closed.append(n)
            return "(%s)" % body
        if k == 9:
            return "(?:%s)" % self.alt(depth - 1)
        if k == 10:
            self.groups += 1
            n = self.groups
            name = r.choice(["g%d" % n, "alt_x_%d" % n, "tuple_t_%d" % n, "n%d" % n, "skiplines0" if n == 1 else "s%d" % n])
            body = self.alt(depth - 1)
            self.closed.append(n)
            self.names.append(name)
            return "(?P<%s>%s)" % (name, body)
        if k == 11:
            return "(?=%s)" % self.alt(depth - 1) if r.random() < 0.5 else "(?!%s)" % self.alt(depth - 1)
        if k == 12:
            return "(?<=%s)" % self.fixed_width(depth) if r.random() < 0.5 else "(?<!%s)" % self.fixed_width(depth)
        if k == 13 and self.closed:
            n = r.choice(self.closed)
            if r.random() < 0.5 or not self.names:
                return "\\%d" % n
            return "(?P=%s)" % r.choice(self.names)
        if k == 14 and self.closed:
            n = r.choice(self.closed)
            return "(?(%d)%s|%s)" % (n, self.seq(depth - 1), self.seq(depth - 1)) if r.random() < 0.6 else "(?(%d)%s)" % (n, self.seq(depth - 1))
        if k == 15:
            return "(?>%s)" % self.alt(depth - 1)
        if k == 16:
            return "(?%s:%s)" % (r.choice(["i", "s", "m", "-i", "i-s", "a", "u", "x"]), self.alt(depth - 1))
        if k == 17:
            return "(?#c)"
        return self.lit()

    def quant(self):
        r = self.r
        k = r.randrange(10)
        q = ["", "", "", "*", "+", "?", "{2}", "{1,2}", "{,2}", "{2,}"][k]
        if q and r.random() < 0.25:
            q += r.choice(["?", "+"])
        return q

    def seq(self, depth):
        r = self.r
        n = r.randrange(0, 4)
        return "".join(self.atom(depth) + self.quant() for _ in range(n))

    def alt(self, depth):
        r = self.r
        parts = [self.seq(depth) for _ in range(r.choice([1, 1, 1, 2, 3]))]
        return "|".join(parts)

    def pattern(self):
        r = self.r
        p = self.alt(3)
        if r.random() < 0.15:
            p = r.choice(["(?i)", "(?s)", "(?m)", "(?a)", "(?im)", "(?x) "]) + p
        return p


def random_subject(rnd):
    n = rnd.randrange(0, 9)
    return "".join(rnd.choice(ALPHA + ["\n", "\r", "ab", "\u0345", "\x1c", "\u00a0", "\u0663", "\u00b2"]) for _ in range(n))


FUZZ_SUBJECTS = 22
FUZZ_PATTERNS = 1500 * SCALE


def gen_engine():
    entries = []
    for p in PATTERNS:
        # MULTILINE only changes ^, $ (and inline flags / tag expansions):
        mls = (False, True) if re.search(r"\^|\$|\(\?|<|\n", p) else (False,)
        for ml in mls:
            e = grid_entry(p, ml, SUBJECTS)
            if e:
                entries.append(e)
    rnd = random.Random("engine-fuzz" + SEED)  # same seed: scale only extends the sequence
    seen = set()
    n_fuzz = 0
    attempts = 0
    while n_fuzz < FUZZ_PATTERNS and attempts < 40000:
        attempts += 1
        g = Gen(rnd)
        p = g.pattern()
        if p in seen:
            continue
        seen.add(p)
        extra = [random_subject(rnd) for _ in range(6)]
        ml = rnd.random() < 0.35
        e = grid_entry(p, ml, SUBJECTS[:FUZZ_SUBJECTS], extra, brief=True)
        if e:
            entries.append(e)
            n_fuzz += 1
    dump("engine.json", {"subjects": SUBJECTS, "fuzz_subject_count": FUZZ_SUBJECTS, "entries": entries})


TAG_INPUTS = [
    "<HOST>", "<ADDR>", "<IP4>", "<IP6>", "<DNS>", "<CIDR>", "<SUBNET>", "<F-IP4/>", "<F-IP6/>", "<F-ADDR/>",
    "<F-CIDR/>", "<F-SUBNET/>", "<F-DNS/>", "<F-ID/>", "<F-PORT/>", "<F-ID>x</F-ID>", "<F-PORT>x</F-PORT>",
    "<F-USER>a</F-USER>", "</F-USER>", "<F-USER></F-USER></F-USER>", "<F-A>x</F-B></F-A>",
    "<F-ID></F-ID><F-ID>", "<SKIPLINES><SKIPLINES><SKIPLINES>", "<F-X/>", "<F-ID/><F-ID/>", "<F-ID /",
    "<F-ID/", "<HOST", "HOST>", "<<HOST>", "<HOST>>", "<ho st>", "<F-USER-X>a</F-USER-X>", "<F-U_1>", "<F-0>",
    "<F-\u00e9>", "<\u00e9>", "<\u0663>", "<a\u0345>", "<-->", "</-->", "<->", "<_>", "</_/>", "<//>", "<a//>",
    "<a/b>", "</ a>", "<F->", "<F-/>", "</F->", "<F-a>", "<f-id/>", "<F-ID/ >", "<F-ID/>/>", "</F-ID/>",
    "<F-ALT_USER_1>x</F-ALT_USER_1>", "<F-tuple_a>x", "<F-TUPLE_A_1>x</F-TUPLE_A_1>", "<F-A.B>", "<F-A B>",
    "a<HOST>b<HOST>c", "<IP4><IP6><DNS>", "<F-USER>", "<F-USER>x", "x</F-USER>", "<F-PORT>x</F-PORT></F-PORT>",
    "((?i)abc)", "(?:(?i)abc)", "x((?i)a)y((?s)b)", "\\((?i)a)", "\\\\((?i)a)", "((?i)a", "((?i))", "(?:(?i)(?s)a)",
    "((?ims)a)", "((?x)a)", "((?-i)a)", "((?P<n>a))", "((?:i)a)", "(?i)a", "((?i)((?m)a))", "((?I)a)", "(((?i)a))",
    "(?:((?i)a))", "((?i)a)|((?s)b)", "\\\\\\((?i)a)", "[((?i)a)]", "((?i)\n)", "((?a)\u00e9)",
    "", " ", "plain", "<>", "<", ">", "</", "/>", "<F-ID>", "<F-ID>\n</F-ID>",
]


def gen_tags():
    out = []
    for src in TAG_INPUTS:
        for usedns in ("yes", "warn", "no", "raw"):
            exp = Regex._resolveHostTag(src, useDns=usedns)
            out.append({"src": src, "usedns": usedns, "tag": exp,
                        "glob": FR.R_GLOB2LOCFLAGS[0].sub(FR.R_GLOB2LOCFLAGS[1], exp) if FR.R_GLOB2LOCFLAGS else exp})
    # Whole constructor on the tag inputs (error text, empty handling):
    cons = []
    for src in TAG_INPUTS:
        for ml in (False, True):
            _, e = construct("regex", src, ml)
            cons.append({"src": src, "ml": ml, "c": e})
        _, e = construct("fail", src, False)
        cons.append({"src": src, "ml": False, "kind": "fail", "c": e})
    dump("tags.json", {"resolve": out, "construct": cons})


FAIL_PATTERNS = [
    r"<HOST>", r"^<HOST>$", r"<ADDR>", r"<IP4>", r"<IP6>", r"<DNS>", r"<F-ID/>", r"<SUBNET>", r"^<ADDR>/<CIDR>$",
    r"<ADDR>/<F-CIDR>\d+</F-CIDR>", r"<F-MLFID>\d+</F-MLFID>", r"(?P<ip4>\d+)", r"(?P<ip6>\S+)", r"(?P<dns>\S+)",
    r"(?P<fid>\S*)", r"(?P<cidr>\d+)<IP4>", r"<IP4>/(?P<cidr>\d*)", r"<F-ID>\S+</F-ID> <HOST>", r"<ADDR>|<F-ID/>",
    r"<IP4>|<IP6>", r"%%<HOST>?", r"^test <HOST> group$", r"^test <IP4> group$", r"^test <IP6> group$",
    r"^test <DNS> group$", r"^test id group: ip:port = <F-ID><IP4>(?::<F-PORT/>)?</F-ID>$",
    r"^test id group: user:\(<F-ID>[^\)]+</F-ID>\)$", r"^test id group: anything = <F-ID/>$", r"^test no group$",
    r"(?P<ip6>[:\da-f]+)", r"(?P<ip4>\S+)", r"(?P<ip4>.*)", r"<F-ALT_ID_1>\d+</F-ALT_ID_1>|<F-ID>\w+</F-ID>",
    r"<F-TUPLE_ID_1>\d+</F-TUPLE_ID_1> <F-ID>\w+</F-ID>", r"<F-ALT_CIDR_1>\d+</F-ALT_CIDR_1><IP4>",
    r"<IP4>/<F-TUPLE_CIDR_1>\d+</F-TUPLE_CIDR_1>", r"<F-PORT/>", r"no group", r"(?P<mlfid>x)", r"(?P<fport>x)",
    r"(?P<IP4>x)", r"(?P<ip4>\d)(?P<cidr>\d)", r"<IP4> <F-CIDR>\u0663+</F-CIDR>", r"<F-CIDR>\S+</F-CIDR> <IP4>",
]
FAIL_SUBJECTS = [
    "1.2.3.4\n", "1.2.3.4/24\n", "1.2.3.4/0\n", "1.2.3.4/33\n", "999.999.999.999\n", "[::1]\n", "::1\n", "2001:db8::1\n",
    "2001:db8::1/64\n", "::ffff:1.2.3.4\n", "::ffff:1.2.3.4/120\n", "example.com\n", "ex\u00e4mple.com\n", "host_1.example.org\n",
    "1.2.3.4 5\n", "5 1.2.3.4\n", "abc 1.2.3.4\n", "12 abc\n", "a:b::c\n", "1:2:3:4:5:6:7:8\n", "1.2.3.4/\u0663\u0663\n",
    "1.2.3.4 \u0663\u0663\n", "\u0663 1.2.3.4\n", "1.2.3.4/99999999999999\n", "[1.2.3.4]\n", "[2001:db8::1]/64\n", "12\n", "x\n", "\n", "",
    "0.0.0.0\n", "255.255.255.255\n", "01.02.03.04\n", "1.2.3.4.5\n", "fe80::1%eth0\n", "::\n", ":::\n", "1::\n",
]


def gen_fail():
    out = []
    for p in FAIL_PATTERNS:
        for usedns in ("warn", "no"):
            obj, c = construct("fail", p, False, usedns)
            rec = {"p": p, "usedns": usedns, "c": c, "r": {}}
            if obj is not None:
                for i, s in enumerate(FAIL_SUBJECTS):
                    m = match_record(obj, s, [("", "", s.rstrip("\n"))] if s.endswith("\n") else None, True, ids=True)
                    if m:
                        rec["r"][str(i)] = m
            out.append(rec)
    # prefRegex combos
    prefs = [r"^(?P<fid>x)", r"^<HOST>", r"no group", r"(?P<mlfid>a)", r"<F-CONTENT>.*</F-CONTENT>"]
    combos = []
    for pr in prefs:
        pobj, _ = construct("regex", pr)
        for fp in (r"^y", r"^<HOST>", r"<F-ID/>", r"(?P<mlfid>a)", r"(?P<fport>1)"):
            _, c = construct("fail", fp, False, "warn", pobj)
            combos.append({"pref": pr, "p": fp, "c": c})
    dump("fail.json", {"subjects": FAIL_SUBJECTS, "entries": out, "pref_combos": combos})


def gen_charclasses():
    def ranges(pred):
        out = []
        start = None
        for cp in range(0x110000):
            ok = pred(chr(cp))
            if ok and start is None:
                start = cp
            elif not ok and start is not None:
                out.append([start, cp - 1])
                start = None
        if start is not None:
            out.append([start, 0x10FFFF])
        return out
    res = {}
    for name in ("d", "s", "w"):
        cre = re.compile("\\" + name)
        res[name] = ranges(lambda ch, c=cre: c.fullmatch(ch) is not None)
    dump("charclasses.json", res)


UNIT_FAIL = [
    # filtertestcase.py / servertestcase.py (addFailRegex arguments)
    (r"(?:(?:Authentication failure|Failed [-/\w+]+) for(?: [iI](?:llegal|nvalid) user)?|[Ii](?:llegal|nvalid) user|ROOT LOGIN REFUSED) .*(?: from|FROM) <HOST>", False),
    (r"(?:(?:Authentication failure|Failed [-/\w+]+) for(?: [iI](?:llegal|nvalid) user)?|[Ii](?:llegal|nvalid) user|ROOT LOGIN REFUSED) .*(?: from|FROM) <HOST>$", False),
    (r"Failed .* from <HOST>", False), (r"Accepted .* from <HOST>", False),
    (r"error,relay=<HOST>,.*550 User unknown", False), (r"Invalid user .* <HOST>", False),
    (r"<HOST>", False), (r"^<HOST>", False), (r"fail from <ADDR>$", False),
    (r"^.*rsyncd\[(?P<pid>\d+)\]: connect from .+ \(<HOST>\)$<SKIPLINES>^.+ rsyncd\[(?P=pid)\]: rsync error: .*$", True),
    (r"^.* sendmail\[.*, msgid=<(?P<msgid>[^>]+).*relay=\[<HOST>\].*$<SKIPLINES>^.+ spamd: result: Y \d+ .*,mid=<(?P=msgid)>(,bayes=[.\d]+)?(,autolearn=\S+)?\s*$", True),
    (r"^.*rsyncd\[(?P<pid>\d+)\]: connect from .+ \(<HOST>\)$<SKIPLINES>^.+ rsyncd\[(?P=pid)\]: rsync error: .*$", False),
    (r"^<F-MLFID>\S+</F-MLFID> <HOST>$<SKIPLINES>^<F-MLFID/> .*$", True),
]
UNIT_IGNORE = [("rsync error: Received SIGINT", False), ("for roehl", False)]


def gen_unit():
    """unit.json: regexes of upstream's filter/server unit tests over the
    log files of the test-suite, as single lines and (multi-line regexes)
    windows of consecutive lines."""
    d = UP / "fail2ban" / "tests" / "files"
    flt = Filter(None)
    out = []
    for f in sorted(d.glob("testcase*.log")):
        raw = f.read_bytes().decode("utf-8", "replace")
        lines = [l for l in raw.split("\n") if l != ""]
        tl = []
        for line in lines:
            tm = flt.dateDetector.matchTime(line)
            if tm[0]:
                a, b = tm[0].start(1), tm[0].end(1)
                tl.append((line[:a], line[a:b], line[b:]))
            else:
                tl.append(("", "", line))
        n = len(tl)
        for kind, lst in (("fail", UNIT_FAIL), ("ignore", UNIT_IGNORE)):
            for pat, ml in lst:
                try:
                    obj = FailRegex(pat, multiline=ml) if kind == "fail" else Regex(pat, multiline=ml)
                except RegexException:
                    continue
                if ml or "<SKIPLINES>" in pat:
                    wins = [(i, k) for i in range(n) for k in range(1, 6) if i + k <= n] + [(0, n)]
                else:
                    wins = [(i, 1) for i in range(n)]
                res = {}
                for wi, (i, k) in enumerate(wins):
                    org = [tuple(t) for t in tl[i:i + k]]
                    m = match_record(obj, Regex._tupleLinesBuf(org), org, kind == "fail", ids=True)
                    if m:
                        res[str(wi)] = m
                out.append({"file": f.name, "p": pat, "ml": ml, "kind": kind,
                            "tuples": [list(t) for t in tl], "wins": [list(w) for w in wins], "res": res})
    dump("unit.json", out)


# --------------------------------------------------------------------------
# mutated real patterns (parser parity on near-valid input)
# --------------------------------------------------------------------------
PAT_CHARS = list("()[]{}*+?|^$\\.<>-:&~#=!P,0123456789a ") + ["(?", "(?P<x>", "\\", "\\b", "(?:", "[^", "{1,2}", "<HOST>", "</F-USER>", "<F-USER>", "(?i)", "(?=", "(?<="]


def mutate_pattern(rnd, s):
    if not s:
        return s
    kind = rnd.randrange(8)
    i = rnd.randrange(len(s))
    if kind == 0:
        return s[:i] + s[i + 1:]
    if kind == 1:
        return s[:i] + rnd.choice(PAT_CHARS) + s[i:]
    if kind == 2:
        return s[:i] + rnd.choice(PAT_CHARS) + s[i + 1:]
    if kind == 3 and i + 1 < len(s):
        return s[:i] + s[i + 1] + s[i] + s[i + 2:]
    if kind == 4:
        return s[:i]
    if kind == 5:
        j = rnd.randrange(i, len(s))
        return s[:j] + s[i:j + 1] + s[j:]
    if kind == 6:
        return s[i:]
    j = min(len(s), i + rnd.randrange(1, 12))
    return s[:i] + s[j:]


def compact_construct(src, ml, usedns, pref=None):
    obj, e = construct("regex", src, ml, usedns)
    if obj is not None:
        return obj, compact_expect(e)
    # errors embed the (large) expanded regex: keep inner message + hash
    expanded = Regex._resolveHostTag(src, useDns=usedns)
    if FR.R_GLOB2LOCFLAGS:
        expanded = FR.R_GLOB2LOCFLAGS[0].sub(FR.R_GLOB2LOCFLAGS[1], expanded)
    if e["type"] == "RegexException" and expanded.lstrip() != "":
        # RegexException chained from re.error
        try:
            Regex(src, multiline=ml, useDns=usedns)
        except RegexException as ex:
            inner = str(ex.__context__) if ex.__context__ is not None else None
        e = {"ok": False, "type": "RegexException", "inner": inner,
             "regex_fnv": fnv64(expanded), "regex_len": len(expanded)}
    return None, e


def gen_pattern_mutation(configs, per_config=4 * SCALE):
    res = {}
    for e in configs:
        if e["usedns"] != "warn":
            continue
        rnd = random.Random("patmut/" + e["id"] + SEED)
        srcs = ([e["pref_src"]] if e["pref_src"] else []) + e["fail_src"] + e["ignore_src"]
        if not srcs:
            continue
        recs = unique_lines(e)
        lines = [r["line"] for r in recs[:6]]
        entries = []
        ml = e["maxlines"] > 1
        for _ in range(per_config):
            src = rnd.choice(srcs)
            for _ in range(rnd.randrange(1, 3)):
                src = mutate_pattern(rnd, src)
            obj, c = compact_construct(src, ml, "warn")
            ent = {"p": src, "ml": ml, "c": c}
            if obj is not None:
                r = {}
                for i, ln in enumerate(lines):
                    m = match_record(obj, ln, None, False)
                    if m:
                        r[str(i)] = m
                ent["r"] = r
            entries.append(ent)
        res[e["id"]] = {"lines": lines, "entries": entries}
    dump("patmut.json", res)


# --------------------------------------------------------------------------
def main():
    configs = load_configs()
    print("configs: %d (x usedns)" % len(configs), file=sys.stderr)
    gen_configs(configs)
    gen_search(configs)
    gen_search_nodns(configs)
    gen_multi(configs)
    gen_fuzz(configs)
    gen_tags()
    gen_fail()
    gen_charclasses()
    gen_unit()
    gen_pattern_mutation(configs)
    gen_engine()


if __name__ == "__main__":
    main()
