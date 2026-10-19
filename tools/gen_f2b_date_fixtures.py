#!/usr/bin/env python3
"""Generate oracle fixtures for crates/f2b-date (date detection) from the
real upstream implementation: fail2ban/server/{datedetector,datetemplate,
strptime,mytime}.py.

Usage (from the repository root):

    python3 tools/gen_f2b_date_fixtures.py

Writes testdata/f2b-date/*.json (sorted keys, compact, deterministic: running
it twice yields byte-identical files; the script re-executes itself with
PYTHONHASHSEED=0 because upstream's `%Exk`/`%Exl` names depend on the hash
seed).  Every expected value is produced by upstream; nothing is hand-written.

Environment pinned per scenario (see SCENARIOS): the process time zone (`TZ`,
a POSIX rule or IANA name), the clock (`MyTime.setTime`), upstream's
import-time year window (the wall-clock year `datetime.now().year` that
`_updateTimeRE` sees, patched through a shim so the output does not depend on
the date the script runs) and `MyTime.setAlternateNow`.

Every detector is built from empty caches; "fresh" runs build one detector per
line (template-level `hits` of cached templates are reset in between, which
equals a fresh process).
"""
import ast
import logging
import datetime
import glob
import json
import os
import random
import re
import sys
import time
import types
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

if os.environ.get("PYTHONHASHSEED") != "0":
    env = dict(os.environ, PYTHONHASHSEED="0")
    os.execve(sys.executable, [sys.executable] + sys.argv, env)

sys.path.insert(0, os.path.join(ROOT, "fail2ban"))
os.environ["TZ"] = "CET-01CEST-02,M3.5.0,M10.5.0"
time.tzset()

from fail2ban.server import datedetector as dd_mod  # noqa: E402
from fail2ban.server import strptime  # noqa: E402
from fail2ban.server.datedetector import (  # noqa: E402
    DD_patternCache, DateDetector, DateDetectorCache)
from fail2ban.server.mytime import MyTime  # noqa: E402
from fail2ban.server.datetemplate import DatePatternRegex as DatePatternRegexClass  # noqa: E402

OUT = os.path.join(ROOT, "testdata", "f2b-date")
UP = os.path.join(ROOT, "fail2ban")
TESTS = os.path.join(UP, "fail2ban", "tests")

# ---------------------------------------------------------------------------
# scenarios
# ---------------------------------------------------------------------------
SCENARIOS = [
    # upstream's pinned sample-test environment
    dict(id="pinned", tz="CET-01CEST-02,M3.5.0,M10.5.0", now=1124013600, wall_year=2026, alt=None, full=True),
    # IANA zone, clock just after New Year (UTC) = still Dec 31 locally
    dict(id="ny_iana", tz="America/New_York", now=1735693230, wall_year=2026, alt=None, full=False),
    # half-hour DST, fractional clock, later wall-clock year (window 203x)
    dict(id="lord_howe", tz="<+1030>-10:30<+11>-11,M10.1.0,M4.1.0", now=1700000000.5, wall_year=2031, alt=1e9, full=False),
    # year window starting 1970 (alternate now 1.0)
    dict(id="window_alt1", tz="UTC", now=1124013600, wall_year=2026, alt=1.0, full=False),
    # fail2ban-regex: setAlternateNow(0) (falsy -> default window), US rule, early clock
    dict(id="window_alt0", tz="EST5EDT,M3.2.0,M11.1.0", now=1331000000, wall_year=2012, alt=0, full=False),
    # negative offset east of UTC and an alternate now before 2001
    dict(id="tokyo_alt_old", tz="JST-9", now=1262303999.25, wall_year=2026, alt=-1e9, full=False),
]

logging.disable(logging.CRITICAL)
ORIG_DEFAULTS = list(DateDetectorCache.DEFAULT_TEMPLATES)


class _FakeTime(object):
    """`time` module stand-in for datedetector: time() == MyTime.time()."""
    @staticmethod
    def time():
        return MyTime.myTime


dd_mod.time = _FakeTime()


def reset_caches():
    DD_patternCache.clear()
    DateDetectorCache.DEFAULT_TEMPLATES[:] = ORIG_DEFAULTS
    DateDetector._defCache = DateDetectorCache()


def reset_hits():
    """Make cached template objects look fresh (template-level `hits`)."""
    seen = []
    for v in list(DD_patternCache._cache.values()):
        seen.append(v[0])
    seen.extend(t for t in DateDetectorCache.DEFAULT_TEMPLATES if not isinstance(t, str))
    seen.extend(DateDetector._defCache._DateDetectorCache__templates)
    for t in seen:
        t.hits = 0


def update_time_re(wall_year):
    """Run strptime._updateTimeRE() as if `datetime.now()` were in wall_year."""
    real = strptime.datetime

    class FakeDT(real.datetime):
        @classmethod
        def now(cls, tz=None):
            return real.datetime(wall_year, 6, 15, 12, 0, 0)

    shim = types.SimpleNamespace(datetime=FakeDT, timedelta=real.timedelta, date=real.date)
    strptime.datetime = shim
    try:
        strptime._updateTimeRE()
    finally:
        strptime.datetime = real


class _AnchoredTime(object):
    """`time` for strptime: mktime() is primed with the zone's standard-time
    offset before each call. glibc's mktime starts from the offset of its
    previous call (process-global state), which decides ambiguous local times;
    priming makes the result a pure function (the crate documents the same)."""

    def __getattr__(self, name):
        return getattr(time, name)

    @staticmethod
    def mktime(t):
        anchor = None
        for ts in (947937600, 963662400):
            lt = time.localtime(ts)
            if lt.tm_isdst == 0:
                anchor = lt
                break
        if anchor is None:
            anchor = time.localtime(947937600)
        time.mktime(anchor)
        return time.mktime(t)


strptime.time = _AnchoredTime()


def setup(scn):
    os.environ["TZ"] = scn["tz"]
    time.tzset()
    MyTime.setTime(scn["now"])
    MyTime.setAlternateNow(scn["alt"])
    update_time_re(scn["wall_year"])
    reset_caches()


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def dump(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        f.write("\n")


def classify(ex):
    """Map an upstream construction exception to the crate's error category."""
    msg = str(ex)
    if isinstance(ex, ValueError) and "already a template" in msg:
        return "duplicate"
    if isinstance(ex, (ValueError, KeyError)) and ("time zone" in msg or isinstance(ex, KeyError)):
        return "timezone"
    return "pattern"


def tinfo(t):
    pat = t.pattern if hasattr(t, "pattern") else None
    return [STRINGS(t.name), None if pat is None else STRINGS(pat), STRINGS(t.regex), t.flags, t.template.weight]


class _Probe(object):
    """Mapping for detecting unkeyed conversions (`%s`, `%.2s`, ...), which would
    insert the repr of upstream's whole dict (hash-order dependent): such
    patterns are a documented deviation and are kept out of the fixtures."""
    def __getitem__(self, k):
        return "x"

    def keys(self):
        return []

    def __str__(self):
        return "\0DICT\0"

    __repr__ = __str__


def unkeyed_conversion(pattern):
    try:
        fmt = DatePatternRegexClass._patternRE.sub(r'%(\1)s', pattern)
        return "\0" in (fmt % _Probe())
    except Exception:  # noqa: BLE001
        return False


def force_compile(dd):
    for t in dd.templates:
        t.template._compileRegex()


def get_date_pattern(dd):
    templates = dd.templates
    if not len(templates) or len(templates) > 2:
        return [None, STRINGS("Default Detectors")]
    t = templates[0]
    pat = t.pattern if hasattr(t, "pattern") else None
    return [None if pat is None else STRINGS(pat), STRINGS(t.name)]


def build(cfg):
    """Filter.setDatePattern semantics; returns (dd, None) or (None, category)."""
    try:
        dd = DateDetector()
        if cfg.get("tz") is not None:
            dd.default_tz = cfg["tz"]
        kind = cfg["kind"]
        if kind == "default":
            pass
        elif kind == "default_now":
            dd.addDefaultTemplate()
        elif kind == "multi":
            pats = [p.strip() for p in re.split("\n+", cfg["pattern"])]
            for p in filter(bool, pats):
                dd.appendTemplate(p)
        elif kind == "list":
            for p in cfg["patterns"]:
                dd.appendTemplate(p)
        else:
            raise AssertionError(kind)
        force_compile(dd)
        return dd, None
    except Exception as ex:  # noqa: BLE001
        return None, classify(ex)


class Interner(object):
    """Global string table (template names, regexes, patterns): ids are stable."""
    def __init__(self):
        self.names = []
        self.idx = {}

    def __call__(self, name):
        i = self.idx.get(name)
        if i is None:
            i = self.idx[name] = len(self.names)
            self.names.append(name)
        return i


STRINGS = Interner()


def byte_of(line, i):
    if line.isascii():
        return i
    return len(line[:i].encode("utf-8", "surrogatepass"))


def step(dd, line, intern):
    """One matchTime+getTime step -> record (see module docs)."""
    try:
        timeMatch = dd.matchTime(line)
    except Exception as ex:  # noqa: BLE001
        return ["!" + type(ex).__name__], True
    m, tpl = timeMatch
    for t in dd.templates:
        intern(t.name)
    if m is None:
        return None, False
    try:
        s1, e1 = m.start(1), m.end(1)
        g1 = [byte_of(line, s1) if s1 >= 0 else None, byte_of(line, e1) if e1 >= 0 else None]
        text = line[s1:e1]
    except IndexError:  # no group 1 (e.g. newline in pattern): upstream's filter would crash here
        g1 = ["!IndexError", "!IndexError"]
        text = ""
    rec = [byte_of(line, m.start()), byte_of(line, m.end())] + g1 + [intern(tpl.name)]
    try:
        res = dd.getTime(text, timeMatch)
        rec.append(None if res is None else repr(float(res[0])))
    except Exception as ex:  # noqa: BLE001
        rec.append("!" + type(ex).__name__)
    return rec, False


def final_state(dd, intern):
    return {
        "order": [intern(t.name) for t in dd.templates],
        "hits": [t.hits for t in dd.templates],
        "dp": get_date_pattern(dd),
    }


class Lines(object):
    """Global line table (ids are stable, content stored once)."""
    def __init__(self):
        self.table = []
        self.idx = {}

    def id(self, s):
        i = self.idx.get(s)
        if i is None:
            i = self.idx[s] = len(self.table)
            self.table.append(s)
        return i


LINES = Lines()


def run(cfg, lines, fresh=False, orders=False, times=None, tag=""):
    """Run `lines` through a detector built from cfg. Returns the run record."""
    reset_caches()
    intern = STRINGS
    dd, err = build(cfg)
    rec = {"cfg": cfg, "tag": tag, "fresh": fresh, "orders": orders}
    if err:
        rec["error"] = err
        return rec
    rec["init"] = [tinfo(t) for t in dd.templates]
    rec["init_dp"] = get_date_pattern(dd)
    rec["ids"] = [LINES.id(l) for l in lines]
    if times:
        rec["times"] = times
    res, ords = [], []
    t0 = MyTime.myTime
    for n, line in enumerate(lines):
        if times:
            MyTime.setTime(times[n])
        if fresh:
            reset_hits()
            dd, err = build(cfg)
            assert err is None
        r, stop = step(dd, line, intern)
        res.append(r)
        if orders:
            ords.append([intern(t.name) for t in dd.templates])
        if stop:
            rec["trunc"] = True
            break
    MyTime.setTime(t0)
    rec["res"] = res
    if orders:
        rec["orders_list"] = ords
    if not fresh:
        rec["final"] = final_state(dd, intern)
    return rec


# ---------------------------------------------------------------------------
# corpus
# ---------------------------------------------------------------------------
def read_text_lines(path):
    data = open(path, "rb").read().decode("utf-8", "replace")
    lines = data.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return [l.rstrip("\r") if False else l for l in lines]


def corpus_files():
    files = sorted(glob.glob(os.path.join(TESTS, "files", "logs", "*")))
    files += sorted(glob.glob(os.path.join(TESTS, "files", "*.log")))
    return [f for f in files if os.path.isfile(f)]


def harvest_strings(path):
    tree = ast.parse(open(path, encoding="utf-8").read())
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            try:
                node.value.encode("utf-8")
            except UnicodeEncodeError:
                continue
            out.append(node.value)
    return out


def harvest_patterns():
    """String arguments of setDatePattern/appendTemplate/... in upstream tests."""
    pats = []
    for path in glob.glob(os.path.join(TESTS, "*.py")):
        tree = ast.parse(open(path, encoding="utf-8").read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, (ast.Attribute, ast.Name)):
                fname = node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id
                if fname in ("setDatePattern", "appendTemplate", "DatePatternRegex", "_getPatternTemplate",
                             "_getAnchoredTemplate", "addDefaultTemplate"):
                    for a in node.args:
                        for c in ast.walk(a):
                            if isinstance(c, ast.Constant) and isinstance(c.value, str):
                                pats.append(c.value)
    return pats


# ---------------------------------------------------------------------------
# synthetic lines
# ---------------------------------------------------------------------------
MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
DAY = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
ZONES = ["", " +0200", "Z", " UTC", " GMT", "+02:00", "-0330", "+02", " -0000", " +05:45", "-11:00", " Z",
         "+1400", "-1200", " +0100", "  +0000", "+00:00"]
PREFIX = ["", "", "", "[", "<13>", "host ", "pid=123 ", "  ", "é ", "日本語 ", "x", "@", "1", "(", "ERROR ",
          "\t", "- - "]
SUFFIX = ["", "", "", " host sshd[12]: Failed password for root from 1.2.3.4", "]", "z", " 12:00:00", "123", ")",
          ": error", " +0200", ".5", "Z", "\t", " 2005"]


def comp(r, years=None):
    y = r.choice(years or [1970, 1999, 2000, 2001, 2003, 2004, 2005, 2005, 2005, 2005, 2005, 2006, 2007, 2010,
                           2012, 2015, 2019, 2020, 2024, 2025, 2026, 2027, 2029, 2030, 2031, 2039, 2099])
    mo = r.randint(1, 12)
    d = r.choice([r.randint(1, 28)] * 4 + [r.randint(1, 31), 29, 30, 31])
    h = r.choice([r.randint(0, 23)] * 6 + [0, 1, 2, 3, 12, 23, 24, 25])
    mi = r.choice([r.randint(0, 59)] * 6 + [0, 30, 59, 60])
    s = r.choice([r.randint(0, 59)] * 6 + [0, 59, 60, 61, 62])
    return dict(y=y, mo=mo, d=d, h=h, mi=mi, s=s, f=r.choice(["", "", ".123", ".981746", ",5", ".1234567", ".000001"]),
                wd=r.choice(DAY), mon=MON[mo - 1], zone=r.choice(ZONES))


def pad(r, n, w=2, space_ok=True):
    t = str(n)
    if len(t) >= w:
        return t
    return r.choice(["0" * (w - len(t)), " " * (w - len(t)), ""]) + t if space_ok else "0" * (w - len(t)) + t


def fmt_iso(r, c):
    sep = r.choice("-/.")
    return "%s%s%s%s%s%s%02d:%02d:%02d%s%s" % (
        c["y"], sep, pad(r, c["mo"]), sep, pad(r, c["d"]), r.choice(["T", " ", "  ", "T"]), c["h"], c["mi"],
        c["s"], c["f"].replace(",", ",") if r.random() < 0.6 else "", r.choice(["", c["zone"], c["zone"]]))


def fmt_asctime(r, c):
    return "%s%s %s %s:%02d:%02d%s%s" % (
        (c["wd"] + " ") if r.random() < 0.4 else "", c["mon"], pad(r, c["d"]), pad(r, c["h"]), c["mi"], c["s"],
        c["f"] if r.random() < 0.3 and c["f"].startswith(".") else "",
        (" %d" % c["y"]) if r.random() < 0.5 else "")


def fmt_asctime_y(r, c):
    return "%s%s %s %d %s:%02d:%02d%s" % (
        (c["wd"] + " ") if r.random() < 0.4 else "", c["mon"], pad(r, c["d"]), c["y"], pad(r, c["h"]), c["mi"],
        c["s"], c["f"] if c["f"].startswith(".") else "")


def fmt_dmy(r, c):
    sep = r.choice("-/")
    y = str(c["y"]) if r.random() < 0.5 else "%02d" % (c["y"] % 100)
    return "%s%s%s%s%s %s:%02d:%02d" % (pad(r, c["d"]), sep, pad(r, c["mo"]), sep, y, pad(r, c["h"]), c["mi"], c["s"])


def fmt_apache(r, c):
    sep = r.choice("-/")
    return "%s%s%s%s%d%s%02d:%02d:%02d%s%s" % (
        pad(r, c["d"]), sep, c["mon"], sep, c["y"], r.choice([" ", ":", ""]), c["h"], c["mi"], c["s"],
        c["f"] if c["f"].startswith(".") and r.random() < 0.4 else "", (" " + c["zone"].strip()) if r.random() < 0.5 else "")


def fmt_cpanel(r, c):
    return "%s/%s/%d:%02d:%02d:%02d" % (pad(r, c["mo"]), pad(r, c["d"]), c["y"], c["h"], c["mi"], c["s"])


def fmt_mdy(r, c):
    return "%s-%s-%d %s:%02d:%02d%s" % (pad(r, c["mo"]), pad(r, c["d"]), c["y"], pad(r, c["h"]), c["mi"], c["s"],
                                        c["f"] if c["f"].startswith(".") else "")


def fmt_epoch(r, c):
    t = r.choice([1124013600, 1000000000, 1330000000 + r.randint(0, 10 ** 6), 9999999999, 99999999999,
                  r.randint(10 ** 9, 2 * 10 ** 9), 1124013600123, 1124013600123456, 112401360012, 999999999])
    f = r.choice(["", "", ".1", ".123", ".123456", ".1234567", ".12"])
    return r.choice(["%s%s", "[%s%s]", "audit(%s%s:55)", "type=SYSCALL msg=audit(%s%s:12): x", "%s%s ", "x%s%s",
                     "%s%s abc", "audit(%s%s)", "[%s%s", "%s%s]"]) % (t, f)


def fmt_timeonly(r, c):
    return "%02d:%02d:%02d" % (c["h"], c["mi"], c["s"])


def fmt_angle(r, c):
    return "<%s/%s/%s@%02d:%02d:%02d>" % (pad(r, c["mo"]), pad(r, c["d"]), r.choice([str(c["y"]), "%02d" % (c["y"] % 100)]),
                                         c["h"], c["mi"], c["s"])


def fmt_mysql(r, c):
    return "%02d%02d%02d%s%s:%02d:%02d" % (c["y"] % 100, c["mo"], c["d"], r.choice([" ", "  ", ""]), pad(r, c["h"]), c["mi"], c["s"])


def fmt_tomcat(r, c):
    return "%s %s, %d %s:%02d:%02d %s" % (c["mon"], pad(r, c["d"]), c["y"], pad(r, c["h"] % 13), c["mi"], c["s"],
                                          r.choice(["AM", "PM", "am", "pm", "Pm", ""]))


def fmt_assp(r, c):
    return "%s-%s-%02d %s:%02d:%02d" % (c["mon"], pad(r, c["d"]), c["y"] % 100, pad(r, c["h"]), c["mi"], c["s"])


def fmt_compact(r, c):
    return "%d%02d%02d%s%02d%s%02d%s%02d%s%s" % (
        c["y"], c["mo"], c["d"], r.choice(["-", "T", " ", "  ", ""]), c["h"], r.choice([":", ""]), c["mi"], r.choice([":", ""]),
        c["s"], c["f"] if c["f"] and r.random() < 0.3 else "", c["zone"] if r.random() < 0.5 else "")


def fmt_monit(r, c):
    return "%s %s %s %s:%02d:%02d%s%s" % (
        r.choice(["PDT", "EST", "CET", "UTC", "GMT", "Z", "ERROR", "ABC", "PST", "XXXXX", "AB", "WARN"]),
        (c["wd"] + " ") if r.random() < 0.3 else "", c["mon"] + " " + pad(r, c["d"]), pad(r, c["h"]), c["mi"], c["s"],
        c["f"] if c["f"].startswith(".") and r.random() < 0.3 else "", (" %d" % c["y"]) if r.random() < 0.4 else "")


def fmt_zone_first(r, c):
    return "%s %s%s %s %s:%02d:%02d%s%s" % (
        r.choice(["+00:00", "-0500", "+0200", "Z", "UTC", "GMT", "+02", "-11:30"]), (c["wd"] + " ") if r.random() < 0.3 else "",
        c["mon"], pad(r, c["d"]), pad(r, c["h"]), c["mi"], c["s"], c["f"] if c["f"].startswith(".") else "",
        (" %d" % c["y"]) if r.random() < 0.5 else "")


def fmt_tai(r, c):
    n = r.choice(["4000000037c219bf2ef02e94", "400000000000000000000000", "4000000fffffffffffffffff", "40000000" + "%016x" % r.randint(0, 2 ** 64 - 1),
                  "400000003f1fb3dc1d3c6a50", "ffffffffffffffffffffffff"])
    return "@" + n[:24]


FORMATS = [fmt_iso, fmt_asctime, fmt_asctime_y, fmt_dmy, fmt_apache, fmt_cpanel, fmt_mdy, fmt_epoch, fmt_timeonly,
           fmt_angle, fmt_mysql, fmt_tomcat, fmt_assp, fmt_compact, fmt_monit, fmt_zone_first, fmt_tai]

ALPHABET = list("0123456789:-/. TZ@[]<>()+,;_%abcdefghijklmnopqrstuvwxyzJFMASOND") + ["é", "٣", "İ", "ı", "ſ", "\u0300", "\x1c", "\u00a0", "日", "K"]


def mutate(r, s):
    s = list(s)
    for _ in range(r.choice([1, 1, 2, 3])):
        op = r.choice(["del", "ins", "rep", "dup"])
        if not s:
            s.append(r.choice(ALPHABET))
            continue
        i = r.randrange(len(s))
        if op == "del":
            del s[i]
        elif op == "ins":
            s.insert(i, r.choice(ALPHABET))
        elif op == "rep":
            s[i] = r.choice(ALPHABET)
        else:
            s.insert(i, s[i])
    return "".join(s)


def synth_lines(seed, per_format=60):
    r = random.Random(seed)
    out = []
    for fi, f in enumerate(FORMATS):
        for _ in range(per_format):
            c = comp(r)
            text = f(r, c)
            line = r.choice(PREFIX) + text + r.choice(SUFFIX)
            out.append(line)
            if r.random() < 0.15:
                out.append(mutate(r, line))
    return out


def dst_lines():
    out = []
    dates = [(3, d) for d in (11, 12, 13, 14, 25, 26, 27, 28)] + [(4, d) for d in (1, 2, 3, 4)] + \
            [(10, d) for d in (1, 2, 3, 29, 30, 31)] + [(11, d) for d in (5, 6, 7)]
    for y in (2004, 2005, 2006, 2011, 2012):
        for (mo, d) in dates:
            for h, mi in ((0, 30), (1, 59), (2, 0), (2, 15), (2, 30), (2, 45), (3, 0), (3, 30), (1, 30), (0, 0)):
                out.append("%d-%02d-%02d %02d:%02d:%02d" % (y, mo, d, h, mi, 7))
                if (y + mo + d + h + mi) % 5 == 0:
                    out.append("%s %02d %02d:%02d:%02d %d" % (MON[mo - 1], d, h, mi, 9, y))
    return out


def rollover_lines():
    """Year-less lines around the pinned clocks (assume-year logic)."""
    out = []
    for mo in range(1, 13):
        for d in (1, 2, 14, 15, 28, 31):
            if d == 31 and mo in (2, 4, 6, 9, 11):
                continue
            for h in (0, 9, 10, 11, 23):
                out.append("%s %2d %02d:%02d:%02d host x" % (MON[mo - 1], d, h, 0, 1))
    out += ["Feb 29 10:00:00 x", "Feb 30 10:00:00 x", "Dec 31 23:59:59 x", "Jan  1 00:00:00 x", "Aug 14 10:00:00", "Aug 14 10:00:01",
            "Aug 15 09:59:59", "Aug 15 10:00:01", "Aug 15 11:00:01", "Aug 16 10:00:00", "10:00:00", "09:59:59", "10:00:01", "23:59:59",
            "00:00:00", "12:00:00"]
    # two- and four-digit years around century / window edges
    for y in ("00", "01", "05", "99", "70", "26", "30", "31", "32", "2000", "2001", "1999", "2026", "2029", "2030", "2031", "2039", "2040", "1970", "1969", "9999", "0001", "0000"):
        out.append("%s-01-02 03:04:05" % y)
        out.append("02/01/%s 03:04:05" % y)
        out.append("Jan 02 03:04:05 %s" % y)
        out.append("%s0102 030405" % y)
        out.append("<01/02/%s@03:04:05>" % y)
        out.append("Jan-02-%s 03:04:05" % y)
        out.append("%s%s%s 03:04:05" % (y[-2:], "01", "02"))
    return out


def odd_lines():
    return [
        "", " ", "x", "2005", "2005-", "2005-08", "2005-08-14", "2005-08-14 10", "2005-08-14 10:00", "Aug", "Aug 14", "Jan 2 3:4:5",
        "1124013600", "112401360", "11240136000", "112401360012", "@4000000037c219bf2ef02e94", "@4000000037c219bf2ef02e9",
        "@4000000037C219BF2EF02E94", "  Aug 14 11:22:33", "\tAug 14 11:22:33", "Aug 14 11:22:33\n", "Aug 14 11:22:33\r\n",
        "2005-08-14 11:22:33\n", "٢٠٠٥-٠٨-١٤ ١١:٢٢:٣٣", "２００５-０８-１４ １１:２２:３３", "1124013600\u0663", "\u0661\u0661\u0662\u0664\u0660\u0661\u0663\u0666\u0660\u0660",
        "AUG 14 11:22:33", "aug 14 11:22:33", "aUg 14 11:22:33", "ſep 14 11:22:33", "Sep 14 11:22:33", "Se\u0070 14 11:22:33", "İun 14 11:22:33",
        "Jun 14 11:22:33 İ", "Jul 14 11:22:33", "Aug 14 11:22:33 PM", "Aug 14, 2005 11:22:33 PM", "Aug 14, 2005 12:22:33 am", "Aug 14, 2005 12:22:33 AM",
        "Aug 14, 2005 0:22:33 AM", "Aug 14, 2005 13:22:33 AM", "Aug 14, 2005 1:22:33 pm", "Aug 14, 2005 12:00:00 PM",
        "2005-08-14T10:00:00+02:00", "2005-08-14T10:00:00-0000", "2005-08-14T10:00:00Z", "2005-08-14T10:00:00 UTC", "2005-08-14T10:00:00 EST",
        "2005-08-14T10:00:00+0200abc", "2005-08-14T10:00:00+2", "2005-08-14T10:00:00+25:00", "2005-08-14T10:00:00+0260",
        "2005-08-14T10:00:00.123456789", "2005-08-14T10:00:00,123", "2005-08-14 10:00:60", "2005-08-14 10:00:61", "2005-08-14 10:00:62",
        "2005-02-29 10:00:00", "2004-02-29 10:00:00", "2000-02-29 10:00:00", "1900-02-29 10:00:00", "2005-04-31 10:00:00", "2005-13-01 10:00:00",
        "2005-00-01 10:00:00", "2005-01-00 10:00:00", "0000-01-01 10:00:00", "0001-01-01 00:00:00", "9999-12-31 23:59:59", "9999-12-31 23:59:59 +0100",
        "0001-01-01 00:00:00 +0100", "0001-01-01 00:00:00 -0100", "2005-08-14 24:00:00", "2005-08-14 23:60:00",
        "ERROR Apr 16 21:05:29", "PDT Apr 16 21:05:29", "CET Apr 16 21:05:29", "ABCDE Apr 16 21:05:29", "Z Apr 16 21:05:29", "+00:00 Jan 23 21:59:59.011 2005",
        "Sun Jan 23 21:59:59.011 2005", "Sun Jan 23 2005 21:59:59.011", "Sun, Jan 23 2005 21:59:59.011", "Mon Jan 23 21:59:59", "Jan 23 2005 9:59:59",
        "Jan 23  9:59:59", "Jan  3 09:59:59", "Jan 3  9:59:59", "Jan 03 09:59:59", "[31/Oct/2006:09:22:55 -0000]", "26-Jul-2007 15:20:52.252", "26-Jul-2007 15:20:52 +0200",
        "05/20/2008:01:57:39", "01-27-2012 16:22:44.252", "<09/16/08@05:03:30>", "130322 11:46:11", "Apr-27-13 02:33:06", "20050123T215959", "20050123 215959",
        "20050123  85959", "20050123-21:59:59", "2005-01-23 21:59:59.981746 +0100", "audit(1124013600.123:55)", "type=SYSCALL msg=audit(1124013600.123:55): a",
        "[1124013600] x", "[1124013600", "1124013600]", "x1124013600", "1124013600x", "1124013600.5", "1124013600.123456", "1124013600.1234567", "1124013600123", "1124013600123456",
        "1124013600123.456", "1124013600123456.7", "11240136001234567", "112401360012345", "1124013600 Aug 14 10:00:00", "Aug 14 10:00:00 1124013600",
        "Aug 14 10:00:00 2005-08-14 10:00:00", "2005-08-14 10:00:00 Aug 14 10:00:00", "x 2005-08-14 10:00:00 y", "a2005-08-14 10:00:00", "2005-08-14 10:00:00z",
        "12:34:56", "x 12:34:56", "12:34:56 x", "12:34:567", "112:34:56", "1:2:3", "00:00:00", "24:00:00", "23:59:60", "23:59:61",
        "99-99-99 99:99:99", "31/12/99 23:59:59", "01/01/00 00:00:00", "01/01/01 00:00:00", "31-12-2005 23:59:59", "1-1-2005 1:1:1", "31/13/2005 23:59:59",
    ]


def synth_patterns():
    out = []
    for p in ORIG_DEFAULTS:
        out += [p, "{^LN-BEG}" + p, "^" + p, "{UNB}" + p, p + "**", "**" + p, p + "$", "(?i)" + p, "(" + p + ")", "{DATE}", "^{DATE}", "{DATE}$",
                "^[^\\[]*\\[({DATE})", "^<W>{DATE}", "x{DATE}y", "^\\[(?:{DATE})\\]"]
    toks = ["%a", "%A", "%b", "%B", "%d", "%e", "%H", "%I", "%j", "%m", "%M", "%p", "%S", "%U", "%w", "%W", "%y", "%Y", "%z", "%Z", "%f", "%k", "%l",
            "%ExY", "%Exy", "%Exm", "%Exd", "%ExH", "%ExM", "%ExS", "%Exz", "%ExZ", "%Exk", "%Exl", "%%", "%c", "%x", "%X", "%T", "%R", "%r", "%G", "%u", "%V", "%P",
            "%OH", "%Od", "%Om"]
    for t in toks:
        out += [t, "^" + t, t + " %H:%M:%S", "%Y-%m-%d " + t]
    # stray / invalid percent usage and regex errors
    out += ["%", "100%", "%Q", "%(Y)s", "%(Y)", "%(nope)s", "%(Y)d", "%d%", "%5d", "%-5s", "%5s", "%.2s", "%(Y).2s", "%(Y)5s", "%(Y)-5s", "%(Y)r", "%(%)s",
            "%Ex", "%ExQ", "%E", "%O", "%(", "%(Y", "%%%d", "%%d", "%%%%", "%d%d", "%d %d", "%H:%H", "%Y%y", "%b%B", "%z %Z", "%Z %z",
            "(", ")", "(()", "[", "]", "[a", "a**", "*", "+a", "a{2}{3}", "a{3,2}", "(?P<a>x)(?P<a>y)", "(?P<n>x)(?P=m)", "(?P=x)", "\\y", "\\1", "(?<n>a)", "(?<=a|bc)x",
            "(?<=a+)x", "(?i", "(?z)", "x(?i)", "(?s).", "a|b", "|", "()", "(|)", "(?:)", "^", "$", "^$", ".*", "\\d+", "\\D+", "\\w+", "\\b", "\\B", "(?#c)%Y", "%Y(?#c)",
            "[[]%Y", "[]%Y]", "[a-]%Y", "[^]]%Y", "{", "%Y{", "%Y{2}", "%Y{,2}", "%Y{2,}", "{DATE", "{DATE}{DATE}", "{date}", "{Date} %Y", "{UNB}", "{UNB}^", "{NONE}", "{none}",
            "{DEFAULT}", "{^LN-BEG}", "{^LN-BEG}{^LN-BEG}%Y", "^{^LN-BEG}%Y", "{UNB}{^LN-BEG}%Y", "{^LN-BEG}{UNB}%Y", "(?:^|\\b)%Y", "^(?:\\W{0,2})?%Y", "(?=^|\\b|\\W)%Y", "%Y(?=\\b|\\W|$)",
            "(?:^|\\b|\\W)%Y", "((%Y))", "(?P<x>%Y)", "(?P<Y>\\d+)", "(?P<d>1)(?P<m>2)", "(?P<m>\\d+)", "(?P<d>\\d+) (?P<b>\\w+)", "(?P<H>\\d+)", "(?P<_x>\\d)",
            "EPOCH", "epoch", "Epoch", "LEPOCH", "{EPOCH}", "{LEPOCH}", "{epoch}", "^{EPOCH}", "[{EPOCH}]", "x{EPOCH}y", "({EPOCH})", "({LEPOCH})", "\\{EPOCH}", "%Y{EPOCH}", "{EPOCH}{EPOCH}",
            "{^LN-BEG}EPOCH", "^EPOCH", "{^LN-BEG}LEPOCH", "^LEPOCH", "{^LN-BEG}Epoch", "TAI64N", "{^LN-BEG}TAI64N", "^TAI64N", "tai64n", "TAI64N**", "x TAI64N",
            "^type=\\S+ msg=audit\\(({EPOCH})", "(?<=\\|\\s){LEPOCH}(?=\\s\\|)", "(%ExY%Exm%Exd", "%ExY%Exm%Exd)", "^%ExY-%Exm-%Exd %H:%M:%S(?: ?%Exz)?",
            "%d/%b[^/]*/%Y:%H:%M:%S %z", "^%H:%M:%S.%f", "^%Y-%m-%d-%H%M%S\\.%f %z **", "^(?:%a )?%b %d %H:%M:%S(?:\\.%f)?(?: %ExY)?",
            "{^LN-BEG}%Y-%m-%d %H:%M:%S(?:\\s*%Z)?\\s", "%Y-%m-%d %H:%M:%S\\s*(?P<z>[+-]\\d{4})", "(?P<Y>\\d{4})-(?P<m>\\d\\d)-(?P<d>\\d\\d)", "%d %d", "%Y %j", "%Y %U %w", "%Y %W %a",
            "%Y %U %a", "%Y %W %w", "%j %H", "%y %j", "%a %H:%M", "%w", "%d", "%m", "%m %H", "%d %H", "%H %p %I", "%I %p", "%I", "%H:%M:%S %I", "%l %p", "%Exl %p", "(?:%p)?%I", "%I(?: %p)?",
            "%Y-%m-%d %H:%M:%S %Z", "%Y-%m-%d %H:%M:%S %ExZ", "%Y-%m-%d %H:%M:%S%Exz", "%Y-%m-%d %H:%M:%S %z", "%Y-%m-%d %H:%M:%S(?: %z)?", "%b %d %H:%M:%S %Y %z",
            "^\\d+ %Y", "^\\D+ %Y", "\u00e9%Y", "%Y\u00e9", "%\u00e9", "\u0663%Y", "(?P<\u00e9>x)", "(?P<>x)", "(?P<1a>x)", "(?P<a b>x)", "%Y\n%m", "a\nb", "%Y\\\n"]
    # random compositions
    r = random.Random(4242)
    atoms = toks + [" ", "-", "/", ":", "T", "[", "]", "\\s*", "\\s+", "(?: )?", "[ T]", "(?:T| )", ".*?", "\\d+", "\\w+", "(?P<_sep>[-/.])", "(?P=_sep)", "(?:", ")?", ")", "(", "^", "$",
                    "{^LN-BEG}", "{UNB}", "**", "\\.", "\\[", "(?i)", "x", "é", "{DATE}", "(?=x)", "(?<=x)", "(?!x)", "|", "*", "?", "+", "{2}"]
    for _ in range(1500):
        out.append("".join(r.choice(atoms) for _ in range(r.randint(1, 9))))
    return out


def render_pattern(p):
    """Naive line that might match pattern p (token substitution + regex cleanup)."""
    vals = {"a": "Sun", "A": "Sunday", "b": "Aug", "B": "August", "d": "14", "e": "14", "H": "10", "I": "10", "j": "226", "m": "08", "M": "00", "p": "AM", "S": "07",
            "U": "33", "w": "0", "W": "33", "y": "05", "Y": "2005", "z": "+0200", "Z": "CEST", "f": "123456", "k": "10", "l": "10", "ExY": "2005", "Exy": "05", "Exm": "08",
            "Exd": "14", "ExH": "10", "ExM": "00", "ExS": "07", "Exz": "+0200", "ExZ": "CET", "Exk": "10", "Exl": "10", "%": "%", "c": "Sun Aug 14 10:00:07 2005",
            "x": "08/14/05", "X": "10:00:07", "T": "10:00:07", "R": "10:00", "r": "10:00:07 AM", "G": "2005", "u": "7", "V": "33", "P": "am"}
    s = p
    s = re.sub(r"%(Ex[a-zA-Z]|[a-zA-Z%])", lambda m: vals.get(m.group(1), ""), s)
    s = s.replace("{DATE}", "Aug 14 10:00:07").replace("{^LN-BEG}", "").replace("{UNB}", "").replace("**", "")
    s = s.replace("{EPOCH}", "1124013600").replace("{LEPOCH}", "1124013600123").replace("EPOCH", "1124013600").replace("TAI64N", "@4000000037c219bf2ef02e94")
    s = s.replace("(?P<_sep>[-/.])", "-").replace("(?P=_sep)", "-").replace("\\s*", " ").replace("\\s+", " ").replace("\\s", " ").replace("[ T]", "T")
    s = s.replace("(?:T| )", "T").replace("\\d+", "123").replace("\\w+", "abc").replace(".*?", "z")
    s = re.sub(r"\(\?[:=!]|\(\?<[=!]|\(\?P<\w+>|\(\?i\)|\(\?#[^)]*\)", "", s)
    s = re.sub(r"[()^$|?*+]|\{\d+(?:,\d*)?\}", "", s)
    s = s.replace("\\.", ".").replace("\\[", "[").replace("\\]", "]").replace("\\", "")
    return s


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------
def gen_tz():
    cands = ["", "UTC", "GMT", "Z", "CET", "CEST", "EST", "PST", "PDT", "NST", "NPT", "ACST", "ChST", "WIB", "A", "Y", "ABC", "ABCD", "ABCDE", "ABCDEF", "abc", "utc",
             "UTC+0200", "UTC-0200", "UTC+02:00", "UTC+02", "UTC+2", "UTC+200", "UTC+02:0", "UTC+0", "GMT-3", "GMT-03", "GMT+0530", "CET+0100", "CET-01:00", "EST-05", "+0200", "-0200",
             "+02:00", "-02:30", "+02", "-02", "+2", "+0", "+00", "+0000", "-0000", "+1400", "+1560", "+1960", "+2400", "+25", "+2560", "+09", "+19", "+29", "+0A", "+-02", "02:00", "0200",
             "UTC +0200", " UTC", "UTC ", "UTC\n", "\nUTC", "+02:00\n", "UTC+02:00\n\n", "Europe/Paris", "CET-1", "UTC+٠٢٠٠", "+٠٢:٠٠", "UTC+\u0662\u0660\u0660", "ＵＴＣ", "UT", "Zulu",
             "AAAAA+0100", "AAAAAA+0100", "AA+0100", "A+0100", "Z+0100", "NPT+0545", "NPT-0545", "HAT", "NDT", "MART", "VET", "-12", "-1200", "+1200", "+13", "+14", "-13", "UTC-12:00",
             "UTC+00:60", "UTC+00:99", "+0099", "-0099"]
    cands += list(strptime.TZ_ABBR_OFFS.keys())[2:]
    out = []
    for c in cands:
        rec = {"in": c}
        try:
            rec["ok"] = strptime.validateTimeZone(c)
        except Exception as ex:  # noqa: BLE001
            rec["err"] = type(ex).__name__
        dd = DateDetector()
        try:
            dd.default_tz = c
            rec["setter"] = dd.default_tz
        except Exception as ex:  # noqa: BLE001
            rec["setter_err"] = type(ex).__name__
        out.append(rec)
    return out


def scenario_lines(scn, rnd_seed):
    """Per-scenario line selection: (corpus_all, synth, special)."""
    files = corpus_files()
    corpus = []
    for f in files:
        corpus += [(os.path.basename(f), l) for l in read_text_lines(f)]
    return files, corpus


def main():
    random.seed(0)
    files = corpus_files()
    per_file = {os.path.basename(f): read_text_lines(f) for f in files}
    corpus_all = []
    for f in files:
        corpus_all += per_file[os.path.basename(f)]
    harvested = []
    for p in ("datedetectortestcase.py", "filtertestcase.py", "samplestestcase.py", "clientreadertestcase.py"):
        harvested += [s for s in harvest_strings(os.path.join(TESTS, p)) if 3 <= len(s) <= 300 and re.search(r"\d", s)]
    harvested = sorted(set(harvested))
    patterns_h = sorted(set(harvest_patterns()))

    expanded = json.load(open(os.path.join(ROOT, "testdata", "expanded-regex.json")))
    samples = {}
    for d in ("stock", "tests-config"):
        for f in sorted(glob.glob(os.path.join(ROOT, "testdata", "samples", d, "*.json"))):
            j = json.load(open(f))
            samples["%s/%s" % (d, j["filter"])] = j["records"]
    filter_cfgs = []
    for key in sorted(expanded):
        e = expanded[key]
        basekey = "%s/%s" % (e["basedir"], e["filter"])
        recs = [r["line"] for r in samples.get(basekey, []) if json.dumps(r["filter_options"], sort_keys=True) == json.dumps(e["options"], sort_keys=True)]
        filter_cfgs.append((key, e["datepattern"], recs))
    user_patterns = sorted(set(sum([[p for p in (e["datepattern"] or "").split("\n") if p.strip()] for e in expanded.values()], [])))

    synth = synth_lines(1001)
    synth2 = synth_lines(2002, per_format=25)
    odd = odd_lines()
    dst = dst_lines()
    roll = rollover_lines()

    meta = {
        "python": sys.version.split()[0],
        "scenarios": SCENARIOS,
        "default_templates": ORIG_DEFAULTS,
    }
    all_runs = {}

    for scn in SCENARIOS:
        setup(scn)
        sid = scn["id"]
        runs = []
        full = scn["full"]
        r = random.Random(77)

        def pick(seq, n):
            seq = list(seq)
            if len(seq) <= n:
                return seq
            rr = random.Random(len(seq) * 31 + n)
            return rr.sample(seq, n)

        # --- default detector: fresh per line
        fresh_set = (corpus_all + harvested + odd + synth + dst + roll) if full else \
            (pick(corpus_all, 350) + pick(harvested, 100) + odd + pick(synth, 450) + pick(dst, 100) + roll[::4])
        # (split in chunks so the Rust test can spread them over threads)
        step_n = max(1, len(fresh_set) // 8 + 1)
        for c in range(0, len(fresh_set), step_n):
            runs.append(run({"kind": "default"}, fresh_set[c:c + step_n], fresh=True, tag="default-fresh"))
        # --- default detector, sequential (one per log file, like a real filter)
        if full:
            for name, ls in sorted(per_file.items()):
                runs.append(run({"kind": "default"}, ls, tag="default-seq:" + name))
            runs.append(run({"kind": "default"}, synth2 + odd + roll + dst, tag="default-seq:synth"))
        else:
            for name, ls in sorted(per_file.items())[:12]:
                runs.append(run({"kind": "default"}, ls[:200], tag="default-seq:" + name))
            runs.append(run({"kind": "default"}, pick(synth2 + odd + roll + dst, 800), tag="default-seq:synth"))
        # --- explicit default (addDefaultTemplate) and sorted order sanity
        runs.append(run({"kind": "default_now"}, pick(synth2, 300), tag="default_now"))

        # --- default_tz variants
        for tz in ([None, "UTC", "CET", "+0200", "-05:30", "EST", "UTC+02:00", "Z", "ChST", "NPT", "", "PDT+0100"] if full else ["UTC", "+0530", "-0800"]):
            ls = pick([l for l in synth if re.search(r"\d{2}:\d{2}", l)], 250 if full else 120) + odd[:40] + pick(roll, 60)
            runs.append(run({"kind": "default", "tz": tz}, ls, fresh=True, tag="tz:%s" % tz))

        # --- user date patterns from the filter configs (setDatePattern semantics) with their sample lines
        for key, dp, recs in filter_cfgs:
            if dp is None:
                if full:
                    runs.append(run({"kind": "default"}, recs, tag="filter-default:" + key))
                continue
            if not full and (zlib.crc32(key.encode()) % 3):
                continue
            ls = recs if full else recs[:60]
            runs.append(run({"kind": "multi", "pattern": dp}, ls, tag="filter:" + key))
            if full:
                runs.append(run({"kind": "multi", "pattern": dp}, ls, fresh=True, tag="filter-fresh:" + key))

        # --- single user patterns: construction info + rendered probe lines
        pat_pool = sorted(set(user_patterns + patterns_h + synth_patterns() + [h for h in harvested if len(h) < 60]))
        pat_pool = [p for p in pat_pool if not unkeyed_conversion(p)]
        if not full:
            pat_pool = pick(pat_pool, 250)
        probe_pool = pick(synth + odd, 60)
        for p in pat_pool:
            rendered = render_pattern(p)
            probes = [rendered, "x " + rendered + " y", rendered + "  trailing", "[" + rendered + "]", mutate(random.Random(len(p)), rendered)] + probe_pool[:12]
            probes = [q for q in probes if q]
            cfg = {"kind": "list", "patterns": [p]}
            runs.append(run(cfg, probes, tag="pattern"))
        # --- pairs of patterns (ordering, duplicates, mixed with defaults)
        pr = random.Random(5)
        # upstream compiles lazily (first use), so a bad pattern combined with a
        # duplicate reports the duplicate first; keep such combinations out
        pool_ok = [p for p in pat_pool if len(p) < 80 and build({"kind": "list", "patterns": [p]})[1] is None]
        for _ in range(200 if full else 40):
            ps = [pr.choice(pool_ok) for _ in range(pr.randint(2, 4))]
            ls = [render_pattern(p) for p in ps] + pick(synth, 25)
            runs.append(run({"kind": "list", "patterns": ps}, ls, tag="patterns"))

        # --- reordering sequences (state after each step), incl. aging of templates
        for seed in range(12 if full else 3):
            rr = random.Random(900 + seed)
            fmts = rr.sample(FORMATS, rr.randint(2, 5))
            seq = []
            for _ in range(rr.randint(4, 9)):
                f = rr.choice(fmts)
                for _ in range(rr.randint(1, 40)):
                    seq.append(rr.choice(PREFIX[:6]) + f(rr, comp(rr, [2005, 2004, 2006])) + rr.choice(SUFFIX[:5]))
            for _ in range(60):
                seq.append(rr.choice(fmts)(rr, comp(rr, [2005])) + rr.choice(SUFFIX))
            runs.append(run({"kind": "default"}, seq, orders=True, tag="reorder:%d" % seed))
            # same with time advancing (templates age out after 300 s)
            t = scn["now"]
            times = []
            for _ in seq:
                t += rr.choice([0, 0, 1, 5, 120, 301, 700, 4000])
                times.append(t)
            runs.append(run({"kind": "default"}, seq, orders=True, times=times, tag="reorder-aging:%d" % seed))
            MyTime.setTime(scn["now"])
        # a single-template detector and anchored sets
        for pat in ("{^LN-BEG}", "{DEFAULT}", "{^LN-BEG}\n%Y-%m-%d", "^{DATE}\n{DATE}"):
            runs.append(run({"kind": "multi", "pattern": pat}, pick(synth + odd, 300), orders=True, tag="multi:" + pat))
        MyTime.setTime(scn["now"])
        all_runs[sid] = runs

        # scenario time_re table
        time_re = dict(strptime.timeRE)
        patt, names = strptime.getTimePatternRE()
        scn_info = {"id": sid, "ExY": time_re["ExY"], "Exy": time_re["Exy"]}
        if sid == "pinned":
            meta["time_re"] = time_re
            meta["names"] = names
            meta["pattern_re"] = patt
            meta["tz_abbr"] = {str(k): v for k, v in strptime.TZ_ABBR_OFFS.items() if k is not None}
        meta.setdefault("scenario_info", []).append(scn_info)
        print("scenario %s: %d runs" % (sid, len(runs)), file=sys.stderr)

    # checks against accidental state leaks
    dump(os.path.join(OUT, "meta.json"), meta)
    dump(os.path.join(OUT, "lines.json"), LINES.table)
    dump(os.path.join(OUT, "strings.json"), STRINGS.names)
    setup(SCENARIOS[0])
    dump(os.path.join(OUT, "tz.json"), gen_tz())
    for sid, runs in all_runs.items():
        dump(os.path.join(OUT, "scn_%s.json" % sid), runs)


if __name__ == "__main__":
    main()
