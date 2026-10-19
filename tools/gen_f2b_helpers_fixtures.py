#!/usr/bin/env python3
"""Generate golden fixtures for crates/f2b-helpers from upstream Fail2Ban.

Imports the *real* upstream functions (fail2ban/helpers.py, stdlib shlex) and
evaluates them over a deterministic grid of inputs: values harvested from the stock
config (jail.conf, paths-*.conf, filter.d, action.d), the upstream unit-test
cases, adversarial hand-written cases and seeded exhaustive/random fuzz grids.
Python's result (or ValueError message) is recorded; the Rust tests assert exact
equality.

Also regenerates crates/f2b-helpers/src/pyunicode_tables.rs (Python's `\\w` and
`str.isprintable()` as range tables) from the running interpreter.

Output (sorted keys, ASCII-only JSON, deterministic):
  testdata/f2b-helpers/as_bool.json          [[input, bool], ...]
  testdata/f2b-helpers/merge_dicts.json      [[x pairs, y pairs, merged pairs], ...]
  testdata/f2b-helpers/splitwords.json       [[input, ignore_comments, [words]], ...]
  testdata/f2b-helpers/remove_comments.json  [[input, output], ...]
  testdata/f2b-helpers/extract_options.json  [{"in": s, "ok": [name, [[k, v], ...]]} | {"in": s, "err": msg}]
  testdata/f2b-helpers/split_with_options.json  [[input, [entries]], ...]
  testdata/f2b-helpers/substitute_tags.json  [{"tags": [[k, v]...], "conditional", "ignore": [..],
                                               "addrepl": [[k, v]...] | null, "ok": [[k, v]...] | "err": msg}]
  testdata/f2b-helpers/shlex_split.json      [{"in": s, "ok": [tokens]} | {"in": s, "err": msg}]
  testdata/f2b-helpers/unicode_class.json    boundary code points of Python's \\w / non-printable classes
                                             exercised through extract_options and tag-error reprs

Usage: tools/gen_f2b_helpers_fixtures.py [--upstream DIR] [--out DIR]
Stock-config inputs are produced by upstream's own readers (JailReader, FilterReader,
ActionReader) run on the stock config tree, so the dicts handed to
substituteRecursiveTags are exactly those upstream builds (getCombined()).
"""
import argparse
import configparser
import itertools
import json
import os
import random
import re
import shlex
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--upstream", type=Path, default=ROOT / "fail2ban")
    ap.add_argument("--out", type=Path, default=ROOT / "testdata" / "f2b-helpers")
    ap.add_argument("--src", type=Path, default=ROOT / "crates" / "f2b-helpers" / "src")
    return ap.parse_args()


ARGS = parse_args()
sys.path.insert(0, str(ARGS.upstream))
sys.dont_write_bytecode = True

from fail2ban.helpers import (  # noqa: E402
    _as_bool, splitwords, removeComments, extractOptions, splitWithOptions,
    substituteRecursiveTags, _merge_dicts,
)
import logging  # noqa: E402
logging.disable(logging.CRITICAL)
from fail2ban.client.jailreader import JailReader  # noqa: E402
from fail2ban.client.filterreader import FilterReader  # noqa: E402
from fail2ban.client.actionreader import ActionReader  # noqa: E402
from fail2ban.client.configparserinc import SafeConfigParserWithIncludes  # noqa: E402

CONFIG = ARGS.upstream / "config"


def dump(name, obj):
    ARGS.out.mkdir(parents=True, exist_ok=True)
    with open(ARGS.out / name, "w", encoding="ascii", newline="\n") as f:
        json.dump(obj, f, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
        f.write("\n")


def pairs(d):
    return [[k, v] for k, v in d.items()]


def is_rust_string(s):
    # Rust strings cannot hold lone surrogates.
    return not any(0xD800 <= ord(c) <= 0xDFFF for c in s)


def uniq(seq):
    seen = set()
    out = []
    for x in seq:
        key = json.dumps(x, sort_keys=True)
        if key not in seen:
            seen.add(key)
            out.append(x)
    return out


# --------------------------------------------------------------------------
# Unicode tables
# --------------------------------------------------------------------------
def ranges_of(pred):
    out = []
    for c in range(0x110000):
        if 0xD800 <= c <= 0xDFFF:
            continue
        if pred(chr(c)):
            if out and out[-1][1] == c - 1:
                out[-1][1] = c
            else:
                out.append([c, c])
    return out


WORD_RE = re.compile(r"\w")
SPACE_RE = re.compile(r"\s")
WORD_RANGES = ranges_of(lambda ch: WORD_RE.match(ch) is not None)
NONPRINTABLE_RANGES = ranges_of(lambda ch: not ch.isprintable())
SPACES = [c for c in range(0x110000) if not 0xD800 <= c <= 0xDFFF and SPACE_RE.match(chr(c))]
# str.strip() / isspace() must agree with \s (the Rust side uses one predicate for both).
assert all(chr(c).isspace() == (c in set(SPACES)) for c in range(0x110000) if not 0xD800 <= c <= 0xDFFF)


def write_tables():
    def fmt(name, rs):
        lines = [f"pub(crate) const {name}: &[(u32, u32)] = &["]
        for lo, hi in rs:
            lines.append(f"    (0x{lo:x}, 0x{hi:x}),")
        lines.append("];")
        return "#[rustfmt::skip]\n" + "\n".join(lines) + "\n"

    text = (
        "// @generated by tools/gen_f2b_helpers_fixtures.py from Python "
        f"{sys.version_info.major}.{sys.version_info.minor} "
        "(Unicode %s). Do not edit.\n" % __import__("unicodedata").unidata_version
        + "//\n// WORD_RANGES: code points matched by `re` `\\w` (str.isalnum() or '_').\n"
        "// NONPRINTABLE_RANGES: code points for which str.isprintable() is False.\n"
        + fmt("WORD_RANGES", WORD_RANGES)
        + fmt("NONPRINTABLE_RANGES", NONPRINTABLE_RANGES)
    )
    path = ARGS.src / "pyunicode_tables.rs"
    path.write_text(text, encoding="utf-8", newline="\n")


# --------------------------------------------------------------------------
# Config harvesting
# --------------------------------------------------------------------------
def raw_parser(path):
    cp = configparser.RawConfigParser(strict=False, interpolation=None)
    cp.optionxform = str
    cp.read(path, encoding="utf-8")
    return cp


def raw_values(paths):
    """Every raw option value (+ DEFAULT) of the given ini files."""
    out = []
    for p in paths:
        cp = raw_parser(p)
        for k, v in cp.defaults().items():
            out.append((k, v))
        for sec in cp.sections():
            for k, v in cp.items(sec):
                out.append((k, v))
    return out


def jail_sections():
    cp = raw_parser(CONFIG / "jail.conf")
    return [s for s in cp.sections() if s != "INCLUDES"]


def jail_options(basedir, sec):
    jr = JailReader(sec, force_enable=True, basedir=str(basedir), share_config={})
    if not jr.read():
        return None
    try:
        jr.getOptions()
    except Exception:
        return None
    return jr.options


ACTION_VARIANTS = [
    "%(action_)s", "%(action_mw)s", "%(action_mwl)s", "%(action_xarf)s",
    "%(action_cf_mwl)s", "%(action_blocklist_de)s", "%(action_abuseipdb)s",
    "%(action_)s\n         %(action_mwl)s",
    "%(action_)s\n%(action_blocklist_de)s\n%(action_abuseipdb)s",
    "iptables-multiport[name=x, port=\"ssh\"]\n   dummy",
]


def harvest_jail_values():
    """action/filter/banaction values: raw from jail.conf & paths-*.conf, and as resolved by
    upstream's JailReader (interpolated), including jail.local action overrides."""
    raw, resolved = [], []
    paths = [CONFIG / "jail.conf"] + sorted(CONFIG.glob("paths-*.conf"))
    for k, v in raw_values(paths):
        if k in ("action", "filter") or k.startswith(("action_", "banaction")):
            raw.append(v)
    for sec in jail_sections():
        o = jail_options(CONFIG, sec)
        if o:
            for k in ("action", "filter", "banaction", "banaction_allports"):
                if o.get(k):
                    resolved.append(o[k])
    tmp = Path(tempfile.mkdtemp(prefix="f2bh-"))
    try:
        shutil.copytree(CONFIG, tmp / "c", ignore=shutil.ignore_patterns("*.pyc"))
        for i, variant in enumerate(ACTION_VARIANTS):
            (tmp / "c" / "jail.local").write_text(
                "[DEFAULT]\nbanaction = iptables-multiport\nmta = sendmail\nlogpath = /var/log/x.log\n"
                "[sshd]\naction = %s\n[recidive]\naction = %s\n" % (
                    (variant.replace("\n", "\n    "),) * 2))
            for sec in ("sshd", "recidive"):
                o = jail_options(tmp / "c", sec)
                if o and o.get("action"):
                    resolved.append(o["action"])
    finally:
        shutil.rmtree(tmp)
    return raw, resolved


# --------------------------------------------------------------------------
# Fuzz helpers
# --------------------------------------------------------------------------
def exhaustive(alphabet, maxlen):
    for n in range(0, maxlen + 1):
        for t in itertools.product(alphabet, repeat=n):
            yield "".join(t)


def token_fuzz(rng, tokens, count, lo, hi):
    return ["".join(rng.choice(tokens) for _ in range(rng.randint(lo, hi))) for _ in range(count)]


# --------------------------------------------------------------------------
# as_bool / splitwords / remove_comments
# --------------------------------------------------------------------------
def gen_as_bool(config_values):
    inputs = [
        "", "0", "1", "2", "-1", "01", "10", "on", "ON", "On", "oN", "off", "OFF", "true", "TRUE",
        "True", "tRuE", "TrUe", "false", "False", "FALSE", "yes", "YES", "Yes", "yEs", "no", "NO",
        "y", "n", "t", "f", "Y", "T", "enable", "enabled", "disable", "disabled", "none", "None",
        " 1", "1 ", "\t1", "1\n", " true", "true ", "yes\n", "on ", " on", "tru", "truee", "yess",
        "ons", "\u0131", "\u0130N", "\u212a", "\uff11", "\uff34\uff32\uff35\uff25", "\u017f",
        "TRU\u0045", "\u0442rue", "1\x00", "\x001", "o\u0307n", "YE\u015e", "\u1e9e",
    ]
    inputs += [v for v in config_values if len(v) < 12]
    inputs = [s for s in uniq(inputs) if is_rust_string(s)]
    return [[s, _as_bool(s)] for s in inputs]


def comment_inputs(rng, config_texts):
    base = [
        "", " ", "#", ";", "# c", "; c", "a # c", "a ; c", "a#c", "a;c", "a\n# c\nb", "a\n#c\n;d\nb",
        "line1 A # comment ...\nline2 B ; comment ...", "\n\t\t\t# comment ...\n\t\t\t; comment ...\n"
        "\t\t\tline1 A # comment ...\n\t\t\tline2 B ; comment ...\n\t\t",
        "# a\n# b", "a\n\n# b", "a \n# b", "a\r\n# b\r\nc", "a\u00a0# b", "a\u2028# b\nc",
        "a\x1c# b", "x ;\ny", "x ; \n y", "1, 2 ,# 3, 4\n5", "a\t#c", "#\n#\n#", " #\n #", "a#b #c",
        "a ##", "a ;;;", "\n#", "\n\n#x", "#x\n\n#y\nz", "é # é\nü ; ü", "# é\n é # x",
        "abc\n  # c1\n  d # c2\n  # c3\ne",
    ]
    base += config_texts
    base += list(exhaustive(["a", " ", ",", "\n", "#", ";", "\t"], 4))
    alpha = ["a", "b", " ", " ", ",", "\n", "\n", "#", ";", "\t", "\u00a0", "\x1c", "\u2028", "\r", "é"]
    base += token_fuzz(rng, alpha, 4000, 5, 14)
    return [s for s in uniq(base) if is_rust_string(s)]


def gen_splitwords(inputs):
    out = []
    for s in inputs:
        for ic in (False, True):
            out.append([s, ic, splitwords(s, ignoreComments=ic)])
    return out


def gen_remove_comments(inputs):
    return [[s, removeComments(s)] for s in inputs]


def gen_merge_dicts():
    grid = [
        ({}, {}), ({"a": "1"}, {}), ({}, {"a": "1"}), ({"a": "1", "b": "2"}, {"b": "3", "c": "4"}),
        ({"b": "2", "a": "1"}, {"a": "9", "z": "0", "b": "8"}), ({"a": "1"}, {"b": "2"}),
        ({"k1": "v", "k2": "v", "k3": "v"}, {"k3": "w", "k1": "w"}), ({"a": ""}, {"a": "x"}), ({"a": "x"}, {"a": ""}),
    ]
    return [[pairs(x), pairs(y), pairs(_merge_dicts(x, y))] for x, y in grid]


# --------------------------------------------------------------------------
# extract_options / split_with_options
# --------------------------------------------------------------------------
TEST_EXTRACT = [
    "mail-whois[name=SSH]", "mail.who_is", "mail.who_is[a=cat,b=dog]", "mail--ho_is",
    "mail[a=',']", "mail[a=b, ]", "mail-how[",
    'mail[a="test with interim (wrong) "" quotes"]', "mail[a='test with interim (wrong) '' quotes']",
    "mail[a='x, y, z', b=x, y, z]", "mail['s']", "abc[]",
    'option[opt01=abc,opt02="123",opt03="with=okay?",opt04="andwith,okay...",opt05="how about spaces",'
    'opt06="single\'in\'double",opt07=\'double"in"single\',  opt08= leave some space, opt09=one for luck,'
    ' opt10=, opt11=]',
    'substitution[failregex="^<known/failregex>$", honeypot="<sweet>,<known/honeypot>", '
    'sweet="test,<known/honeypot>,test2"]',
    'substitution[failregex="^\\s*<Definition/failregex>\\s*$", honeypot="<default/honeypot>"]',
]
TEST_EXTRACT.append(TEST_EXTRACT[12].replace(",", "]["))

HAND_EXTRACT = [
    "", " ", "a", "a ", " a", "[", "[]", "[a=b]", "a[", "a]", "a[]", "a[] ", "a []", "a [b=c]",
    "a[b=c]", "a[b=c] ", "a[b=c]\n", "a[b=c]\n\n", "a[b=c]x", "a[b=c]]", "a[[b=c]]", "a[b=c][d=e]",
    "a[b=c] [d=e]", "a[b=c]\n[d=e]", "a[b=c]  [  d=e  ]", "a[b=c][]", "a[][b=c]", "a[b=c][][d=e]",
    "a[b=c,]", "a[b=c,,]", "a[,b=c]", "a[,]", "a[ , ]", "a[b=c, , d=e]", "a[b=c;d=e]",
    "a[b]", "a[b=]", "a[=c]", "a[b==c]", "a[b=c=d]", "a[b=c d]", "a[b=c  d ]", "a[b = c]", "a[ b=c ]",
    "a[ b = c ]", "a[b=\"c\"]", "a[b='c']", "a[b=\"c]", "a[b='c]", "a[b=\"c\" ]", "a[b=\"c\"d]",
    "a[b=\"c\" , d=e]", "a[b=\"c\"][d=e]", "a[b=\"c\" ][ d=e]", "a[b=\"c\"]\n[d=e]", "a[b=\"c\"d=e]",
    "a[b=\"\"]", "a[b='']", "a[b=\"\",c='']", "a[b=\" \"]", "a[b=\"  x  \"]", "a[b=\"x\ny\"]",
    "a[b=x\ny]", "a[b=x,\nc=y]", "a[b=x\n,c=y]", "a[b=\"x\"\n]", "a[b=\"x\"\n,c=d]",
    "a[b=c\n]", "a[b=c\n\n]", "a[b=c ]\n", "a[b=\"c\"]  \t\n ", "a[b=c,d=e,f=g]", "a[b=c,d=e,b=f]",
    "a[b=c][b=d]", "a[x?y=z=v]", "a[x?y=z]", "a[x?=z=v]", "a[?y=z=v]", "a[x?y=z=v, w?q=r=s]",
    "a[x?y=z=v][w?q=r=s]", "a[x?y?z=v=w]", "a[x?y=z?w=v]", "a[x.y-z_w=v]", "a[x y=v]", "a[x\ty=v]",
    "a[\tx=v]", "a[\nx=v]", "a[x=v\t]", "a[x=v\n]", "a[x=\"v\"\n]", "a[x=v]\n]", "a[x=v]\n ]",
    "a[x=v,\n]", "a[x=v,\n ]", "a[x=v,\n y]", "a[x=v, y]", "a[x=v,y]", "a[x=v,y=]", "a[x=v,'y']",
    "a[x=v,\"y\"]", "a['x'=v]", "a[\"x\"=v]", "a[x=v]a[y=w]", "a[x=v]a", "a[x=v] a", "a b[x=v]", "a[x=v]]]",
    "a[x=']']", "a[x=\"]\"]", "a[x=\"][\"]", "a[x=y][z=\"][\"]", "a[x=\"y\"][z=w]", "a[x=y]\n\n[z=w]",
    "a[x=y]  \n  [z=w]", "a[x=y][z=w", "a[x=y]z=w]", "a[x=y]['z'=w]", "a[x=y][z]", "a[x=y][z=w][",
    "a[x=y]][z=w]", "a[x=y][[z=w]]", "a[b=" + "c" * 40 + "\"d\"]", "a[b=\"" + "c" * 40 + "\"d" + "e" * 40 + "]",
    "a[" + "x" * 40 + "]", "a[b=c, " + "x" * 40 + "]", "a[b=c, " + "x y z " * 8 + "]",
    "a[b=\"c\" " + "x" * 40 + "]", "a[b=\"c\"" + "\u00e9" * 30 + "]", "a[\u00e9=\u00fc]", "a[\u00e9\u00e9=\u00fc, \u4e2d\u6587=\u2603]",
    "\u00e9[\u00e9=\u00fc, \u00fc]", "\u00e9\u00e9[b=\"c\"\u00fc]", "a[b=c, \u00fc\u00e9 d]", "a[b=\"c\" \u4e2d\u6587 \U0001f600]",
    "a[b=\u00a0c\u00a0]", "a[b=\u3000c\u3000, d=\u2003e]", "a[\u00a0b=c]", "a[b=c,\u00a0]", "a[b=c\u00a0]\u00a0",
    "a[b=c]\u00a0", "a[b=c]\x1c", "a[b=\x1cc\x1c]", "a[b=c]\x0b", "a[b=c]\x0c", "a[b=c]\x85", "a[b=c]\u2028",
    "a\tb[c=d]", "a[c=d]\tb", "x\n[a=b]", "x\u00a0[a=b]", "\n[a=b]", "[a=b]x",
    "name[a=1]\n", "n[a=1]\r\n", "n[a=1]\r", "n[a=\"1\r\n\"]", "n[a=1\r\n,b=2]", "n[a=\"1\"\r\n]",
    "n[a=1,\r\nb=2]", "n[a=1] \r\n [b=2]", "n[a=\"x\"\n", "n[a=\"x\"]\n[",
    "n[a=,b=,c=]", "n[a=,]", "n[a=,,]", "n[a=\"\",]", "n[a=\"\" ,]", "n[a=\"\"\n,b=\"\"\n]",
]


def extract_inputs(rng, config_values, extra_ws=True):
    base = list(TEST_EXTRACT) + HAND_EXTRACT
    for v in config_values:
        base.append(v)
        base.append(v.replace(",", "]["))
        base.append(v + "x")
        base.append(v[:-1] if v else v)
        base.append(v.replace("]", ""))
        base.append(" " + v + " ")
        base.append(v.replace('"', "'"))
        base.append(v.replace(", ", ",\n  "))
        # every line of multi-line values separately (as upstream does after splitWithOptions)
        base.extend(line for line in v.splitlines())
        base.extend(w for w in splitWithOptions(v))
    base += ["a[" + s + "]" for s in exhaustive(["x", "=", '"', ",", "]", "[", " ", "\n"], 4)]
    base += list(exhaustive(["a", "[", "]", "=", '"', "'", ",", " ", "\n"], 4))
    toks = ["a", "b", "x=y", "k=", "k='v w'", 'k="v, w"', "k=\"", "'", '"', ",", ", ", " ", "\n", "][", "] [",
            "[", "]", "?f=i", "x?f=i=", "=", "-", ".", "_", "\u00e9", "\u00a0", "\t", "  ", "w1=1", "w2=\"2\""]
    base += ["n[" + s + "]" for s in token_fuzz(rng, toks, 6000, 1, 9)]
    base += token_fuzz(rng, toks, 3000, 1, 9)
    base += ["n[" + s + "]" + t for s, t in zip(token_fuzz(rng, toks, 1500, 1, 7), token_fuzz(rng, toks, 1500, 0, 3))]
    return [s for s in uniq(base) if is_rust_string(s)]


def gen_extract(inputs):
    out = []
    for s in inputs:
        try:
            name, opts = extractOptions(s)
            out.append({"in": s, "ok": [name, pairs(opts)]})
        except ValueError as e:
            out.append({"in": s, "err": str(e)})
    return out


TEST_SPLIT = []
for sep in ("\n", "\t", " "):
    TEST_SPLIT += ["a%sb" % sep, "a[x=y]%sb" % sep, "a[x=y][z=z]%sb" % sep, 'a[x="y][z"]%sb' % sep,
                   'a[x="y z"]%sb' % sep, 'a[x="y\tz"]%sb' % sep, 'a[x="y\nz"]%sb' % sep]

HAND_SPLIT = [
    "", " ", "\n", "a", " a", "a ", "a  ", "a   b", "a  b", "a\n\nb", "a \n b", "a\n  b", "  a  ",
    "a[", "a[x", "a[x=", "a[x=y", "a[x=y]", "a[x=y] ", "a[x=y]  b", "a [x=y]", "a  [x=y]", "a\n[x=y]",
    "a [x=y] [z=w]", "a[x=y] [z=w]", "a[x=y]\n[z=w]", "a[x=y]\n\n[z=w]", "a[ x=y ]", "a[ x = y ]", "a[x=y ,z=w]",
    "a[x=y , z=w]", "a[x=y,z=w]", "a[x=y,\nz=w]", "a[x=y\n,z=w]", "a[\nx=y\n]", "a[\n x=y,\n z=w\n]",
    "a[x=y][z=w]b", "a[x=y]b", "a[x=y] b[z=w]", "a[x=y]\nb[z=w]\nc", "a[x=y]\n  b[z=w]\n  c",
    "a[x=\"y\"]", "a[x=\"y\"]b", "a[x=\"y\" ]", "a[x=\"y\"  ]  b", "a[x='y']", "a[x='y z']", "a[x=\"\"]", "a[x='']",
    "a[x=\"y]", "a[x='y]", "a[x=\"y\"z]", "a[x=y]z]", "a[x=y]]", "a[[x=y]]", "a[x=y z]", "a[x=y z] b",
    "a[x=y\nz] b", "a[x=y,z]", "a[x=y,z] b", "a[,x=y]", "a[,]", "a[ ,]", "a[]", "a[] b", "a[ ]", "a[ ] b", "a []", "a [] b",
    "a[x?f=i=y]", "a[x?f=i=y] b", "a[x?f=i]", "a[x?f=i] b", "a[x?=i=y]", "a[?f=i=y]", "[a]", "[a] b", "[", "]", "[]", "] [",
    "a[x=y]\n", "a[x=y]\n\n", "a[x=y] \n", "\na[x=y]", "a[x=y]\r\nb", "a\r\nb", "a\rb", "a\u00a0b", "a\u3000b", "a\x1cb", "a\x0bb",
    "a\x0cb", "a\u2028b", "a\x85b", "\u00e9[\u00fc=\u00e9]\u00e9", "\u00e9\u00e9[\u00fc=\u00e9] \u00e9", "a[\u00fc=\"\u00e9 \u00fc\"]  b",
    "a[x=y] \u00a0 b", "a[x=y]\u00a0b", "a[x=y]\u00a0\u00a0b", "a\u00a0\u00a0\u00a0b", "a\t\tb", "a\t \nb",
    "iptables-multiport[name=x, port=\"ssh\"]\n sendmail-whois[name=x]\n dummy",
    "a[x=y]\n   b\n   c[z=w]", "a\nb\nc", "a b c", "a  b  c  ", "a[b=c]d[e=f]g[h=i]", "a[b=c]  d[e=f]  g[h=i]",
    "a[b=\"c d\"] e[f='g h']\n i[j=\"k\nl\"]", "x[a=\"[\"]", "x[a=\"]\"] y", "x[a=\"][\"] y", "x[a=']'] y", "x[a=\"[\"][b=\"]\"] y",
    "x[a=b]\n]", "x[a=b\n]\n]", "x[a=b][", "x[a=b][ ", "x[a=b][\n", "x[a=b] [", "x[a=b] [ ", "x[a=b][c", "x[a=b][c=", "x[a=b][c=d",
    "x[a=b][c=d]", "x[a=b][c=d] ", "x[a=b][c=d]y", "x[a=b,", "x[a=b, ", "x[a=b,\n", "x[a=b,c", "x[a=b,c=", "x[a=b,c=d",
    "x[a=b ", "x[a=b  ", "x[a=b\n", "x[a=\"b\"", "x[a=\"b\" ", "x[a=\"b\"\n", "x[a=\"b\",", "x[a=\"b\"][", "x[a=\"b\"] [",
    "x[a=b]  \n  y", "x[a=b]\t\ty", "x[a=b]\n\t\ty", "x [ a = b ] y", "x [a=b ] y", "x [ a=b] y", "x\n[a=b]\n[c=d] y",
    "[a=b] [c=d]", "a=b c=d", "a=b\nc=d", "a,b c,d", "a, b", "a[,b]", "a[b,]", "a[b,,c]", "a[b=c,,d=e]", "a[b=,c=d]",
    "a[b=c,d=]", "a[b=,]", "a[b=,,]", "a[b=,\n]", "a[b=]", "a[b=] c", "a[=b]", "a[=b] c", "a[b==c]", "a[b==c] d",
]


def split_inputs(rng, raw_vals, resolved_vals):
    base = list(TEST_SPLIT) + HAND_SPLIT
    allvals = uniq(raw_vals + resolved_vals)
    for v in allvals:
        base.append(v)
        base.append(" " + v)
        base.append(v + "\n")
        base.append(v.replace("\n", "  "))
        base.append(v.replace("\n", " "))
        base.append(v.replace(" ", ""))
        base.append(v.replace(", ", ",\n"))
    # multi-line action lists, as typically written in jail.local
    pool = [v for v in resolved_vals if v and "\n" not in v][:60]
    for i in range(0, len(pool) - 2, 2):
        for sep in ("\n", "\n    ", " ", "  ", "\n\n", "\t", " \n "):
            base.append(sep.join(pool[i:i + 3]))
    base += list(exhaustive(["a", "[", "]", "=", '"', " ", "\n", ","], 4))
    toks = ["a", "b", "x=y", "k=", "k='v w'", 'k="v, w"', '"', "'", ",", ", ", " ", "  ", "\n", "\n ", "][", "] [",
            "[", "]", "?f=i", "x?f=i=", "=", "-", ".", "_", "\u00e9", "\u00a0", "\t", "w1=1", "w2=\"2\"", "n[x=y]", "n[]"]
    base += token_fuzz(rng, toks, 9000, 1, 10)
    base += token_fuzz(rng, toks, 3000, 8, 16)
    return [s for s in uniq(base) if is_rust_string(s)]


def gen_split(inputs):
    return [[s, splitWithOptions(s)] for s in inputs]


# --------------------------------------------------------------------------
# substituteRecursiveTags
# --------------------------------------------------------------------------
def _guarded_substitute():
    """Verbatim upstream substituteRecursiveTags with an abort once a value exceeds 50k chars.

    Fuzzed inputs can make upstream blow up exponentially (MemoryError); such cases are
    dropped, deterministically, after a guarded dry run. The recorded results always come
    from the unmodified upstream function.
    """
    import inspect
    import fail2ban.helpers as H
    src = inspect.getsource(H.substituteRecursiveTags)
    needle = "value = value.replace('<%s>' % rtag, repl)\n"
    assert needle in src
    m = re.search(r"^(\t+)" + re.escape(needle), src, re.M)
    src = src.replace(m.group(0), m.group(0) + m.group(1) + "if len(value) > 50000: raise OverflowError\n")
    ns = dict(vars(H))
    exec(compile(src, "<guarded>", "exec"), ns)
    return ns["substituteRecursiveTags"]


GUARDED = _guarded_substitute()
DROPPED = [0]


def run_subst(tags, conditional, ignore, addrepl_map, addrepl_fn=None):
    fn = addrepl_fn
    if fn is None and addrepl_map is not None:
        fn = addrepl_map.get
    try:
        GUARDED(tags, conditional, ignore=set(ignore), addrepl=fn)
    except OverflowError:
        DROPPED[0] += 1
        return None
    except ValueError:
        pass
    try:
        res = substituteRecursiveTags(tags, conditional, ignore=set(ignore), addrepl=fn)
        return {"ok": pairs(res)}
    except ValueError as e:
        return {"err": str(e)}


def tag_case(tags, conditional="", ignore=(), addrepl=None):
    tags = dict(tags)
    case = {
        "tags": pairs(tags),
        "conditional": conditional,
        "ignore": sorted(ignore),
        "addrepl": None if addrepl is None else pairs(addrepl),
    }
    res = run_subst(tags, conditional, ignore, addrepl)
    if res is None:
        return None
    case.update(res)
    return case


def action_cases_upstream():
    cases = []
    cases += [
        {'A': '<A>'}, {'A': '<B>', 'B': '<A>'}, {'A': '<B>', 'B': '<C>', 'C': '<A>'},
        {'A': 'to=<B> fromip=<IP>', 'C': '<B>', 'B': '<C>', 'D': ''},
        {'failregex': 'to=<honeypot> fromip=<IP>', 'sweet': '<honeypot>', 'honeypot': '<sweet>', 'ignoreregex': ''},
        {'X': 'x=x<T>', 'T': '1', 'Z': '<X> <T> <Y>', 'Y': 'y=y<T>'},
        {'X': 'x=x<T> <Z> <<R1>> <<R2>>', 'R1': 'Z', 'R2': 'Y', 'T': '1', 'Z': '<T> <Y>', 'Y': 'y=y<T>'},
        {'actionstart': 'ipset create <ipmset> hash:ip timeout <bantime> family <ipsetfamily>\n<iptables> -I <chain> <actiontype>',
         'ipmset': 'f2b-<name>', 'name': 'any', 'bantime': '600', 'ipsetfamily': 'inet',
         'iptables': 'iptables <lockingopt>', 'lockingopt': '-w', 'chain': 'INPUT', 'actiontype': '<multiport>',
         'multiport': '-p <protocol> -m multiport --dports <port> -m set --match-set <ipmset> src -j <blocktype>',
         'protocol': 'tcp', 'port': 'ssh', 'blocktype': 'REJECT'},
        {'A': '<<B><C>>', 'B': 'D', 'C': 'E', 'DE': 'cycle <A>'},
        {'DE': 'cycle <A>', 'A': '<<B><C>>', 'B': 'D', 'C': 'E'},
        {'HOST': "192.0.2.0", 'ABC': "123 <HOST>", 'xyz': "890 <ABC>"},
    ]
    return [c for c in map(tag_case, cases) if c]


def action_cases_hand():
    out = []
    # conditional lookup, ignore set, addrepl fallback, missing tags
    base = {
        'a': '<b> <c> <d>', 'b': 'B', 'b?family=inet6': 'B6', 'c': '<b>', 'd': '<HOST> <e?x>',
        'e': 'E', 'e?x': 'EX', 'f': '<g>', 'g': 'G<h>', 'h': 'H', 'n': '<<b><c>>', 'x': '', 'y': '<x>',
    }
    for cond in ("", "family=inet6", "x", "family=inet4"):
        for ign in ((), ("b",), ("h", "c"), ("a",), ("HOST", "e"), ("b", "c", "d", "e", "f", "g", "h")):
            for repl in (None, {"HOST": "1.2.3.4", "zz": "ZZ"}, {"q": "<a>", "HOST": "<b>", "d": "ZZ"}):
                out.append(tag_case(base, cond, ign, repl))
    # empty conditional values and empty replacement
    out.append(tag_case({'a': '<b>', 'b': ''}))
    out.append(tag_case({'a': '<b>', 'b?c': '', 'b': 'x'}, 'c'))
    out.append(tag_case({'a': '<b>'}, '', (), {'b': ''}))
    out.append(tag_case({}))
    out.append(tag_case({'a': 'no tags', 'b': 'a < b > c', 'c': '<>', 'd': '< >', 'e': '<a b>', 'f': '<<>>'}))
    out.append(tag_case({'a': '<b>', 'b': '<c', 'c': '>'}))
    out.append(tag_case({'a': '<<b>>', 'b': 'c', 'c': 'z', 'bc': 'q'}))
    out.append(tag_case({'a': '<<b>>', 'b': 'c', 'cc': 'q'}))
    out.append(tag_case({'a': '<<b>c>', 'b': 'x', 'xc': 'ok'}))
    out.append(tag_case({'a': '<b><b><b>', 'b': 'x<c>', 'c': 'y'}))
    out.append(tag_case({'a': '<b>\n<b>', 'b': '<c>', 'c': 'x'}))
    out.append(tag_case({'a': '\u00e9<b>\u00fc<b>', 'b': '\u4e2d<c>', 'c': '\U0001f600'}))
    out.append(tag_case({'a': '<<b>>', 'b': '\u00e9', '\u00e9': 'ok', '<b>': 'no'}))
    out.append(tag_case({'a': '\u00e9<<b>>\u00e9\u00e9<<b>>', 'b': 'c', 'c': 'x\u00e9<c2>', 'c2': '<b>'}))
    # growth through embedded tags that shifts earlier occurrences (positions after replacement)
    out.append(tag_case({'a': '<b><c><b>', 'b': '<<d>>', 'c': 'C', 'd': 'e', 'e': 'EE'}))
    out.append(tag_case({'a': '<a1><a2>', 'a1': 'x', 'a2': '<a1>'}))
    # repeat-count guard: embedded recursion pumping more than MAX_TAG_REPLACE_COUNT times
    chain = {'t0': '<t1>'}
    for i in range(1, 30):
        chain['t%d' % i] = '<t%d>' % (i + 1)
    chain['t30'] = 'end'
    out.append(tag_case(chain))
    out.append(tag_case({'a': '<<b>>', 'b': 'c', 'c': '<<b>>'}))
    out.append(tag_case({'A': '<B>', 'B': '<<C>>', 'C': 'D', 'D': '<<C>>'}))
    # tag names that need repr quoting in the error message
    for weird in ("it's", 'say"hi"', "back\\slash", "tab\there", "new\nline", "\u00e9", "\u00a0nb", "\u200b", "a'b\"c",
                  "\x01", "\x7f", "\U0001f600", "\U000e0001", "\ufeff", "\u2028", "\ud7ff", "\uffff"):
        out.append(tag_case({'A': '<%s>' % weird, weird: '<A>'}))
        out.append(tag_case({'A': '<%s>' % weird + '<%s>' % weird, weird: '<A>', 'z': '1'}))
        out.append(tag_case({'A': '<B>', 'B': '<%s>' % weird, weird: '<A>'}))
    return out


def action_cases_fuzz(rng, count):
    names = ["A", "B", "C", "D", "E", "AB", "x", "x?c", "A?c", "B?c", "HOST", "\u00e9", "AC", "BD"]
    vtoks = ["<A>", "<B>", "<C>", "<D>", "<E>", "<x>", "<HOST>", "<<A>>", "<<A><B>>", "<A><B>", "<<C>D>", "x", " ", "-",
             "<", ">", "<AB>", "<A?c>", "<x?c>", "\u00e9", "<\u00e9>", "", "<<x>>", "<c>"]
    out = []
    for _ in range(count):
        n = rng.randint(1, 6)
        keys = rng.sample(names, n)
        tags = {k: "".join(rng.choice(vtoks) for _ in range(rng.randint(0, 4))) for k in keys}
        cond = rng.choice(["", "", "c", "family=inet6"])
        ign = rng.sample(names, rng.randint(0, 2)) if rng.random() < 0.3 else []
        repl = None
        if rng.random() < 0.3:
            repl = {k: "".join(rng.choice(vtoks) for _ in range(rng.randint(0, 3))) for k in rng.sample(names, 3)}
        out.append(tag_case(tags, cond, ign, repl))
    return out


def stock_reader_cases():
    """Dicts exactly as upstream builds them in DefinitionInitConfigReader.getCombined()."""
    cases = []
    ignore_escaped = {"matches", "ipmatches", "ipjailmatches"}

    def combined(reader):
        combinedopts = reader._opts
        if reader._initOpts:
            combinedopts = {**combinedopts, **reader._initOpts}
        if not len(combinedopts):
            return None, None
        if any(not isinstance(v, str) for v in combinedopts.values()):
            # include-only files such as filter.d/common.conf: options without a value (None);
            # the Rust side has no counterpart of a valueless option.
            return None, None
        ignore = set()
        for n in combinedopts:
            cond = SafeConfigParserWithIncludes.CONDITIONAL_RE.match(n)
            if cond:
                ignore.add(cond.groups()[0])
        return combinedopts, ignore

    def add(reader, is_action):
        tags, ignore = combined(reader)
        if tags is None:
            return
        # addrepl in upstream is reader.getCombOption. Record every name the real method is
        # asked for (per parameter combination) and replay it from a dict, so the fixture is
        # self-contained; the dict result must equal the run with the real method.
        grid = [("", ignore)]
        if is_action:
            grid += [("family=inet6", ignore), ("", ignore | ignore_escaped)]
        for cond, ign in grid:
            queried = {}

            def recorder(name, reader=reader, queried=queried):
                v = reader.getCombOption(name)
                queried[name] = v
                return v

            real = run_subst(tags, cond, ign, None, addrepl_fn=recorder)
            if real is None:
                continue
            amap = {n: v for n, v in sorted(queried.items()) if v is not None}
            case = tag_case(tags, cond, ign, amap)
            assert case and real == {k: case[k] for k in real}, \
                "addrepl dict does not reproduce getCombOption"
            cases.append(case)
            if cond == "" and ign is ignore:
                cases.append(tag_case(tags, cond, ign, None))

    base = str(CONFIG)
    seen = set()
    # filters: every filter.d/*.conf, plus options as the stock jails pass them
    filter_calls = [(p.stem, {}) for p in sorted((CONFIG / "filter.d").glob("*.conf"))]
    for sec in jail_sections():
        o = jail_options(CONFIG, sec)
        if o and o.get("filter"):
            try:
                n, opts = extractOptions(o["filter"])
            except ValueError:
                continue
            filter_calls.append((n, opts))
    for mode in ("normal", "ddos", "extra", "aggressive"):
        filter_calls.append(("sshd", {"mode": mode}))
    for name, opts in filter_calls:
        key = ("f", name, json.dumps(opts, sort_keys=True))
        if key in seen:
            continue
        seen.add(key)
        r = FilterReader(name, "jail", dict(opts), share_config={}, basedir=base)
        if not r.read():
            continue
        try:
            r.getOptions(None)
        except Exception:
            continue
        add(r, False)
    # actions: every action.d/*.conf, plus options as the stock jails pass them
    action_calls = [(p.stem, {"name": "jail"}) for p in sorted((CONFIG / "action.d").glob("*.conf"))]
    for sec in jail_sections():
        o = jail_options(CONFIG, sec)
        if o and o.get("action"):
            for act in splitWithOptions(o["action"]):
                try:
                    n, opts = extractOptions(act)
                except ValueError:
                    continue
                opts = dict(opts)
                opts.setdefault("name", sec)
                action_calls.append((n, opts))
    for name, opts in action_calls:
        key = ("a", name, json.dumps(opts, sort_keys=True))
        if key in seen:
            continue
        seen.add(key)
        r = ActionReader(name, "jail", dict(opts), share_config={}, basedir=base)
        if not r.read():
            continue
        try:
            r.getOptions(None)
        except Exception:
            continue
        add(r, True)
    return cases


def unicode_inputs():
    """Boundary code points of the classes whose Python definition we embed."""
    pts = set()
    for rs in (WORD_RANGES, NONPRINTABLE_RANGES):
        for lo, hi in rs:
            pts.update((lo - 1, lo, hi, hi + 1))
    pts.update(range(0, 0x250))
    pts = sorted(c for c in pts if 0 <= c < 0x110000 and not 0xD800 <= c <= 0xDFFF)
    return pts


def gen_unicode(pts):
    extract, tags = [], []
    for c in pts:
        ch = chr(c)
        if ch in "<> ":
            continue
        for s in ("n[%s=1]" % ch, "n[a%s=\"%s\", b?%s=%s=v]" % (ch, ch, ch, ch), "n[%s%s=1]" % (ch, ch)):
            extract.append(s)
        tags.append(tag_case({"A": "<B>", "B": "<%s>" % ch, ch: "<A>"}))
    return gen_extract(extract), tags


# --------------------------------------------------------------------------
# shlex
# --------------------------------------------------------------------------
HAND_SHLEX = [
    "", " ", "\n", "a", "a b", " a  b ", "a\tb\nc\rd", "'a b'", '"a b"', "'a'b", "a'b'", "a'b c'd", '"a"b', 'a"b"c',
    "''", '""', "'' ''", "a ''", "'' a", "a''", "''a", "a\"\"b", "'a", '"a', "a'", 'a"', "'", '"', "\\", "a\\", "\\a", "\\ a",
    "a\\ b", "a\\\\b", "a\\'b", "a\\\"b", "'a\\'b'", "'a\\\\b'", "'a\\b'", '"a\\"b"', '"a\\\\b"', '"a\\b"', '"a\\$b"', '"a\\\nb"',
    "a\\\nb", "\\\n", "a\\\n", "'\\'", '"\\"', '"\\\\"', '"\\', "'\\", "a #b", "#a", "a#b", "a # b c", '"#"', "'#'", "a;b", "a|b",
    "a&&b", "$a ${b}", "a=b", "a=\"b c\"", "a='b c' d", "_SYSTEMD_UNIT=sshd.service + _COMM=sshd", "a\x00b", "\x00", "a\u00a0b",
    "\u00a0", "a\x0bb", "a\x0cb", "a\x1cb", "a\u2028b", "a\x85b", "\u00e9 \u00fc", "\u00e9'\u00fc \u4e2d'\u00e9", '\u4e2d"\\\u4e2d"',
    "\\\u00e9", "\\\U0001f600", "'\U0001f600'", "a  b", "a\n\nb", "a\\\\", "a\\\\\\", "'a''b'", '"a""b"', "'a'\"b\"'c'",
    "\"a'b\"", "'a\"b'", "\"a\\'b\"", "a\\'", "a\\\"", "\"\\'\"", "'\\\"'", "\"\\\\\\\"\"", "a b\\", "a 'b", "a \"b", "'a' 'b",
    "foo 'bar baz' \"qux quux\" corge\\ grault", "a\\\tb", "a\\ \\ b", "\\ ", " \\ ", "' '", "\" \"", "'\n'", "\"\n\"", "'\\\n'", "\"\\\n\"",
    "\"\\\n\\\n\"", "'a'\\\n'b'", "a'b\nc'd e", "x\"a\\nb\"", "x'a\\nb'", "\"\\a\\b\\c\"", "\"a\\ b\"", "\\\\\\\\",
]


def shlex_inputs(rng, journal_values):
    base = list(HAND_SHLEX)
    for v in journal_values:
        base.append(v)
        base.append(" " + v + " ")
        base.append(v.replace("+", "'+'"))
        base.append(v + "'")
        base.append(v + "\\")
        base.append(v.replace(" ", "\n"))
        base.append('"%s"' % v)
    base += list(exhaustive(["a", " ", "\\", "'", '"', "\n", "\t", "#", "$"], 4))
    toks = ["a", "b", " ", "  ", "\n", "\t", "\\", "'", '"', "\\\\", "\\'", '\\"', "''", '""', "#", "$x", "\u00a0", "\x0b",
            "\x1c", "\u00e9", "=", "+", "\r", "\\\n", "\\ ", "\x00"]
    base += token_fuzz(rng, toks, 12000, 1, 10)
    return [s for s in uniq(base) if is_rust_string(s)]


def gen_shlex(inputs):
    out = []
    for s in inputs:
        try:
            out.append({"in": s, "ok": shlex.split(s)})
        except ValueError as e:
            out.append({"in": s, "err": str(e)})
    return out


# --------------------------------------------------------------------------
def main():
    write_tables()
    rng = random.Random(0xF2B)

    raw_jail, resolved_jail = harvest_jail_values()

    # all raw config values (for as_bool/splitwords/remove_comments)
    conf_files = ([CONFIG / "jail.conf", CONFIG / "fail2ban.conf"] + sorted(CONFIG.glob("paths-*.conf"))
                  + sorted((CONFIG / "filter.d").glob("*.conf")) + sorted((CONFIG / "action.d").glob("*.conf")))
    all_raw = raw_values(conf_files)
    short_values = sorted({v for _, v in all_raw if v is not None})
    comment_texts = sorted({v for _, v in all_raw if v and len(v) < 600 and ("\n" in v or "#" in v or ";" in v or "," in v)})
    comment_texts += [Path(p).read_text(encoding="utf-8") for p in sorted((CONFIG / "filter.d").glob("sshd.conf"))]
    comment_texts += [Path(CONFIG / "jail.conf").read_text(encoding="utf-8")[:4000]]

    dump("as_bool.json", gen_as_bool(short_values))
    dump("merge_dicts.json", gen_merge_dicts())

    comment_in = comment_inputs(rng, comment_texts)
    dump("splitwords.json", gen_splitwords(comment_in))
    dump("remove_comments.json", gen_remove_comments(comment_in))

    config_vals = uniq(raw_jail + resolved_jail)
    config_vals = [v for v in config_vals if is_rust_string(v)]
    dump("extract_options.json", gen_extract(extract_inputs(rng, config_vals)))
    dump("split_with_options.json", gen_split(split_inputs(rng, raw_jail, resolved_jail)))

    cases = action_cases_upstream() + action_cases_hand() + action_cases_fuzz(rng, 2500) + stock_reader_cases()
    cases = [c for c in cases if c]
    dump("substitute_tags.json", cases)

    journal = []
    for k, v in all_raw:
        if k == "journalmatch":
            journal.append(v)
    for p in sorted((CONFIG / "filter.d").glob("*.conf")):
        r = FilterReader(p.stem, "jail", {}, share_config={}, basedir=str(CONFIG))
        if r.read():
            try:
                r.getOptions(None)
            except Exception:
                continue
            jm = r._opts.get("journalmatch")
            if jm is not None:
                journal.append(jm)
    dump("shlex_split.json", gen_shlex(shlex_inputs(rng, sorted(set(journal)))))

    pts = unicode_inputs()
    ex, tg = gen_unicode(pts)
    dump("unicode_class.json", {"extract": ex, "tags": tg})


if __name__ == "__main__":
    main()
