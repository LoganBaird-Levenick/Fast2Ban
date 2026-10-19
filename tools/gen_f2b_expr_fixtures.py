#!/usr/bin/env python3
"""Generate oracle fixtures for the f2b-expr crate from real upstream Fail2Ban.

Every expected value comes from calling the upstream implementation:

  * MyTime.str2seconds / MyTime.seconds2str   (fail2ban/server/mytime.py)
  * Jail.setBanTimeExtra + the evformula lambda fed with the observer's
    BanTimeIncr (fail2ban/server/jail.py, observer.py), which is also the only
    way upstream evaluates `bantime.factor` (an `eval`) and `bantime.formula`.

Output (deterministic, sorted keys): testdata/f2b-expr/
  str2seconds.json  [input, kind, repr]           kind: i f E(rror) or an
                    unsupported-by-design category (B bigint, X other type, b bool)
  seconds2str.json  [type(i|f), repr, status(ok|error|bignum), output]
  expr.json         [expression, kind, repr]      evaluated as `bantime.factor`
  bantime.json      option sets with the per-(rand,time,count) results
  floats.json       float reprs (for Display == Python repr)

Usage: tools/gen_f2b_expr_fixtures.py [--out DIR]
"""
import argparse
import ast
import json
import math
import os
import random
import struct
import sys
import warnings

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "fail2ban"))
warnings.simplefilter("ignore")
sys.setrecursionlimit(10000)

import logging  # noqa: E402

logging.disable(logging.CRITICAL)

from fail2ban.server.jail import Jail  # noqa: E402
from fail2ban.server.mytime import MyTime  # noqa: E402
from fail2ban.server.observer import ObserverThread  # noqa: E402

I64_MIN, I64_MAX = -(2**63), 2**63 - 1


def classify(r):
    """(kind, repr): i/f exact numbers, b bool, B bignum, X other type."""
    t = type(r)
    if t is bool:
        return ("b", repr(r))
    if t is int:
        return ("i", str(r)) if I64_MIN <= r <= I64_MAX else ("B", "")
    if t is float:
        return ("f", repr(r))
    return ("X", t.__name__)


def outcome(fn):
    try:
        return classify(fn())
    except BaseException as e:  # noqa: BLE001 - upstream raises anything
        if isinstance(e, KeyboardInterrupt):
            raise
        return ("E", type(e).__name__)


class Tracker:
    """Re-evaluates an expression and reports whether any int it computed
    (literal, operator result, call result) left the i64 range. Upstream's
    unbounded ints make such expressions valid; this crate returns an
    `Overflow` error for them by design (kind "B")."""

    class _Wrap(ast.NodeTransformer):
        def visit(self, node):
            node = self.generic_visit(node)
            if isinstance(node, (ast.BinOp, ast.UnaryOp, ast.Call, ast.IfExp, ast.BoolOp,
                                 ast.Constant)):
                call = ast.Call(func=ast.Name("_chk", ast.Load()), args=[node], keywords=[])
                return ast.copy_location(call, node)
            return node

    def __init__(self, src):
        try:
            tree = ast.parse(src, mode="eval")
            tree = ast.fix_missing_locations(Tracker._Wrap().visit(tree))
            self.code = compile(tree, "<tracked>", "eval")
        except BaseException:  # noqa: BLE001 - invalid source: upstream errors too
            self.code = None

    def big(self, **env):
        if self.code is None:
            return False
        flag = [False]

        def chk(v):
            if type(v) is int and not (I64_MIN <= v <= I64_MAX):
                flag[0] = True
            return v

        try:
            eval(self.code, {"_chk": chk, "math": math, **env})
        except BaseException:  # noqa: BLE001
            return False
        return flag[0]


def eval_text(src):
    """`eval(str)` strips leading spaces/tabs before compiling."""
    return src.lstrip(" \t")


# ---------------------------------------------------------------- str2seconds


UNITS = [
    "d", "da", "dd", "day", "days", "w", "we", "wee", "ww", "week", "weeks",
    "mo", "mon", "month", "months", "y", "ye", "yea", "yy", "year", "years",
    "s", "se", "sec", "ss", "second", "seconds", "m", "mi", "min", "mm",
    "minute", "minutes", "h", "ho", "hou", "hh", "hour", "hours",
]


def str2seconds_inputs():
    out = []
    add = out.append
    # every bantime/findtime/maxtime-like value in config/*.conf, docs and tests
    for v in ["10m", "48h", "1w", "1d", "1h", "1", "600", "3600", "-1", "1year",
              "1month", "1 month", "1 year", "30d", "24h", "12h", "5m", "30min",
              "1000 days", "60", "86400", "0", "10", "100", "1.5", "0.5", "3m",
              "1y6mo30w15d12h35m25s", "2yy 3mo 4ww 10dd 5hh 30mm 20ss",
              "2 years 3 months 4 weeks 10 days 5 hours 30 minutes 20 seconds",
              "1 year + 1 month - 1 week + 1 day",
              "2 * 0.5 yea + 1*1 mon - 3*1/3 wee + 2/2 day - (2*12 hou 3*20 min 80 sec) ",
              "2*.5y+1*1mo-3*1/3w+2/2d-(2*12h3*20m80s) ",
              "1ye -2mo -3we -4da -5ho -6mi -7se", "1hour+30min", "0d 1h 30m",
              "1year-6mo", "6 months", "1d12h", "1d 12h 30", "1h30m", "1h 30m 15s",
              "1 2", "1 2 3", "1  2", "1\t2", "1\n2", "1 \n 2", "10 20 30", "3 4 5 6",
              "1d 2d", "1y 1m", "1M", "1Mo", "1mi", "1mon", "1m o", "1ddd", "1dayss",
              "1daysx", "1 day s", "1da", "1dd", "d", "m", "s", "1d1", "1d1d", "1d 1",
              "a1", "1a1", "1e5", "1E5", "1e", "1e+", "1.5e3", "1.e3", ".5", "5.",
              "1_000", "1__0", "1_", "0x10", "0b1", "0o7", "00", "01", "0_0",
              "01.5", "- 1", "+1", "--1", "-+1", "+-1", "1+", "+", "-", "*", "**",
              "", " ", "  ", "\t", "\n", "\n\n", "(", ")", "()", "(1)", "((1))",
              "(1", "1)", "1 +", "+ 1", "5 # comment", "5#c", "#c\n5", "5\n#c",
              "10m # x", "10 #x\n20", "5\n", "5\n\n", "\n5", " 5", "\t5", "\f5",
              "5\f", "5\r", "5\r\n", "5\r6", "\n 5", "\f 5", " \f5", "(1\n+2)",
              "1 \\\n+2", "1\\\n", "1\\", "1 \\ 2",
              "1;2", "1,", "1,2", "'a'", '"a"', "'1'", "1j", "1J", "1 if 1 else 2",
              "1 if 0 else 2", "not 1", "True", "False", "None", "1<2", "1==1",
              "~1", "~-1", "1<<4", "1>>1", "1&3", "1|2", "1^3", "2**10", "2**-1",
              "2**0.5", "(-8)**0.5", "-8**0.5", "0**-1", "0**0", "0.0**-1",
              "7//2", "-7//2", "7//-2", "7%3", "-7%3", "7%-3", "7.5//2", "7.5%2",
              "1/3", "1/0", "1//0", "1%0", "1.0//0", "1.0%0", "1/0.0", "1e400",
              "-1e400", "1e400-1e400", "1e-400", "(1+2)*3", "2*3", "1+1", "1.0",
              "1.", "1 .real", "abs(1)", "min(1,2)", "max", "foo", "ban.Time",
              "math.pi", "__import__('os')", "(lambda: 1)()", "[1]", "{1}", "1[0]",
              "1 and 2", "0 or 5.0", "1 < 2 < 3", "1 if 2", "1 else 2", "else",
              "if", "and", "1 and", "1 or", "not", "1 not 2", "1 in 2", "1 is 2",
              "1 @ 2", "1 := 2", "x := 1", "1 = 1", "1 +* 2", "1 ** ** 2",
              "9223372036854775807", "9223372036854775808", "-9223372036854775807",
              "9223372036854775807+1", "9223372036854775807*2", "99999999999999999999",
              "1000000000000d", "1000000000y", "9007199254740993/3",
              "9007199254740993/1", "9223372036854775807/9223372036854775806",
              "9223372036854775807/3", "1/9223372036854775807",
              "9223372036854775807//2", "9223372036854775807%10",
              "1 2 ", " 1 2", "1d\u00a02h", "1\u00a02", "1 \u00a02", "1\u00a0d",
              "1\u2003d", "1\u3000d", "1\x1f2", "1\x0b2", "1\x1c2", "1\x852",
              "1\u0085d", "1\u1680d", "1\u2028d", "1\u2029 2",
              "\u00bd", "1\u00bd", "\u0661", "1\u0663", "\uff11", "1\uff11",
              "1\u017f", "1\u017fec", "1\u017feconds", "1\u017f2", "1m\u0131n",
              "1M\u0130N", "1\u212a", "1\u0131n", "1\u0130", "m\u0131n", "1\u00e9",
              "1 \u00e9", "\u00e9", "1d \u00e9", "10m # \u00fc", "10m #\u00fc\n",
              "1h # day", "1h # 2d 3d", "1h # 1 2", "1 # a\n 2", "(1 # c\n +2)",
              "(1\n\n+2)\n", "1 if 1 else", "x1", "_1", "1_x", "0_1", "0__0",
              "1.5.3", "1..2", "1..real", "1.if 1 else 2", "1if 1else 2", "1or 2",
              "1and 2", "1in 2", "1is 2", "1not in 2", "1else", "1ifx",
              "0x1for 2", "0x", "0xg", "0b2", "0o8", "0b12", "0X1F", "0B11", "0O17",
              "0x_f", "0xf_f", "0x__f", "1e1_0", "1e_1", "1_e1", "1.0_0", "1._0",
              "1_.0", "1e+1", "1e-1", "1E+1", ".e1", "e1", "1e1e1", "0e0", "0.", ".0",
              "00.5", "00e1", "0_0.5", "01e1", "1 \n", "1 \r\n 2"]:
        add(v)
    # unit spelling x case x number x separator
    for u in UNITS:
        for n in ("1", "2", "10", "1.5", "0.5", "0", "-1"):
            for sep in ("", " "):
                add(f"{n}{sep}{u}")
        add(f"1{u.upper()}")
        add(f"1 {u.capitalize()}")
        add(f"1{u}x")
        add(f"1{u}2")
        add(f"1{u}_")
        add(f"1{u}1{u}")
        add(f"1 {u} 1 {u}")
    # unit pairs with joiners
    pair_units = ["d", "day", "w", "mo", "y", "year", "s", "sec", "m", "min", "h", "hours"]
    for ua in pair_units:
        for ub in pair_units:
            for j in ("", " ", "+", " + ", "-", " - ", "*", "/", "  "):
                add(f"2{ua}{j}3{ub}")
    # exact int/int division, huge operands (CPython rounds correctly)
    rng = random.Random(20240601)
    for _ in range(400):
        a = rng.getrandbits(rng.randint(1, 63))
        b = rng.getrandbits(rng.randint(1, 63)) or 1
        sa = rng.choice(["", "-"])
        sb = rng.choice(["", "-"])
        op = rng.choice(["/", "//", "%", "*", "+", "-", "/"])
        add(f"{sa}{a}{op}{sb}{b}")
    # fuzz over a token alphabet (no `**`/`<<`: Python could take forever)
    toks = ["1", "2", "10", " ", " ", "+", "-", "*", "/", "(", ")", "d", "h", "m", "s",
            "w", "y", "mo", "min", ".", "5", "e", "_", "x", "0", "#", "//", "%", "\n",
            "\t", "day", "sec", "ye", "\\", "~", "&", "|", "^", ",", "if", "else", "1.5"]
    for _ in range(4000):
        t = "".join(rng.choice(toks) for _ in range(rng.randint(1, 9)))
        if "**" not in t:
            add(t)
    seen, uniq = set(), []
    for s in out:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq


def rewrite(val):
    """The text MyTime.str2seconds hands to eval (steps copied from upstream)."""
    val = MyTime._str2sec_prep.sub(r" \1", val)
    for rexp, rpl in MyTime._str2sec_parts:
        val = rexp.sub(rpl, val)
    return MyTime._str2sec_fini.sub(r"\1+\2", val)


# Python accepts these, this crate rejects them by design (documented).
STR2SEC_UNSUPPORTED = {"1 .real", "1..real", "abs(1)", "min(1,2)", "(lambda: 1)()"}


def gen_str2seconds():
    cases = []
    for s in str2seconds_inputs():
        k, r = outcome(lambda s=s: MyTime.str2seconds(s))
        if k in ("i", "f") and Tracker(eval_text(rewrite(s))).big():
            k, r = "B", ""
        if s in STR2SEC_UNSUPPORTED:
            assert k in ("i", "f"), s
            k, r = "U", ""
        cases.append([s, k, r])
    return {"cases": cases}


# ---------------------------------------------------------------- seconds2str


def gen_seconds2str():
    vals = []
    ints = [0, 1, 2, 5, 9, 10, 11, 29, 30, 31, 59, 60, 61, 119, 120, 121, 599, 600,
            3594, 3595, 3596, 3599, 3600, 3601, 3604, 3605, 3606, 3609, 3610, 3611,
            3615, 3619, 3620, 7199, 7200, 7205, 86399, 86400, 86401, 86429, 86430,
            86459, 86460, 86461, 90000, 100000, 604799, 604800, 604801, 608399,
            608400, 609000, 1000000, 31535999, 31536000, 31536001, 31579199,
            31579200, 31622400, 31622399, 100000000, 10**10, 10**15, I64_MAX,
            -1, -59, -60, -61, -3595, -3600, -86400, -31536000, I64_MIN,
            86400 * 390, 86400 * 368, 86400 * 15, 86400 * 14 - 10,
            86400 * 2 + 3600 * 7 + 60 * 15, 86400 * 2 + 3599, 3600 * 2 - 5,
            3600 - 5, 3600 - 10, 86400 * 365, 86400 * 366, 86400 * 7, 86400 * 30,
            86400 * 1000, 600, 1200, 2400, 4800, 9600, 19200, 38400, 76800, 153600]
    for v in ints:
        vals.append(v)
    floats = [0.0, -0.0, 0.5, 1.0, 1.5, 59.5, 59.9999, 60.0, 90.5, 119.99, 3594.9,
              3595.0, 3599.4, 3599.5, 3600.0, 3604.99, 3605.0, 3615.0, 3625.0,
              3600 * 3.52, 86400 * 365.49, 86400 * 365.5, 86400 * 365.51,
              86399.5, 86400.0, 86429.9, 86430.0, 86489.99, 86490.0, 604799.5,
              604800.0, 608399.99, 608400.0, 2629800.0, 31557600.0, 31535999.5,
              31536000.0, 1e-7, 1e-300, 5e-324, 1e15, 1e17, 1e20, 1e22, 1e23,
              1e24, 1e25, 1e300, 1.7976931348623157e308, float("inf"), float("-inf"),
              float("nan"), -0.5, -59.5, -90.5, -3600.5, -1e20, -1e25, 86400 * 2.5,
              86400 * 1.5, 43200.0, 129600.0, 216000.0, 1209600.0 - 1801.0,
              1209600.0 - 1800.0, 1209600.0 + 1800.0, 172800.0 + 30.0]
    for v in floats:
        vals.append(v)
    rng = random.Random(77)
    for _ in range(1500):
        mag = rng.choice([2, 3, 4, 5, 6, 7, 8, 9, 10])
        v = rng.randint(0, 10**mag)
        vals.append(v)
        vals.append(v + rng.random())
        vals.append(round(rng.random() * 10**mag, rng.randint(0, 3)))
    cases = []
    seen = set()
    for v in vals:
        key = (type(v).__name__, repr(v))
        if key in seen:
            continue
        seen.add(key)
        tag = "i" if isinstance(v, int) else "f"
        try:
            s = str(MyTime.seconds2str(v))
            status = "ok"
        except BaseException as e:  # noqa: BLE001
            s, status = type(e).__name__, "error"
        if (status == "ok" and tag == "f" and v == v and abs(v) != float("inf")
                and v / 86400 >= 2**63):
            status = "bignum"
        cases.append([tag, repr(v), status, s if status == "ok" else ""])
    return {"cases": cases}


# ----------------------------------------------------------- bantime / expr


_jail = Jail("expr-oracle")


def factor_outcome(expr):
    """`eval(factor)` as upstream does it, observed as 1 * banFactor * 1."""
    def run():
        # a previously failed factor stays in the jail's options: reset it first
        _jail.setBanTimeExtra("factor", "1")
        _jail.setBanTimeExtra("multipliers", "1")
        _jail.setBanTimeExtra("factor", expr)
        f = _jail.getBanTimeExtra()["evformula"]
        return f(ObserverThread.BanTimeIncr(1, 0))
    return outcome(run)


OPERANDS = ["0", "1", "2", "3", "7", "10", "(-1)", "(-2)", "(-7)", "0.0", "(-0.0)", "0.5",
            "(-0.5)", "2.5", "(-2.5)", "1e308", "1e-308", "True", "False", "1e22",
            "(1e400)", "(-1e400)", "(1e400-1e400)", "255", "0x10"]
BIG_OPERANDS = ["9223372036854775807", "(-9223372036854775807)", "9007199254740993",
                "4611686018427387904", "3037000500", "3037000499"]
BINOPS = ["+", "-", "*", "/", "//", "%", "**", "<<", ">>", "&", "|", "^"]


def expr_inputs():
    out = []
    add = out.append
    for a in OPERANDS:
        for b in OPERANDS:
            for op in BINOPS:
                add(f"{a} {op} {b}")
        for op in ["<", "<=", ">", ">=", "==", "!="]:
            for b in OPERANDS[:12]:
                add(f"{a} {op} {b}")
        add(f"-{a}")
        add(f"+{a}")
        add(f"~{a}")
        add(f"not {a}")
        for fn in ["abs", "int", "float", "round", "math.floor", "math.ceil", "math.trunc",
                   "math.sqrt", "math.exp", "math.log", "math.log2", "math.log10",
                   "math.fabs"]:
            add(f"{fn}({a})")
        for nd in ["0", "1", "2", "3", "(-1)", "(-2)", "(-3)", "10", "400", "(-400)", "True"]:
            add(f"round({a}, {nd})")
        for b in ["2", "10", "0.5", "(-1)", "0", "1", "(1e400)"]:
            add(f"math.log({a}, {b})")
        add(f"{a} and 7")
        add(f"{a} or 7")
        add(f"7 if {a} else 8")
        add(f"min({a}, 1)")
        add(f"max({a}, 1)")
        add(f"min(1, {a}, 2)")
        add(f"max(1, {a}, 2)")
    for a in BIG_OPERANDS:
        for b in OPERANDS + BIG_OPERANDS:
            for op in ["+", "-", "*", "/", "//", "%", "&", "|", "^"]:
                add(f"{a} {op} {b}")
            for op in ["<", "<=", ">", ">=", "==", "!="]:
                add(f"{a} {op} {b}")
        for op in [">>"]:
            for b in ["0", "1", "62", "63", "64", "100"]:
                add(f"{a} {op} {b}")
        for fn in ["abs", "int", "float", "round", "math.floor", "math.sqrt", "math.log"]:
            add(f"{fn}({a})")
        add(f"-{a}")
        add(f"~{a}")
        add(f"round({a}, -1)")
        add(f"round({a}, -18)")
        add(f"round({a}, -19)")
        add(f"round({a}, -40)")
    for a in ["0", "1", "2", "3", "62", "63", "64", "(-1)", "100"]:
        for b in ["0", "1", "2", "3", "62", "63", "64", "(-1)", "100"]:
            add(f"{a} << {b}")
            add(f"{a} >> {b}")
            add(f"(-3) << {b}" if a == "0" else f"(-3) >> {a}")
    for e in ["2 ** 62", "2 ** 63", "2 ** 64", "(-2) ** 63", "(-2) ** 64", "3 ** 39", "3 ** 40",
              "(-3) ** 39", "10 ** 18", "10 ** 19", "0 ** 100", "1 ** 100000", "(-1) ** 100001",
              "(-1) ** 100000", "0 ** 0", "(-1) ** (-1)", "2 ** (-2)", "2 ** (-1074)",
              "2 ** (-1075)", "10 ** (-5)", "2.0 ** 1024", "2.0 ** 1023", "(-2.0) ** 1024",
              "(-2.0) ** 1023", "(-8) ** (1/3)", "(-8.0) ** 3.0", "(-8.0) ** (-3.0)",
              "0.0 ** 0.0", "0 ** 0.0", "0.0 ** (-1.0)", "0.0 ** (-2)", "(-0.0) ** (-3)",
              "(-0.0) ** 3", "(-0.0) ** 2", "(-0.0) ** (-3.0)", "1e400 ** 0", "1e400 ** (-1)",
              "(-1e400) ** 3", "(-1e400) ** 2", "(-1e400) ** (-3)", "(-1e400) ** (-2)",
              "0.5 ** 1e400", "2 ** 1e400", "0.5 ** (-1e400)", "2 ** (-1e400)", "1 ** 1e400",
              "(-1) ** 1e400", "(1e400-1e400) ** 0", "1 ** (1e400-1e400)",
              "2 ** (1e400-1e400)", "(1e400-1e400) ** 2", "2 ** 0.5", "4 ** 0.5", "8 ** (1/3)",
              "10 ** 308", "10.0 ** 308", "10.0 ** 309", "10 ** -309", "7 ** 0.0",
              "-2 ** 2", "-2 ** -2", "2 ** -2 ** 2", "2 ** 3 ** 2", "(2 ** 3) ** 2",
              "-(2 ** 2)", "- - 2", "+ - + 2", "~ ~ 5", "- ~ 5", "~ - 5", "not not 0",
              "not 0 == 1", "1 < 2 < 3", "1 < 2 > 3", "3 > 2 > 1", "1 == 1 == 1", "1 == 1 != 2",
              "1 < 1 == 1", "1 <= 1 >= 1", "0 < 1 < 1e400", "1 < (1e400-1e400) < 3",
              "(1e400-1e400) == (1e400-1e400)", "(1e400-1e400) != (1e400-1e400)",
              "(1e400-1e400) < 1", "max(1, 1e400-1e400)", "max(1e400-1e400, 1)",
              "min(1, 1e400-1e400)", "min(1e400-1e400, 1)", "max(1, 1.0)", "max(1.0, 1)",
              "min(1, 1.0)", "min(1.0, 1)", "max(True, 1)", "max(1, True)", "min(True, 1)",
              "max(0, False)", "max(False, 0)", "max(2, 3.5, 3)", "min(2, 3.5, 3)",
              "max(1, 2, 3, 4, 5, 6, 7, 8)", "min(5, 4, 3, 2, 1, 2,)", "max(1, 2,)", "max(1,)",
              "max()", "min(1)", "max(1)", "abs()", "abs(1, 2)", "int()", "int(1, 2)",
              "int(1, 10)", "float()", "float(1, 2)", "round()", "round(1, 2, 3)", "pow(2)",
              "pow(2, 3)", "pow(2, 3, 5)", "pow(2, -1)", "pow(2.5, 2)", "pow(0, -1)",
              "pow(-8, 1/3)", "abs(-9223372036854775807)", "abs(-9223372036854775807 - 1)",
              "-(-9223372036854775807 - 1)", "-9223372036854775807 - 1",
              "-9223372036854775807 - 2", "(-9223372036854775807 - 1) // -1",
              "(-9223372036854775807 - 1) % -1", "(-9223372036854775807 - 1) / -1",
              "9223372036854775807 + 1.0", "9223372036854775807 * 1.0",
              "int(9223372036854775807.0)", "int(9223372036854775808.0)",
              "int(-9223372036854775808.0)", "int(-9223372036854777856.0)",
              "int(1e19)", "int(2.9)", "int(-2.9)", "int(1e400)", "int(1e400-1e400)",
              "int(0.0)", "int(-0.0)", "int(True)", "float(True)", "float(9223372036854775807)",
              "float(-9223372036854775807)", "round(0.5)", "round(1.5)", "round(2.5)",
              "round(-0.5)", "round(-1.5)", "round(-2.5)", "round(2.675, 2)", "round(0.125, 2)",
              "round(0.375, 2)", "round(1.005, 2)", "round(5.5)", "round(6.5)", "round(1e22)",
              "round(1e19)", "round(1e18)", "round(-1e19)", "round(1e300)", "round(0.1, 20)",
              "round(0.1, 323)", "round(0.1, 324)", "round(5e-324, 323)", "round(5e-324, 324)",
              "round(1.5e-323, 323)", "round(123456.789, -2)", "round(123456.789, -5)",
              "round(123456.789, -6)", "round(150, -2)", "round(250, -2)", "round(350, -2)",
              "round(-150, -2)", "round(-250, -2)", "round(149.99, -2)", "round(150.0, -2)",
              "round(250.0, -2)", "round(250.1, -2)", "round(1e22, -22)", "round(1e22, -23)",
              "round(5e22, -22)", "round(5e22, -23)", "round(1.5e22, -22)", "round(2.5e22, -22)",
              "round(1e300, -300)", "round(1.7e308, -308)", "round(1.7e308, -309)",
              "round(9.5e307, -308)", "round(999.9, -3)", "round(999.9, -4)", "round(500.0, -3)",
              "round(1500.0, -3)", "round(0.0, -3)", "round(-0.0, 2)", "round(-0.001, 2)",
              "round(-0.4)", "round(0.4, 0)", "round(-0.4, 0)", "round(7, -1)", "round(15, -1)",
              "round(25, -1)", "round(-15, -1)", "round(-25, -1)", "round(5, -1)",
              "round(4, -1)", "round(95, -2)", "round(50, -2)", "round(51, -2)", "round(7, 1)",
              "round(7, -30)", "round(7, 30)", "round(True)", "round(True, -1)", "round(7, 1.5)",
              "round(7.5, 1.0)", "round(7, 2.0)", "round(7, None)", "round(1e400)",
              "round(1e400, 2)", "round(1e400-1e400)", "round(1e400-1e400, 2)",
              "round(-1e400, 2)", "round(0.5, 400)", "round(2.5, -400)",
              "math.pi", "math.e", "math.tau", "math.inf", "math.nan", "-math.inf", "math.pi * 2",
              "math.exp(0)", "math.exp(1)", "math.exp(709)", "math.exp(710)", "math.exp(-745)",
              "math.exp(-746)", "math.exp(-1e400)", "math.exp(1e400)", "math.exp(1e400-1e400)",
              "math.log(0)", "math.log(0.0)", "math.log(-1)", "math.log(1)", "math.log(1e400)",
              "math.log(-1e400)", "math.log(8, 2)", "math.log(1000, 10)", "math.log(2, 1)",
              "math.log(1, 1)", "math.log(5, 0)", "math.log(5, -1)", "math.log(1e400, 2)",
              "math.log(2, 1e400)", "math.log(1e300, 1e-300)", "math.log(0, 2)",
              "math.log2(8)", "math.log2(0)", "math.log2(-1)", "math.log2(1e-300)",
              "math.log10(1000)", "math.log10(0)", "math.log10(1e-5)", "math.log10(1e22)",
              "math.sqrt(2)", "math.sqrt(-1)", "math.sqrt(0)", "math.sqrt(-0.0)", "math.sqrt(1e400)",
              "math.sqrt(1e400-1e400)", "math.sqrt(9223372036854775807)", "math.fabs(-2)",
              "math.fabs(-0.0)", "math.floor(2.5)", "math.floor(-2.5)", "math.floor(7)",
              "math.ceil(2.5)", "math.ceil(-2.5)", "math.ceil(-0.5)", "math.ceil(7)",
              "math.trunc(2.5)", "math.trunc(-2.5)", "math.floor(1e19)", "math.floor(1e400)",
              "math.floor(1e400-1e400)", "math.floor(True)", "math.pow(2, 3)", "math.pow(2, -1)",
              "math.pow(0, -1)", "math.pow(-8, 1/3)", "math.pow(-2, 3)", "math.pow(2, 1e400)",
              "math.pow(10, 400)", "math.pow(0.5, 2)", "math.pow(0, 0)", "math.pow(2)",
              "math.exp()", "math.exp(1, 2)", "math.log()", "math.log(1, 2, 3)", "math.foo(1)",
              "math.foo", "math", "math.", "math(1)", "math.exp", "math.sin(1)",
              "math.pow(2, 0.5)", "math.hypot(3, 4)", "math.exp(2) / math.exp(1)",
              "math.exp(float(3 + 1) * 0.693147)", "math.exp(1) ** 2",
              "random.random()", "random", "random.random", "ban", "ban.Time", "ban.Count",
              "banFactor", "ban.Time * 2", "max", "min", "abs", "int", "float", "round", "pow",
              "True", "False", "None", "True + True", "True * 3", "True / 2", "True // 2",
              "True % 2", "True ** 2", "True << 3", "True >> 1", "True & True", "True | False",
              "True ^ True", "True & 1", "~True", "-True", "+True", "not True", "True == 1",
              "True and 5", "False or 0.0", "False or False", "0 or 0.0", "0.0 or 0", "1 and 0.0",
              "0.0 and 1", "1 and 2 and 3", "0 or 0 or 3", "1 or 2 or 3", "0 and 1 or 2",
              "1 and 0 or 2", "1 or 0 and 5", "not 1 and 5", "not 0 or 5", "not (1 and 0)",
              "1 if 1 else 2 if 1 else 3", "1 if 0 else 2 if 1 else 3", "1 if 0 else 2 if 0 else 3",
              "(1 if 0 else 2) if 1 else 3", "1 if 1 if 0 else 0 else 5", "1 + 1 if 1 else 2 + 2",
              "1 if 1 else 1 / 0", "1 / 0 if 0 else 2", "1 if 0 else 1 / 0", "1 or 1 / 0",
              "0 and 1 / 0", "1 and 1 / 0", "0 or 1 / 0", "1 if 1 else 2 else 3", "1 if else 2",
              "1 if 1", "if 1 else 2", "1 else 2", "1 if 1 else", "1 if 1 else 2 if 0",
              "2 * 3 + 4", "2 + 3 * 4", "(2 + 3) * 4", "2 * (3 + 4)", "10 - 3 - 2", "10 / 5 / 2",
              "10 // 3 // 2", "2 ** 3 * 2", "2 * 3 ** 2", "1 << 2 + 1", "1 + 2 << 1", "1 << 2 * 3",
              "6 >> 1 << 1", "6 & 3 | 8", "6 | 3 & 8", "6 ^ 3 & 2", "1 | 2 ^ 3 & 4", "1 + 2 & 3",
              "1 << 2 & 3", "1 | 2 < 3", "5 & 4 == 4", "1 + 2 < 4", "-2 ** 2", "(-2) ** 2",
              "- 2 ** 2", "2 ** - 2", "2 ** + 2", "2 ** ~1", "2 ** not 1", "not 1 + 1", "~1 + 1",
              "~ 1.5", "~1.5", "1.5 << 1", "1 << 1.5", "1.5 & 1", "1 | 1.5", "1 ^ 1.0", "1.0 >> 1",
              "5 // 0.0", "5 % 0.0", "5.0 // 0", "5.0 % 0", "5 / 0", "5 // 0", "5 % 0", "0 / 0",
              "0.0 / 0.0", "1e400 / 1e400", "1e400 // 1", "1e400 % 1", "1 % 1e400", "-1 % 1e400",
              "1 % -1e400", "-1 % -1e400", "1 // 1e400", "-1 // 1e400", "1 // -1e400",
              "-1 // -1e400", "1e400 // 1e400", "5.5 // 2", "-5.5 // 2", "5.5 // -2", "-5.5 // -2",
              "5.5 % 2", "-5.5 % 2", "5.5 % -2", "-5.5 % -2", "7 % 2.5", "-7 % 2.5", "7 // 2.5",
              "-7 // 2.5", "0.5 // 0.1", "1 // 0.1", "1 % 0.1", "0.3 % 0.1", "1e22 % 3", "1e22 // 3",
              "1e300 // 1e-300", "1e-300 // 1e300", "-1e-300 // 1e300", "1e-300 % 1e300",
              "-1e-300 % 1e300", "0.0 // 5", "-0.0 // 5", "0.0 // -5", "0.0 % 5", "-0.0 % 5",
              "0.0 % -5", "-0.0 % -5", "5 % -0.0001", "0.1 + 0.2", "0.1 * 3", "1 / 3", "2 / 3",
              "10 / 4", "10 / 5", "7 / 7", "1e300 * 1e10", "1e-300 * 1e-300", "-1e300 * 1e10",
              "1e308 + 1e308", "1e16 + 1", "1e16 + 2", "9007199254740993 + 0.0",
              "9007199254740993 == 9007199254740992.0", "9007199254740993 > 9007199254740992.0",
              "9007199254740993 < 9007199254740994.0", "9223372036854775807 == 9223372036854775808.0",
              "9223372036854775807 < 9223372036854775808.0", "9223372036854775807 > 9.3e18",
              "-9223372036854775807 > -9.3e18", "-9223372036854775807 - 1 == -9223372036854775808.0",
              "9223372036854775807 == 1e400", "9223372036854775807 < 1e400", "1 == 1.0", "1 != 1.0",
              "1 == True", "2 > True", "1.5 > True", "1e400 > 9223372036854775807",
              "-1e400 < -9223372036854775807", "0.1 + 0.2 == 0.3", "2.5 == 2.5", "0.5 < 1",
              "1 < 1.5 < 2", "1 < 1.5 < 1", "1e400 == 1e400", "1000000.0", "100000000000000000.0",
              "1e16", "1e15", "123456789012345678.0", "0.0001", "0.00001", "0.000123", "1.5e-5",
              "12345.6789e3", "5e-324", "1.7976931348623157e308", "2.2250738585072014e-308",
              "1e-7", "1e100", "1e+16", "4.35", "0.1", "1/7", "2/3 * 3", "100 * 1.1", "3 * 1.1",
              "1e22", "1e23", "9.999999999999999e22", "123456789.123456789", "1e-5 * 10",
              "0.30000000000000004", "(1)", "((1))", "(((((((((1)))))))))", "(1 + (2 * (3 + (4))))",
              "(1,)", "(1, 2)", "()", "(1", "1)", "1 2", "1 +", "* 1", "1 *", "1 ** ", "1 // // 2",
              "1 / / 2", "1 < < 2", "1 <> 2", "1 => 2", "1 =< 2", "1 = 2", "1 ! 2", "1 != ",
              "1 ?", "1 $ 2", "1 ` 2", "1 ; 2", "1 : 2", "1 @ 2", "1 # 2", "# 1", "1 #", "1 # 2 +",
              "1 +\n2", "(1 +\n2)", "(1 #c\n+ 2)", "1 \\\n+ 2", "1 \\\n\n", "1 +\\\n2", "\\\n1",
              "1\n", "1\n\n", "1\n \n", "1\n2", "\n1", "\n\n1", "\n 1", " 1", "  1", "\t1", "\f1",
              "\f 1", " \f1", " \t 1", "1 ", "1  ", "1\t", "1\f", "1\r", "1\r\n", "1\r\n2",
              "1\x0b", "\x0b1", "1\x1f", "1\u00a0", "\u00a01", "1\u2003", "1 \u2003", "1\x00",
              "1\x01", "1\x7f", "1\u00e9", "\u00e9", "1 # \u00e9", "1 # \U0001f600\n",
              "'1'", '"1"', "'1' + '2'", "'a' * 3", "3 * 'a'", "1 + '1'", "b'1'", "f'1'", "r'1'",
              "'''1'''", "1j", "1j * 1j", "1 + 1j", "1e5j", "1_0j", "0x1j", "(-8) ** 0.5", "(-8) ** (1/3)",
              "(-0.5) ** 0.5", "(-2) ** 0.5", "(-1) ** 0.5", "(-1.0) ** 0.5", "(-8.0) ** 0.5",
              "[1]", "[]", "{}", "{1}", "{1: 2}", "1[0]", "(1)[0]", "(1).real", "1 .real", "1.real",
              "1..real", "1.0.real", "(1)()", "1()", "lambda: 1", "lambda x: x", "(lambda: 1)()",
              "(x := 1)", "x := 1", "1 if True else 2", "[1, 2][0]", "len([1])", "sum([1, 2])",
              "sum(1, 2)", "any(1)", "chr(65)", "ord('a')", "str(1)", "repr(1)", "bool(1)", "bool(0)",
              "divmod(7, 2)", "hex(1)", "bin(1)", "oct(1)", "bytes(1)", "complex(1, 2)", "type(1)",
              "dir()", "globals()", "locals()", "vars()", "__import__('os')", "__builtins__",
              "eval('1')",
              "1 in 2", "1 in (1,)", "1 is 1", "1 is not 1", "1 not in (2,)", "not in", "in 1", "is 1",
              "1 if 1 else 2 in 3", "yield 1", "await 1", "*1", "**1", "1 if", "else 1", "pass",
              "import os", "del 1", "return 1", "assert 1", "1;", ";1",
              "0x1f", "0X1F", "0xFF", "0xff_ff", "0b101", "0B101", "0b1_01", "0o17", "0O17", "0o1_7",
              "0x", "0xg", "0b", "0b2", "0o", "0o8", "0x_", "0x1_", "0x1__2", "0b_1", "0b1_", "0b11 + 1",
              "0xFFFFFFFFFFFFFFFF", "0x7FFFFFFFFFFFFFFF", "0x8000000000000000", "0b" + "1" * 63,
              "0b" + "1" * 64, "00", "000", "0_0", "0_00", "00_0", "01", "007", "0_1", "00.1", "01.5",
              "0e0", "0e1", "00e1", "01e1", "0.e1", "0_0.5", "0_1.5", "0.0_1", "1_000", "1_0_0",
              "1__0", "1_", "_1", "1_000.5", "1_000.5_5", "1_000e1_0", "1e1_0", "1e_1", "1_e1", "1._5",
              "1_.5", "1.5_", "1.5e", "1.5e+", "1.5e-", "1.5e+1", "1.5e-1", "1.5E+1", "1.e1", "1.E1",
              ".5", ".5e1", ".5e-1", ".e1", ".", "..5", "5.", "5.e1", "5..", "5.5.5", "1e1.5", "1e1e1",
              "1e400", "1e-400", "-1e-400", "1E400", "123456789012345678901234567890.0",
              "0.000000000000000000000000000001", "9223372036854775807", "9223372036854775808",
              "-9223372036854775807", "9223372036854775806 + 1", "9223372036854775807 + 1",
              "99999999999999999999", "99999999999999999999 - 99999999999999999998",
              "1if 1else 2", "1if 0else 2", "1 if 1else 2", "1if 1 else 2", "1or 2", "1and 2",
              "1 or2", "1in (1,)", "1is 1", "1not 1", "1not in (1,)", "1for", "1x", "1_x", "1e", "1ex",
              "1else", "1ifx", "1andx", "1orx", "1inx", "1isx", "1notx", "0x1for 2", "0b1or 2",
              "0o7and 1", "0b1if 1 else 2", "0b1else", "1.if 1 else 2", "1.else", "1.e", "1.ex",
              "1.5if 1 else 2", "1.5else", "1e1if 1 else 2", "1e1else", "1j if 1 else 2",
              "1  2", "1 2", "1\t2", "1\n2", "True False", "1 True", "1(2)", "(1)(2)", "(1)2", "1 (2)",
              "- (1)", "-(-1)", "+(+1)", "~(~1)", "-(1 + 2)", "-(1.5)", "--1", "---1", "-+-1", "~~~1",
              "- - - 1", "not not not 1", "- not 1", "not - 1", "~ not 1", "not ~ 1",
              "(" * 99 + "1" + ")" * 99, "-" * 50 + "1", "~" * 50 + "1", "1" + " + 1" * 50,
              "1" + " * 1" * 50, "2 ** 2 ** 2 ** 2", "not " * 50 + "1", "1 if " * 20 + "1 else 2 " + "else 3 " * 0,
              "max(" * 20 + "1, 2" + ")" * 20 if False else "max(1, max(2, max(3, 4)))",
              "min(max(1, 2), max(3, 4))", "abs(min(-3, -5))", "int(max(2.5, 1.5))", "round(abs(-2.5))",
              "float(int(2.9)) + 0.5", "int(float('1'))", "pow(2, 10)", "pow(2.0, 10)", "pow(2, 0.5)",
              "pow(-2, 3)", "pow(-8, 0.5)", "pow(0, 0)", "pow(True, 2)", "pow(2, True)", "abs(True)",
              "abs(-0.0)", "abs(-1e400)", "abs(1e400-1e400)", "abs(-9223372036854775807)",
              "int(-0.5)", "int(0.5)", "int(1e18)", "int(9.2e18)", "int(9.3e18)", "int(-9.2e18)",
              "int(-9.3e18)", "float(1)", "float(-1)", "float(0)", "float(1e400)", "float(2**53 + 1)",
              "float(9007199254740993)", "float(-9007199254740993)", "float(9223372036854775807)",
              "float(4611686018427387903)", "float(1) / 3", "int(1) / 3",
              ]:
        add(e)
    # unit-style expressions that also work as plain factor expressions
    for e in ["1 * 3600", "1*3600+30*60", "1 * 2629800.0", "2*.5*31557600.0", "1*86400+12*3600",
              "1*31557600.0-6*2629800.0", "2 * 0.5 * 31557600.0"]:
        add(e)
    seen, uniq = set(), []
    for s in out:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq


# Python accepts these, this crate rejects them by design (documented).
EXPR_UNSUPPORTED = {
    "pow(2, 3, 5)", "round(7, None)", "math.sin(1)", "math.hypot(3, 4)", "random.random()",
    "(1).real", "1 .real", "1..real", "1.0.real", "(lambda: 1)()", "(x := 1)", "[1, 2][0]",
    "len([1])", "sum([1, 2])", "ord('a')", "bool(1)", "bool(0)", "eval('1')", "1 in (1,)",
    "1 is 1", "1 is not 1", "1 not in (2,)", "1 if 1 else 2 in 3", "1in (1,)", "1is 1",
    "1not in (1,)", "int(float('1'))",
}


def gen_expr():
    cases = []
    for e in expr_inputs():
        k, r = factor_outcome(e)
        if k in ("i", "f") and Tracker(eval_text(e)).big():
            k, r = "B", ""
        if e in EXPR_UNSUPPORTED:
            assert k in ("i", "f"), e
            k, r = "U", ""
        cases.append([e, k, r])
    return {"cases": cases}


FACTORS = ["1", "2", "1.33", "2.0 / 2.885385", "0.5", "1.5", "-1", "0", "1/3", "True",
           "min(2, 3)", "math.sqrt(4)", "(1+1)", "abs(-2.5)", "1e400", "foo", "1/0",
           "2 ** 0.5", "round(2.6)", "float(3)", "3 // 2", "1e-3", "0x2", "1_0", " 2",
           "2 ", "\t3", "'a'", "2,", "", "ban.Time", "banFactor", "int(2.9)",
           "2 if 1 else 3", "not 1", "1 < 2", "~1", "1 << 3", "1.0", "100", "1e2"]

FORMULAS = [
    None,
    "ban.Time * (1<<(ban.Count if ban.Count<20 else 20)) * banFactor",
    "ban.Time * math.exp(float(ban.Count+1)*banFactor)/math.exp(1*banFactor)",
    "ban.Time * (ban.Count + 1) * banFactor",
    "ban.Time * 2 ** ban.Count",
    "ban.Time * banFactor ** ban.Count",
    "ban.Time + ban.Count * 60",
    "ban.Time * (1 << min(ban.Count, 10))",
    "max(ban.Time, 100) * ban.Count",
    "ban.Time * 1.5 ** ban.Count",
    "int(ban.Time * 1.5 ** ban.Count)",
    "round(ban.Time * 1.5 ** ban.Count, 2)",
    "round(ban.Time * 1.5 ** ban.Count)",
    "ban.Time * ban.Count // 2",
    "ban.Time / (ban.Count - 5)",
    "ban.Time * (ban.Count % 3 + 1)",
    "ban.Time if ban.Count < 5 else ban.Time * 10",
    "ban.Time * (2 if ban.Count > 3 and ban.Count < 10 else 1)",
    "abs(ban.Count - 10) * ban.Time",
    "ban.Time * 1<<ban.Count",
    "ban.Time << ban.Count",
    "ban.Time * math.log(ban.Count + 1, 2)",
    "ban.Time * math.log2(ban.Count)",
    "ban.Time * math.sqrt(ban.Count)",
    "math.floor(ban.Time * 1.5) + math.ceil(ban.Count / 3)",
    "ban.Time * pow(2, ban.Count)",
    "ban.Time * -ban.Count",
    "~ban.Count",
    "ban.Time * (ban.Count > 3)",
    "ban.Count > 3",
    "ban.Time * banFactor",
    "banFactor",
    "ban.Count ** 0.5",
    "ban.Time * 2 ** -ban.Count",
    "ban.Time // 7",
    "ban.Time % 7 + ban.Time",
    "1/ban.Count",
    "ban.Time * (ban.Count & 3) | 1",
    "ban.Time * (ban.Count ^ 5)",
    "(ban.Time + ban.Count) >> 1",
    "ban.Time * 3 if ban.Count else ban.Time * 5",
    "ban.Time * (ban.Count or 1)",
    "(ban.Count and ban.Time) or 7",
    "not ban.Count",
    "ban.Time * math.pi",
    "ban.Time * math.e ** ban.Count",
    "min(ban.Time * 4, 5000)",
    "max(ban.Time, ban.Count * 1000)",
    "float(ban.Time) * ban.Count",
    "ban.Time ** 2",
    "ban.Time * 10 ** ban.Count",
    "10 ** ban.Count",
    "2 ** ban.Count",
    "ban.Time * (1<<ban.Count)",
    "ban.Time * 1.0",
    "ban.Time + 0.5",
    "ban.Time ** 0.5",
    "(-ban.Time) ** 0.5",
    "ban.Time * (ban.Count - 1)",
    "ban.Time*ban.Count",
    "ban.Time*(ban.Count+1)**2",
    "# comment\nban.Time * 2",
    "ban.Time * 2 # comment",
    "ban.Time * \\\n 2",
    "(ban.Time *\n 2)",
    "ban.Time * 2\n",
    " ban.Time * 2",
    "\tban.Time * 2",
    "ban.Time *",
    "ban.Time * (",
    "ban.Time * )",
    "ban.Time ban.Count",
    "ban.Time(1)",
    "ban.time",
    "ban.Time.real",
    "ban",
    "ban.Count.real",
    "foo * ban.Time",
    "foo(1)",
    "unknown",
    "ban.Time * math.foo(2)",
    "ban.Time * random.random()",
    "ban.Time * 'a'",
    "lambda: 1",
    "[ban.Time]",
    "1 if ban.Count else foo",
    "foo if ban.Count else 1",
    "ban.Time if ban.Count > 100 else 5",
    "ban.Time if ban.Count > 100 else foo",
    "",
    "1",
    "0",
    "-1",
    "True",
    "1e400",
    "-1e400",
    "ban.Time * 1e400",
    "ban.Time * (1e400 - 1e400)",
    "ban.Time * 0.1 * 3",
    "ban.Time * (2 ** ban.Count + 1) / 3",
    "ban.Time * 9223372036854775807",
    "ban.Time + 9223372036854775807",
    "abs(ban.Time - 1000)",
    "round(ban.Time / 7)",
    "round(ban.Time / 7, 1)",
    "round(ban.Time / 7, -1)",
    "round(ban.Time, -2)",
    "int(ban.Time / 7)",
    "ban.Time ** -1",
    "ban.Time % ban.Count",
    "ban.Time // ban.Count",
    "ban.Time << (ban.Count * 3)",
    "ban.Time >> ban.Count",
    "ban.Time & ban.Count",
    "ban.Time | ban.Count",
    "ban.Time ^ ban.Count",
]

MULTIPLIERS = [
    None, "1 2 4 8 16 32 64", "1 5 30 60 300 720 1440 2880", "1", "2", "0", "-1 2", "1_0 2",
    "+3 4", " ".join(str(1 << i) for i in range(31)), "1 2 4 8 16 32 64 128 256",
    "3  4", "1 x", " 1 2", "1 2 ", "1\t2", "1\n2", "1.5 2", "1e2", "0x10", "1 -2 3", "007 08",
    "1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32",
    "9223372036854775807 2", "9223372036854775808 2", "1__0", "_1", "1_", "- 1", "+", "-",
    "\u0661 2", "\xa01 2", "1 \xa0",
]

MAXTIMES = [None, "1d", "30d", "12h", "24h", "-1", "0", "1.5h", "1y", "foo", "1h 30m", "1000 days",
            "600", "86400", "1month", "5", "1e400", "30d "]
RNDTIMES = [None, "5m", "0", "30min", "1.5", "1y", "foo", "100"]

TIMES = [("i", 600), ("i", 0), ("f", 1.5), ("i", 86400), ("f", 600.0), ("i", -1), ("i", 3600),
         ("f", 2629800.0), ("i", 10**9)]
COUNTS = list(range(0, 31)) + [-3, -2, -1, 31, 40, 63, 64, 100]
RANDS = [0.0, 0.25, 0.9999]
PROFILES = {
    "full": (TIMES, COUNTS),
    "mid": ([("i", 600), ("f", 1.5), ("i", 0)], [0, 1, 2, 3, 5, 10, 19, 20, 21, 30, -1, 100]),
    "small": ([("i", 600)], [0, 1, 5, 20, -1]),
}


def build_jail(opts):
    j = Jail("oracle")
    # as the server does for every jail: builds the default evformula
    j.setBanTimeExtra("increment", "true")
    for k in ("maxtime", "rndtime", "factor", "formula", "multipliers"):
        v = opts.get(k)
        if v is not None:
            j.setBanTimeExtra(k, v)
    return j


# Python accepts these formulas, this crate rejects them by design (documented):
# `random`/attribute access, and unknown names in branches that are never taken
# (rejected at construction here, only on use by Python).
UNSUPPORTED_FORMULAS = {
    "ban.Time * random.random()", "ban.Time.real", "ban.Count.real",
    "1 if ban.Count else foo", "foo if ban.Count else 1", "ban.Time if ban.Count > 100 else foo",
}


def out_of_i64(v):
    return type(v) is int and not (I64_MIN <= v <= I64_MAX)


def setup_needs_bignum(opts):
    """Python configured fine, but one option needs an int beyond i64."""
    if Tracker(eval_text(opts.get("factor") or "1")).big():
        return True
    for k in ("maxtime", "rndtime"):
        if opts.get(k) and Tracker(eval_text(rewrite(opts[k]))).big():
            return True
    for part in (opts.get("multipliers") or "").split(" "):
        try:
            if out_of_i64(int(part)):
                return True
        except ValueError:
            pass
    return False


def calc_results(opts, times, counts, rands):
    try:
        j = build_jail(opts)
    except BaseException as e:  # noqa: BLE001
        if isinstance(e, KeyboardInterrupt):
            raise
        return "error", []
    import random as _random
    f = j.getBanTimeExtra()["evformula"]
    setup = "big" if setup_needs_bignum(opts) else "ok"
    if any(ch.isdecimal() and ord(ch) > 127 for ch in opts.get("multipliers") or ""):
        setup = "unsupported"  # int() accepts non-ASCII decimal digits; this crate does not
    factor = eval(opts.get("factor") or "1", {"math": math})
    multipliers = [int(x) for x in opts["multipliers"].split(" ")] if opts.get("multipliers") else []
    formula = opts.get("formula") or "ban.Time * (1<<(ban.Count if ban.Count<20 else 20)) * banFactor"
    tracker = None if multipliers else Tracker(formula)
    unsupported = not multipliers and formula in UNSUPPORTED_FORMULAS
    use_rands = rands if opts.get("rndtime") not in (None, "") else rands[:1]
    res = []
    orig = _random.random
    try:
        for rv in use_rands:
            _random.random = lambda rv=rv: rv
            for tt, tv in times:
                for c in counts:
                    k, r = outcome(lambda: f(ObserverThread.BanTimeIncr(tv, c)))
                    if k in ("i", "f", "b"):
                        if multipliers:
                            m = multipliers[c if c < len(multipliers) else -1]
                            x = tv * factor
                            big = out_of_i64(x) or out_of_i64(x * m)
                        else:
                            big = tracker.big(ban=ObserverThread.BanTimeIncr(tv, c), banFactor=factor)
                        if big:
                            k, r = "B", ""
                        elif unsupported:
                            k, r = "U", ""
                    res.append(k if k in ("E", "B", "U") else f"{k}:{r}")
    finally:
        _random.random = orig
    return setup, res


def option_sets():
    sets = []

    def o(profile, **kw):
        d = {k: kw.get(k) for k in ("factor", "formula", "multipliers", "maxtime", "rndtime")}
        sets.append((d, profile))

    # key sets, full grid
    for fa in (None, "2", "1.33", "2.0 / 2.885385"):
        for mt in (None, "1d", "30d", "12h"):
            for rt in (None, "5m"):
                o("full", factor=fa, maxtime=mt, rndtime=rt)
    for m in ("1 2 4 8 16 32 64", "1 5 30 60 300 720 1440 2880",
              " ".join(str(1 << i) for i in range(31))):
        for fa in (None, "2", "1.33"):
            for mt in (None, "1d", "30d"):
                o("full", multipliers=m, factor=fa, maxtime=mt)
    o("full", formula="ban.Time * math.exp(float(ban.Count+1)*banFactor)/math.exp(1*banFactor)",
      factor="2.0 / 2.885385", maxtime="24h")
    # formula sweep
    for fo in FORMULAS:
        for fa in (None, "2", "1.33", "2.0 / 2.885385", "-1"):
            for mt in (None, "1d"):
                o("mid", formula=fo, factor=fa, maxtime=mt)
    # factor sweep (formula path and multiplier path)
    for fa in FACTORS:
        o("small", factor=fa)
        o("small", factor=fa, multipliers="1 2 4 8")
        o("small", factor=fa, maxtime="1d", rndtime="5m")
    # multipliers sweep
    for m in MULTIPLIERS:
        for fa in (None, "2", "1.33"):
            for mt in (None, "1d", "30d"):
                o("mid", multipliers=m, factor=fa, maxtime=mt)
            o("mid", multipliers=m, factor=fa, maxtime="24h", rndtime="5m")
    # maxtime / rndtime sweep on default formula and multipliers
    for mt in MAXTIMES:
        for rt in RNDTIMES:
            o("mid", maxtime=mt, rndtime=rt)
            o("mid", maxtime=mt, rndtime=rt, multipliers="1 5 30 60 300 720 1440 2880", factor="2")
    # multipliers win over formula
    o("mid", formula="ban.Time * 7", multipliers="1 2 3")
    o("mid", formula="foo", multipliers="1 2 3")
    # empty strings mean "not set"
    o("mid", factor="", formula="", multipliers="", maxtime="", rndtime="")
    seen, uniq = set(), []
    for d, prof in sets:
        key = json.dumps([d, prof], sort_keys=True)
        if key not in seen:
            seen.add(key)
            uniq.append((d, prof))
    return uniq


def gen_bantime():
    out = []
    for opts, prof in option_sets():
        times, counts = PROFILES[prof]
        setup, res = calc_results(opts, times, counts, RANDS)
        out.append({
            "opts": opts, "setup": setup, "times": [[t, repr(v)] for t, v in times],
            "counts": counts, "rands": RANDS, "results": res,
        })
    return {"sets": out}


# --------------------------------------------------------------------- floats


def gen_floats():
    rng = random.Random(4242)
    vals = [0.0, -0.0, 1.0, -1.0, 0.1, 0.5, 1.5, 100.0, 1e15, 1e16, 1e17, 1.5e16, 123456789012345680.0,
            0.0001, 0.00001, 0.000123, 1.5e-5, 5e-324, 2.2250738585072014e-308,
            1.7976931348623157e308, 1e22, 1e23, 9.999999999999999e22, 2629800.0, 31557600.0,
            1e300, 1e-300, 4.35, 0.30000000000000004, 123456.789, 1e100, 1e-7, 3.14159, 2.5e-5,
            9007199254740992.0, 9007199254740993.0, 12345678901234567.0, 0.1 + 0.2, 1 / 3, 2 / 3]
    for _ in range(3000):
        bits = rng.getrandbits(64)
        v = struct.unpack("<d", struct.pack("<Q", bits))[0]
        if v == v and abs(v) != float("inf"):
            vals.append(v)
    for _ in range(2000):
        vals.append(round(rng.random() * 10 ** rng.randint(-8, 22), rng.randint(0, 12)))
        vals.append(rng.randint(1, 10**rng.randint(1, 22)) * 1.0)
    seen, out = set(), []
    for v in vals:
        r = repr(v)
        if r not in seen:
            seen.add(r)
            out.append(r)
    out.append("inf")
    out.append("-inf")
    out.append("nan")
    return {"reprs": out}


def dump(obj, path):
    with open(path, "w", encoding="ascii", newline="\n") as f:
        json.dump(obj, f, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
        f.write("\n")


def main():
    import signal
    signal.alarm(1800)  # fail instead of hanging on a pathological upstream eval
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(ROOT, "testdata", "f2b-expr"))
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    dump(gen_str2seconds(), os.path.join(args.out, "str2seconds.json"))
    dump(gen_seconds2str(), os.path.join(args.out, "seconds2str.json"))
    dump(gen_expr(), os.path.join(args.out, "expr.json"))
    dump(gen_bantime(), os.path.join(args.out, "bantime.json"))
    dump(gen_floats(), os.path.join(args.out, "floats.json"))


if __name__ == "__main__":
    main()
