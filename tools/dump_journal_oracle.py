#!/usr/bin/env python3
"""Generate golden fixtures for crates/f2b-backend (systemd journal backend) from upstream Fail2Ban.

python-systemd (libsystemd bindings) cannot be built in every environment, so this script
stubs a fake `systemd` package in `sys.modules` and then drives the REAL upstream
`fail2ban.server.filtersystemd.FilterSystemd`:

  * `systemd.journal` carries the real python-systemd 235 constants, `DEFAULT_CONVERTERS`
    and `Reader._convert_field/_convert_entry` (copied verbatim, pure Python), and a fake
    `Reader` that validates `add_match` exactly like libsystemd's `sd_journal_add_match`
    (`match_is_valid`: len >= 2, no leading `__`, field chars in [A-Z0-9_], `=` present,
    non-empty field -> ValueError("Invalid match")), models `add_disjunction` /
    `flush_matches`, and applies the `Reader.__init__` flag defaults.
  * `FilterSystemd.addJournalMatch/delJournalMatch/getJournalMatch/formatJournalEntry/
    _getJournalArgs/_globJournalFiles` are the upstream implementations, unmodified.

What is NOT covered (needs the C extension): `_get_all`, seeking, waiting, real libsystemd.

Two timestamp styles are recorded, because python-systemd changed between releases:
  naive  (<= 234)  datetime.fromtimestamp(t) in the process zone (TZ); isoformat has no offset.
  fixed  (  235 )  datetime.fromtimestamp(t, _LOCAL_TIMEZONE) with _LOCAL_TIMEZONE the FIXED
                   UTC offset of the moment python-systemd was imported; isoformat ends in
                   `+HH:MM`. (The offset is pinned per case; it is not read from the clock.)

Output (sorted keys, ASCII JSON, deterministic) in crates/f2b-backend/tests/fixtures/:
  journal_matches.json   [{id, ops: [[op, arg]], results: [{ok|err, state, reader}]}]
  journal_entries.json   {styles, encs, entries: [{id, export_hex, typed}], formats: [[entry, style, enc, result]]}
  journal_args.json      [{id, files, kwargs, env_default_flags, ok: {...} | err}]

Usage: tools/dump_journal_oracle.py [--upstream DIR] [--out DIR]
"""
import argparse
import datetime as dt
import json
import logging
import os
import random
import shutil
import struct
import sys
import tempfile
import time
import types
import uuid as uuidmod
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# fake `systemd.journal`
# ---------------------------------------------------------------------------
NOP, APPEND, INVALIDATE = 0, 1, 2
LOCAL_ONLY, RUNTIME_ONLY, SYSTEM_ONLY, CURRENT_USER, OS_ROOT = 1, 2, 4, 8, 16

_IDENT = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789")


def sd_match_is_valid(match):
    """libsystemd sd-journal.c match_is_valid(); `match` is a str (python passes "s#")."""
    if len(match) < 2:
        return False
    if match[0] == "_" and match[1] == "_":
        return False
    for ch in match:
        if ch == "=":
            return match[0] != "="
        if ch in _IDENT:
            continue
        return False
    return False


class _State(object):
    """Mutable globals of the fake module (python-systemd's `_LOCAL_TIMEZONE`)."""
    local_timezone = None


Monotonic = __import__("collections").namedtuple("Monotonic", ["timestamp", "bootid"])


# --- verbatim from systemd-python 235 systemd/journal.py ---------------------------------
def _convert_monotonic(m):
    # python-systemd returns a struct sequence `Monotonic((timedelta, UUID))`; a namedtuple is
    # indexable the same way, which is all fail2ban uses (`[0]`)
    return Monotonic(dt.timedelta(microseconds=m[0]), uuidmod.UUID(bytes=m[1]))


def _convert_source_monotonic(s):
    return dt.timedelta(microseconds=int(s))


def _convert_realtime(t):
    return dt.datetime.fromtimestamp(t / 1000000, _State.local_timezone)


def _convert_timestamp(s):
    return dt.datetime.fromtimestamp(int(s) / 1000000, _State.local_timezone)


def _convert_trivial(x):
    return x


def _convert_uuid(s):
    return uuidmod.UUID(s.decode())


DEFAULT_CONVERTERS = {
    'MESSAGE_ID': _convert_uuid,
    '_MACHINE_ID': _convert_uuid,
    '_BOOT_ID': _convert_uuid,
    'PRIORITY': int,
    'LEADER': int,
    'SESSION_ID': int,
    'USERSPACE_USEC': int,
    'INITRD_USEC': int,
    'KERNEL_USEC': int,
    '_UID': int,
    '_GID': int,
    '_PID': int,
    'SYSLOG_FACILITY': int,
    'SYSLOG_PID': int,
    '_AUDIT_SESSION': int,
    '_AUDIT_LOGINUID': int,
    '_SYSTEMD_SESSION': int,
    '_SYSTEMD_OWNER_UID': int,
    'CODE_LINE': int,
    'ERRNO': int,
    'EXIT_STATUS': int,
    '_SOURCE_REALTIME_TIMESTAMP': _convert_timestamp,
    '__REALTIME_TIMESTAMP': _convert_realtime,
    '_SOURCE_MONOTONIC_TIMESTAMP': _convert_source_monotonic,
    '__MONOTONIC_TIMESTAMP': _convert_monotonic,
    '__CURSOR': _convert_trivial,
    'COREDUMP': bytes,
    'COREDUMP_PID': int,
    'COREDUMP_UID': int,
    'COREDUMP_GID': int,
    'COREDUMP_SESSION': int,
    'COREDUMP_SIGNAL': int,
    'COREDUMP_TIMESTAMP': _convert_timestamp,
}


class Reader(object):
    """Fake journal.Reader: python-systemd's conversion logic + a libsystemd match model."""

    instances = []

    def __init__(self, flags=None, path=None, files=None, converters=None, namespace=None):
        if flags is None:
            if path is None and files is None:
                flags = LOCAL_ONLY
            else:
                flags = 0
        # _reader.c Reader_init
        if bool(path is not None) + bool(files is not None) > 1:
            raise ValueError("path and files cannot be specified simultaneously")
        self.open_args = dict(flags=flags, path=path, files=files, namespace=namespace)
        self.converters = DEFAULT_CONVERTERS.copy()
        if converters is not None:
            self.converters.update(converters)
        self.closed = False
        self.calls = []
        self._groups = [[]]
        Reader.instances.append(self)

    # libsystemd match model
    def add_match(self, *args):
        for arg in args:
            if not sd_match_is_valid(arg):
                raise ValueError("Invalid match")
            self.calls.append(("add_match", arg))
            self._groups[-1].append(arg)

    def add_disjunction(self):
        self.calls.append(("add_disjunction",))
        if self._groups[-1]:
            self._groups.append([])

    def flush_matches(self):
        self.calls.append(("flush_matches",))
        self._groups = [[]]

    def expression(self):
        """Effective OR-of-groups of the journal (empty groups dropped), as list of lists."""
        return [list(g) for g in self._groups if g]

    def close(self):
        self.closed = True

    def _get_cursor(self):
        return "c"

    # python-systemd Reader._convert_field/_convert_entry (verbatim)
    def _convert_field(self, key, value):
        convert = self.converters.get(key, bytes.decode)
        try:
            return convert(value)
        except ValueError:
            return value

    def _convert_entry(self, entry):
        result = {}
        for key, value in entry.items():
            if isinstance(value, list):
                result[key] = [self._convert_field(key, val) for val in value]
            else:
                result[key] = self._convert_field(key, value)
        return result


def install_fake_systemd(upstream):
    pkg = types.ModuleType("systemd")
    jr = types.ModuleType("systemd.journal")
    jr.NOP, jr.APPEND, jr.INVALIDATE = NOP, APPEND, INVALIDATE
    jr.LOCAL_ONLY, jr.RUNTIME_ONLY = LOCAL_ONLY, RUNTIME_ONLY
    jr.SYSTEM, jr.SYSTEM_ONLY, jr.CURRENT_USER, jr.OS_ROOT = SYSTEM_ONLY, SYSTEM_ONLY, CURRENT_USER, OS_ROOT
    jr.Reader = Reader
    jr.DEFAULT_CONVERTERS = DEFAULT_CONVERTERS
    pkg.journal = jr
    sys.modules["systemd"] = pkg
    sys.modules["systemd.journal"] = jr
    sys.path.insert(0, str(upstream))


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
class DummyJail(object):
    name = "oracle"
    database = None


def make_filter(upstream):
    from fail2ban.server.filtersystemd import FilterSystemd
    f = FilterSystemd(DummyJail())
    return f


def jdump(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, sort_keys=True, ensure_ascii=True, indent=None,
                               separators=(",", ":")) + "\n")


def f64_bits(x):
    return struct.unpack("<Q", struct.pack("<d", x))[0]


def exc_name(e):
    return type(e).__name__


# ---------------------------------------------------------------------------
# journalmatch scenarios
# ---------------------------------------------------------------------------
VALID_MATCHES = [
    "_SYSTEMD_UNIT=sshd.service", "_COMM=sshd", "SYSLOG_IDENTIFIER=sshd", "PRIORITY=3",
    "_SYSTEMD_UNIT=ssh.service", "A=", "AB=x", "FIELD_1=a b=c", "_X=1", "X9=y", "MESSAGE=héllo",
    "_TRANSPORT=kernel", "SYSLOG_IDENTIFIER=with space", "Z_=", "0A=1", "A0=\n",
]
INVALID_MATCHES = [
    "", "A", "=", "=x", "a=b", "__CURSOR=x", "__X=", "_a=b", "A B=c", "A-B=c", "AB", "É=1",
    "ABC", "x", "_=", "_", "__", "A:B=1", "a", "1", "A\x00B=1", " A=1", "A =1",
]
EXTRA_SCENARIOS = [
    [["add", ["_SYSTEMD_UNIT=sshd.service", "+", "_COMM=sshd"]],
     ["get", None], ["del", ["_COMM=sshd"]], ["get", None], ["del", None], ["get", None]],
    [["add", ["+"]], ["get", None], ["add", ["+", "+", "A=b"]], ["get", None], ["del", []], ["get", None],
     ["del", []], ["get", None], ["del", None], ["del", None], ["get", None]],
    [["add", []], ["get", None], ["add", []], ["get", None], ["del", None]],
    [["add", ["A=b", "C=d"]], ["add", ["A=b", "+", "X=y"]], ["del", ["A=b"]], ["get", None],
     ["del", ["A=b", "C=d"]], ["del", ["A=b", "C=d"]], ["get", None]],
    [["add", ["A=b", "C"]], ["get", None], ["add", ["A=b"]], ["add", ["+", "bad"]], ["get", None],
     ["del", ["+"]], ["del", ["A=b", "+", "C=d"]], ["del", ["nope"]], ["get", None]],
    [["add", ["_SYSTEMD_UNIT=a b.service"]], ["del", ["_SYSTEMD_UNIT=a b.service"]],
     ["del", ["it's=1"]], ["add", ["A=it's"]], ["del", ["A=it's"]], ["del", ["A=\"q\"", "B=\\"]],
     ["del", ["A=é\n\t"]], ["del", ["A=\u2603\U0001f600"]]],
]


def gen_match_scenarios(seed=20240607):
    rnd = random.Random(seed)
    scenarios = []
    # one-off: every valid and invalid match on its own
    for m in VALID_MATCHES + INVALID_MATCHES:
        scenarios.append([["add", [m]], ["get", None], ["del", [m]], ["get", None]])
    scenarios.extend(EXTRA_SCENARIOS)
    pool = VALID_MATCHES[:8] + ["+", "+"] + INVALID_MATCHES[:6]
    for _ in range(120):
        ops = []
        for _ in range(rnd.randint(2, 9)):
            kind = rnd.choice(["add", "add", "add", "del", "del", "delnone", "get"])
            if kind == "add":
                ops.append(["add", [rnd.choice(pool) for _ in range(rnd.randint(0, 4))]])
            elif kind == "del":
                ops.append(["del", [rnd.choice(pool) for _ in range(rnd.randint(0, 3))]])
            elif kind == "delnone":
                ops.append(["del", None])
            else:
                ops.append(["get", None])
        scenarios.append(ops)
    return scenarios


def run_match_scenario(upstream, ops):
    Reader.instances.clear()
    f = make_filter(upstream)
    rd = f.getJournalReader()
    results = []
    for op, arg in ops:
        rec = {}
        try:
            if op == "add":
                f.addJournalMatch(list(arg))
            elif op == "del":
                f.delJournalMatch(None if arg is None else list(arg))
            else:
                pass
            rec["ok"] = True
        except ValueError as e:
            rec["err"] = str(e)
        rec["state"] = json.loads(json.dumps(f.getJournalMatch()))
        rec["reader"] = rd.expression()
        results.append(rec)
    return results


# ---------------------------------------------------------------------------
# entry scenarios
# ---------------------------------------------------------------------------
BOOT = uuidmod.UUID("0123456789abcdef0123456789abcdef")
MACHINE = uuidmod.UUID("fedcba9876543210fedcba9876543210")


def export_field(name, value, force_binary=False):
    """journalctl -o export encoding of one field (value: bytes)."""
    textual = (not force_binary and b"\n" not in value and b"\x00" not in value
               and all(c >= 0x20 or c == 9 for c in value))
    try:
        value.decode("utf-8")
    except UnicodeDecodeError:
        textual = False
    if textual:
        return name.encode() + b"=" + value + b"\n"
    return name.encode() + b"\n" + struct.pack("<Q", len(value)) + value + b"\n"


class Entry(object):
    def __init__(self, id, fields, rt, mono=123456789, cursor="s=abc;i=1;b=1;m=1;t=1;x=1",
                 boot=BOOT, binary=(), meta_binary=False):
        self.id = id
        self.fields = [(k, v if isinstance(v, bytes) else v.encode("utf-8")) for k, v in fields]
        self.rt = rt
        self.mono = mono
        self.cursor = cursor
        self.boot = boot
        self.binary = set(binary)

    def export(self):
        out = b"__CURSOR=" + self.cursor.encode() + b"\n"
        out += b"__REALTIME_TIMESTAMP=%d\n" % self.rt
        out += b"__MONOTONIC_TIMESTAMP=%d\n" % self.mono
        out += export_field("_BOOT_ID", self.boot.hex.encode())
        for i, (k, v) in enumerate(self.fields):
            out += export_field(k, v, force_binary=(i in self.binary))
        return out + b"\n"

    def raw(self):
        """What python-systemd's C `_get_all` + get_next() would hand to _convert_entry()."""
        entry = {}
        allfields = [("_BOOT_ID", self.boot.hex.encode())] + self.fields
        for k, v in allfields:
            if k in entry:
                if isinstance(entry[k], list):
                    entry[k].append(v)
                else:
                    entry[k] = [entry[k], v]
            else:
                entry[k] = v
        entry["__REALTIME_TIMESTAMP"] = self.rt
        entry["__MONOTONIC_TIMESTAMP"] = (self.mono, self.boot.bytes)
        entry["__CURSOR"] = self.cursor
        return entry


def us(y, mo, d, h, mi, s, micro=0, tzoff=0):
    t = dt.datetime(y, mo, d, h, mi, s, tzinfo=dt.timezone.utc)
    return int(t.timestamp()) * 1000000 + micro - tzoff * 1000000


T0 = us(2024, 5, 17, 10, 30, 45, 123456)


def entry_templates(seed=7):
    rnd = random.Random(seed)
    E = []

    def add(id, fields, rt=T0, **kw):
        E.append(Entry(id, fields, rt, **kw))

    # --- identity / pid variants
    add("plain", [("_HOSTNAME", "host1"), ("SYSLOG_IDENTIFIER", "sshd"), ("SYSLOG_PID", "1234"),
                  ("MESSAGE", "Failed password for root from 1.2.3.4 port 22 ssh2")])
    add("no_host", [("SYSLOG_IDENTIFIER", "sshd"), ("_PID", "77"), ("MESSAGE", "hi")])
    add("empty_host", [("_HOSTNAME", ""), ("SYSLOG_IDENTIFIER", "sshd"), ("MESSAGE", "hi")])
    add("comm_fallback", [("_HOSTNAME", "h"), ("_COMM", "cron"), ("_PID", "9"), ("MESSAGE", "tick")])
    add("empty_ident_comm", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", ""), ("_COMM", "cron"), ("MESSAGE", "x")])
    add("no_ident", [("_HOSTNAME", "h"), ("MESSAGE", "bare message")])
    add("no_ident_no_host", [("MESSAGE", "bare message")])
    add("no_message", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "x")])
    add("empty_message", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "x"), ("MESSAGE", "")])
    add("nothing", [])
    for i, pid in enumerate([b"0", b"00", b"1", b"-5", b"+7", b" 12 ", b"1_0", b"1__0", b"_1", b"1_", b"0x1f", b"0X1F",
                             b"0o17", b"0b11", b"010", b"garbage", b"12abc", b"", b"\xd9\xa3", b"1.5",
                             b"12345678901234567890123456789", b"123456789012345678901234567890123456789012345",
                             b"0x_1f", b"00x1f", b"\t9\n", b"0x", b"- 5", b"\xff"]):
        add("pid_syslog_%d" % i, [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "app"), ("SYSLOG_PID", pid),
                                  ("_PID", "4242"), ("MESSAGE", "m")])
        add("pid_only_%d" % i, [("_HOSTNAME", "h"), ("_COMM", "app"), ("_PID", pid), ("MESSAGE", "m")])
    add("pid_repeated", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "app"), ("SYSLOG_PID", "1"),
                         ("SYSLOG_PID", "2"), ("MESSAGE", "m")])
    add("pid_repeated_mixed", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "app"), ("SYSLOG_PID", "x\xe9"),
                               ("SYSLOG_PID", b"\xff\xfe"), ("SYSLOG_PID", "7"), ("MESSAGE", "m")])
    add("pid_fallback_zero", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "app"), ("SYSLOG_PID", "0"),
                              ("_PID", "5"), ("MESSAGE", "m")])
    add("pid_quote_bytes", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "app"), ("SYSLOG_PID", b"it's \"q\" \\ \t\r\n\x00\x7f"),
                            ("MESSAGE", "m")])
    add("pid_quote_bytes2", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "app"), ("SYSLOG_PID", b"it's"),
                             ("MESSAGE", "m")])
    add("pid_quote_bytes3", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "app"), ("SYSLOG_PID", b"\"q\" it's"),
                             ("MESSAGE", "m")])
    # --- kernel
    add("kernel", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "kernel"), ("MESSAGE", "usb 1-1: new device")],
        mono=5123456)
    add("kernel_comm", [("_HOSTNAME", "h"), ("_COMM", "kernel"), ("MESSAGE", "x")], mono=987654321012)
    add("kernel_src_mono", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "kernel"), ("MESSAGE", "x"),
                            ("_SOURCE_MONOTONIC_TIMESTAMP", "42000001")], mono=5)
    add("kernel_src_mono_neg", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "kernel"), ("MESSAGE", "x"),
                                ("_SOURCE_MONOTONIC_TIMESTAMP", "-1500000")])
    add("kernel_src_mono_garbage", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "kernel"), ("MESSAGE", "x"),
                                    ("_SOURCE_MONOTONIC_TIMESTAMP", "abc")])
    add("kernel_src_mono_repeated", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "kernel"), ("MESSAGE", "x"),
                                     ("_SOURCE_MONOTONIC_TIMESTAMP", "1"), ("_SOURCE_MONOTONIC_TIMESTAMP", "2")])
    add("kernel_pid", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "kernel"), ("SYSLOG_PID", "3"), ("MESSAGE", "x")])
    add("kernel_pid_zero", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "kernel"), ("SYSLOG_PID", "0"),
                            ("MESSAGE", "x")], mono=1)
    add("kernel_big_mono", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "kernel"), ("MESSAGE", "x")],
        mono=123456789012345678)
    add("kernel_no_host", [("SYSLOG_IDENTIFIER", "kernel"), ("MESSAGE", "x")], mono=1999999)
    add("kernelx", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "kernel "), ("MESSAGE", "x")])
    add("Kernel", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "Kernel"), ("MESSAGE", "x")])
    # --- messages
    add("msg_newline", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "x"), ("MESSAGE", "line1\nline2\n\nend\n")])
    add("msg_cr_tab", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "x"), ("MESSAGE", "a\tb\r\nc")])
    add("msg_unicode", [("_HOSTNAME", "h\xfc"), ("SYSLOG_IDENTIFIER", "x\u00e9"), ("MESSAGE", "caf\u00e9 \u2603 \U0001f600")])
    add("msg_list2", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "x"), ("MESSAGE", "one"), ("MESSAGE", "two")])
    add("msg_list3_nl", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "x"), ("MESSAGE", "a\nb"), ("MESSAGE", ""),
                         ("MESSAGE", "c")])
    add("msg_list_mixed_bytes", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "x"), ("MESSAGE", "ok"),
                                 ("MESSAGE", b"caf\xe9"), ("MESSAGE", "caf\u00e9")])
    add("msg_latin1", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "x"), ("MESSAGE", b"caf\xe9 na\xefve")])
    add("msg_invalid_utf8", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "x"),
                             ("MESSAGE", b"a\xffb\xc3c\xe2\x82d\xf0\x9f\x98e\xed\xa0\x80f\xc0\xafg\xf8\x88\x80\x80\x80h")])
    add("msg_trunc_utf8", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "x"), ("MESSAGE", b"end \xe2\x82")])
    add("msg_bytes_ctrl", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "x"), ("MESSAGE", b"a\x00b\x1b[0m\xff\n")])
    add("host_bytes", [("_HOSTNAME", b"h\xe9\xff"), ("SYSLOG_IDENTIFIER", b"id\xe9"), ("MESSAGE", "m")])
    add("msg_binary_form_text", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "x"), ("MESSAGE", "plain text")],
        binary=(0, 1, 2))
    add("msg_long", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "x"), ("MESSAGE", "x" * 5000 + "\n" + "y" * 100)])
    add("msg_empty_binary", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "x"), ("MESSAGE", "")], binary=(2,))
    add("msg_eq_in_value", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "x"), ("MESSAGE", "a=b=c")])
    # --- converters (typed dump)
    add("typed_ints", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "x"), ("PRIORITY", "6"), ("_UID", "1000"),
                       ("_GID", "bad"), ("SYSLOG_FACILITY", "10"), ("CODE_LINE", " 33"), ("ERRNO", "-2"),
                       ("EXIT_STATUS", "0x1"), ("_AUDIT_SESSION", "1_000"), ("COREDUMP_SIGNAL", "11"),
                       ("MESSAGE", "m")])
    add("typed_uuids", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "x"),
                        ("MESSAGE_ID", "fc2e22bc6ee647b6b90729ab34a250b1"),
                        ("_MACHINE_ID", MACHINE.hex),
                        ("MESSAGE", "m")])
    add("typed_uuid_bad", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "x"),
                           ("MESSAGE_ID", "nothex"), ("_MACHINE_ID", "{" + str(MACHINE) + "}"),
                           ("MESSAGE", "m")])
    add("typed_uuid_odd", [("MESSAGE_ID", "urn:uuid:" + str(MACHINE)), ("_MACHINE_ID", "+" + MACHINE.hex[1:]),
                           ("COREDUMP", b"\x00\x01binary\xff"), ("COREDUMP_PID", "77"),
                           ("MESSAGE", "m")])
    add("typed_uuid_odd2", [("MESSAGE_ID", " " + MACHINE.hex[1:] + "\t"), ("_MACHINE_ID", "0x" + MACHINE.hex[2:]),
                            ("_BOOT_ID", b"\xff"), ("MESSAGE", "m")])
    add("typed_other_text", [("_TRANSPORT", "syslog"), ("_SYSTEMD_UNIT", "sshd.service"), ("CODE_FILE", "f.c"),
                             ("_CMDLINE", b"cmd\xff"), ("MESSAGE", "m")])
    add("typed_cursor_ts", [("_SOURCE_REALTIME_TIMESTAMP", "1700000000999999"),
                            ("COREDUMP_TIMESTAMP", "1700000001000000"), ("MESSAGE", "m")])
    add("typed_ts_bad", [("_SOURCE_REALTIME_TIMESTAMP", "x"), ("COREDUMP_TIMESTAMP", "9999999999999999999999"),
                         ("MESSAGE", "m")])
    add("repeated_unit", [("_SYSTEMD_UNIT", "a.service"), ("_SYSTEMD_UNIT", "b.service"), ("PRIORITY", "1"),
                          ("PRIORITY", "x"), ("MESSAGE", "m")])
    # --- source realtime (preferred) vs journal realtime
    add("src_rt", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "x"), ("MESSAGE", "m"),
                   ("_SOURCE_REALTIME_TIMESTAMP", str(T0 - 5000000))])
    add("src_rt_zero_us", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "x"), ("MESSAGE", "m"),
                           ("_SOURCE_REALTIME_TIMESTAMP", str(us(2024, 5, 17, 10, 30, 40)))])
    add("src_rt_garbage", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "x"), ("MESSAGE", "m"),
                           ("_SOURCE_REALTIME_TIMESTAMP", "not-a-number")])
    add("src_rt_repeated", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "x"), ("MESSAGE", "m"),
                            ("_SOURCE_REALTIME_TIMESTAMP", "1700000000000000"),
                            ("_SOURCE_REALTIME_TIMESTAMP", "1700000000000001")])
    add("src_rt_empty", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "x"), ("MESSAGE", "m"),
                         ("_SOURCE_REALTIME_TIMESTAMP", "")])
    add("src_rt_year_overflow", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "x"), ("MESSAGE", "m"),
                                 ("_SOURCE_REALTIME_TIMESTAMP", str(300000000000 * 1000000))])
    add("rt_year_overflow", [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "x"), ("MESSAGE", "m")],
        rt=300000000000 * 1000000)
    # --- instants: epoch, zero micro, DST edges, micro-rounding
    instants = [
        ("epoch", 0), ("epoch1", 1), ("sec0", us(2024, 1, 1, 0, 0, 0)), ("us999999", us(2024, 1, 1, 0, 0, 0, 999999)),
        ("us1", us(2024, 6, 30, 23, 59, 59, 1)), ("y2038", us(2038, 1, 19, 3, 14, 8, 1)),
        ("y2100", us(2100, 12, 31, 23, 59, 59, 999999)), ("y1999", us(1999, 12, 31, 23, 59, 59, 500000)),
        ("y1980", us(1980, 7, 1, 0, 0, 0, 7)), ("y1969", -1000000 * 3600 + 5),
        ("berlin_gap_before", us(2024, 3, 31, 0, 59, 59, 999999)), ("berlin_gap_at", us(2024, 3, 31, 1, 0, 0)),
        ("berlin_gap_after", us(2024, 3, 31, 1, 0, 0, 1)),
        ("berlin_fold_first", us(2024, 10, 27, 0, 30, 0, 250000)),
        ("berlin_fold_second", us(2024, 10, 27, 1, 30, 0, 250000)),
        ("berlin_fold_edge", us(2024, 10, 27, 1, 0, 0)), ("berlin_fold_edge_m1", us(2024, 10, 27, 0, 59, 59, 999999)),
        ("ny_gap", us(2024, 3, 10, 7, 0, 0)), ("ny_gap_m1", us(2024, 3, 10, 6, 59, 59, 999999)),
        ("ny_fold_first", us(2024, 11, 3, 5, 30, 0)), ("ny_fold_second", us(2024, 11, 3, 6, 30, 0)),
        ("ny_fold_edge", us(2024, 11, 3, 6, 0, 0)),
        ("lordhowe_fold", us(2024, 4, 6, 15, 15, 0)), ("lordhowe_fold2", us(2024, 4, 6, 15, 45, 0)),
        ("lordhowe_gap", us(2024, 10, 5, 15, 45, 0)),
    ]
    for _ in range(40):
        instants.append(("rnd%d" % len(instants), rnd.randint(0, 4102444800 * 1000000)))
    for _ in range(25):
        base = rnd.randint(1500000000, 1900000000)
        instants.append(("rndus%d" % len(instants), base * 1000000 + rnd.choice([0, 1, 499999, 500000, 500001, 999999, 5, 123457])))
    for name, rt in instants:
        add("time_" + name, [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "x"), ("MESSAGE", "t")], rt=rt)
        add("srctime_" + name, [("_HOSTNAME", "h"), ("SYSLOG_IDENTIFIER", "x"), ("MESSAGE", "t"),
                                ("_SOURCE_REALTIME_TIMESTAMP", str(rt))], rt=T0)
    return E


def convert_raw(rd, entry):
    """Reader._convert_entry on the raw dict; returns converted dict, or raises."""
    return rd._convert_entry(entry.raw())


def dump_typed(key, value, raw):
    """Typed JSON of a converted value (tz independent). `raw` = unconverted value(s) for datetimes."""
    if isinstance(value, list):
        return {"l": [dump_typed(key, v, r) for v, r in zip(value, raw)]}
    if isinstance(value, bool):
        raise AssertionError
    if isinstance(value, str):
        return {"t": value}
    if isinstance(value, bytes):
        return {"b": value.hex()}
    if isinstance(value, int):
        return {"i": str(value)}
    if isinstance(value, uuidmod.UUID):
        return {"u": value.hex}
    if isinstance(value, dt.datetime):
        return {"dt": int(raw) if not isinstance(raw, bytes) else int(raw)}
    if isinstance(value, dt.timedelta):
        return {"td": int(raw)}
    if isinstance(value, tuple) and isinstance(value[0], dt.timedelta):
        return {"mono": [int(raw[0]), value[1].hex]}
    raise AssertionError((key, value))


def dump_entry_typed(conv, raw):
    out = {}
    for k, v in conv.items():
        r = raw[k]
        out[k] = dump_typed(k, v, r)
    return out


STYLES = [
    {"kind": "naive", "tz": "UTC"},
    {"kind": "naive", "tz": "Europe/Berlin"},
    {"kind": "naive", "tz": "America/New_York"},
    {"kind": "naive", "tz": "Australia/Lord_Howe"},
    {"kind": "naive", "tz": "Asia/Kolkata"},
    {"kind": "fixed", "offset": 0},
    {"kind": "fixed", "offset": 3600},
    {"kind": "fixed", "offset": 7200},
    {"kind": "fixed", "offset": -18000},
    {"kind": "fixed", "offset": 19800},
    {"kind": "fixed", "offset": 34200},
    {"kind": "fixed", "offset": 3661},
]
ENCS = ["utf-8", "latin-1", "ascii", "UTF8", "ISO-8859-1"]


def set_style(style):
    if style["kind"] == "naive":
        os.environ["TZ"] = style["tz"]
        time.tzset()
        _State.local_timezone = None
    else:
        os.environ["TZ"] = "UTC"
        time.tzset()
        _State.local_timezone = dt.timezone(dt.timedelta(seconds=style["offset"]))


def format_case(f, rd, entry, style, enc):
    set_style(style)
    f.setLogEncoding(enc)
    conv = convert_raw(rd, entry)
    try:
        (pre, date, post), tm = f.formatJournalEntry(conv)
        assert isinstance(pre, str) and pre == ""
        return {"ok": {"pre": pre, "date": date, "post": post, "time_bits": f64_bits(tm), "time": tm}}
    except Exception as e:  # upstream would raise inside the filter loop
        return {"err": exc_name(e)}


def gen_entries(upstream):
    f = make_filter(upstream)
    rd = f.getJournalReader()
    templates = entry_templates()
    set_style(STYLES[0])
    entries, formats = [], []
    for idx, e in enumerate(templates):
        raw = e.raw()
        conv = rd._convert_entry(raw)
        entries.append({"id": e.id, "export_hex": e.export().hex(), "typed": dump_entry_typed(conv, raw)})
        has_bytes = any(not isinstance(v, str) for k, v in conv.items() if k in ("MESSAGE", "_HOSTNAME", "SYSLOG_IDENTIFIER", "_COMM"))
        has_lists = any(isinstance(v, list) for v in conv.values())
        timey = e.id.startswith(("time_", "srctime_", "src_rt", "rt_"))
        for si, style in enumerate(STYLES):
            if not timey and style["kind"] == "naive" and style["tz"] not in ("UTC", "Europe/Berlin"):
                continue
            if not timey and style["kind"] == "fixed" and style["offset"] not in (0, 3600):
                continue
            encs = [0]
            if has_bytes or has_lists or e.id.startswith(("msg_", "host_")):
                encs = range(len(ENCS))
            for ei in encs:
                formats.append([idx, si, ei, format_case(f, rd, e, style, ENCS[ei])])
    set_style(STYLES[0])
    return {"styles": STYLES, "encs": ENCS, "entries": entries, "formats": formats}


# ---------------------------------------------------------------------------
# _getJournalArgs scenarios
# ---------------------------------------------------------------------------
TREE = [
    "journal/m1/system.journal", "journal/m1/system@0001-0002.journal", "journal/m1/user-4242.journal",
    "journal/m1/user-%d.journal" % os.geteuid(), "journal/m1/user-4242@aa-bb.journal", "journal/m1/other.journal",
    "journal/m2/system.journal", "journal/m2/user-%d@x-y.journal" % os.geteuid(),
    "run/journal/m3/system.journal", "run/journal/m3/foo.journal", "run/journal/m3/foo@a.journal",
    "alt/system.journal", "alt/user-%d.journal" % os.geteuid(), "alt/remote-a.journal", "alt/x@y.journal", "alt/.hidden.journal",
    "files/a.journal", "files/b.journal", "files/c.log", "files/.d.journal", "files/sub/e.journal",
]


def args_scenarios():
    sc = []
    sc.append(dict(id="default", kwargs={}))
    sc.append(dict(id="default_rotated", kwargs={"rotated": "1"}))
    sc.append(dict(id="default_rotated_true", kwargs={"rotated": "true"}))
    sc.append(dict(id="default_rotated_no", kwargs={"rotated": "no"}))
    sc.append(dict(id="default_rotated_0", kwargs={"rotated": 0}))
    sc.append(dict(id="default_rotated_int", kwargs={"rotated": 2}))
    sc.append(dict(id="env0", kwargs={}, env="0"))
    sc.append(dict(id="env1", kwargs={}, env="1"))
    sc.append(dict(id="env4_rotated", kwargs={"rotated": "1"}, env="4"))
    sc.append(dict(id="env_bad", kwargs={}, env="x"))
    sc.append(dict(id="env_ignored_by_flags", kwargs={"journalflags": "8"}, env="4"))
    for fl in ["0", "1", "2", "4", "8", "12", "5", "16", "13", " 4 ", "+4", "abc", "", "1.5", "0x4", "4_0"]:
        sc.append(dict(id="flags_" + repr(fl), kwargs={"journalflags": fl}))
        sc.append(dict(id="flags_rot_" + repr(fl), kwargs={"journalflags": fl, "rotated": "1"}))
    for fl in [0, 4, 8, 1]:
        sc.append(dict(id="flags_int_%d" % fl, kwargs={"journalflags": fl}))
    sc.append(dict(id="path", kwargs={"journalpath": "@T@/journal/m1"}))
    sc.append(dict(id="path_glob", kwargs={"journalpath": "@T@/journal/*"}))
    sc.append(dict(id="path_alt", kwargs={"journalpath": "@T@/alt"}))
    sc.append(dict(id="path_none_matching", kwargs={"journalpath": "@T@/nothing"}))
    sc.append(dict(id="path_empty_dir", kwargs={"journalpath": "@T@/files/sub"}))
    sc.append(dict(id="path_rotated", kwargs={"journalpath": "@T@/alt", "rotated": "1"}))
    sc.append(dict(id="path_empty_str", kwargs={"journalpath": ""}))
    for fl in ["0", "1", "4", "8", "12", "16"]:
        sc.append(dict(id="path_flags_" + fl, kwargs={"journalpath": "@T@/alt", "journalflags": fl}))
        sc.append(dict(id="path_glob_flags_" + fl, kwargs={"journalpath": "@T@/journal/*", "journalflags": fl}))
    sc.append(dict(id="path_flags4_rotated", kwargs={"journalpath": "@T@/alt", "journalflags": "4", "rotated": "yes"}))
    sc.append(dict(id="files_str", kwargs={"journalfiles": "@T@/files/a.journal"}))
    sc.append(dict(id="files_two", kwargs={"journalfiles": "@T@/files/a.journal @T@/files/b.journal"}))
    sc.append(dict(id="files_comma", kwargs={"journalfiles": "@T@/files/a.journal,@T@/files/b.journal"}))
    sc.append(dict(id="files_glob", kwargs={"journalfiles": "@T@/files/*.journal"}))
    sc.append(dict(id="files_glob_hidden", kwargs={"journalfiles": "@T@/files/.*.journal"}))
    sc.append(dict(id="files_glob_q", kwargs={"journalfiles": "@T@/files/?.journal"}))
    sc.append(dict(id="files_glob_class", kwargs={"journalfiles": "@T@/files/[ab].journal"}))
    sc.append(dict(id="files_glob_dup", kwargs={"journalfiles": "@T@/files/*.journal @T@/files/a.journal"}))
    sc.append(dict(id="files_glob_deep", kwargs={"journalfiles": "@T@/*/sub/*.journal"}))
    sc.append(dict(id="files_list", kwargs={"journalfiles": ["@T@/files/a.journal", "@T@/files/c.log"]}))
    sc.append(dict(id="files_nomatch", kwargs={"journalfiles": "@T@/files/zzz*.journal"}))
    sc.append(dict(id="files_nomatch_rot", kwargs={"journalfiles": "@T@/files/zzz*.journal", "rotated": "1"}))
    sc.append(dict(id="files_nomatch_path", kwargs={"journalfiles": "@T@/files/zzz*.journal", "journalpath": "@T@/alt"}))
    sc.append(dict(id="files_nomatch_path_rot", kwargs={"journalfiles": "@T@/files/zzz*.journal", "journalpath": "@T@/alt", "rotated": "1"}))
    sc.append(dict(id="files_literal_missing", kwargs={"journalfiles": "@T@/files/missing.journal"}))
    sc.append(dict(id="files_empty_str", kwargs={"journalfiles": ""}))
    sc.append(dict(id="files_empty_str_rot", kwargs={"journalfiles": "", "rotated": "1"}))
    sc.append(dict(id="files_empty_list", kwargs={"journalfiles": []}))
    sc.append(dict(id="files_rotated", kwargs={"journalfiles": "@T@/files/*.journal", "rotated": "1"}))
    sc.append(dict(id="files_flags0", kwargs={"journalfiles": "@T@/files/a.journal", "journalflags": "0"}))
    sc.append(dict(id="files_flags4", kwargs={"journalfiles": "@T@/files/a.journal", "journalflags": "4"}))
    sc.append(dict(id="files_and_path", kwargs={"journalfiles": "@T@/files/a.journal", "journalpath": "@T@/alt"}))
    sc.append(dict(id="files_and_path_rot", kwargs={"journalfiles": "@T@/files/a.journal", "journalpath": "@T@/alt", "rotated": "1"}))
    sc.append(dict(id="files_env", kwargs={"journalfiles": "@T@/files/a.journal"}, env="1"))
    sc.append(dict(id="ns", kwargs={"namespace": "foo"}))
    sc.append(dict(id="ns_flags", kwargs={"namespace": "foo", "journalflags": "4"}))
    sc.append(dict(id="ns_rot", kwargs={"namespace": "foo", "rotated": "1"}))
    sc.append(dict(id="ns_path", kwargs={"namespace": "foo", "journalpath": "@T@/alt"}))
    sc.append(dict(id="ns_files", kwargs={"namespace": "foo", "journalfiles": "@T@/files/a.journal"}))
    sc.append(dict(id="ns_env", kwargs={"namespace": "foo"}, env="0"))
    return sc


def sub(obj, tmp):
    if isinstance(obj, str):
        return obj.replace("@T@", tmp)
    if isinstance(obj, list):
        return [sub(o, tmp) for o in obj]
    if isinstance(obj, dict):
        return {k: sub(v, tmp) for k, v in obj.items()}
    return obj


def unsub(obj, tmp):
    if isinstance(obj, str):
        return obj.replace(tmp, "@T@")
    if isinstance(obj, list):
        return [unsub(o, tmp) for o in obj]
    return obj


def gen_args(upstream):
    from fail2ban.server import filtersystemd as fs
    tmp = tempfile.mkdtemp(prefix="f2bjournal")
    try:
        for rel in TREE:
            p = Path(tmp, rel)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("")
        # deterministic stand-in for `systemd-path`
        # (system-state-logs = <tmp>, system-runtime-logs = <tmp>/run: the default branch globs
        # <tmp>/journal/*/... and <tmp>/run/journal/*/...)
        fs._getSystemdPath = lambda name: {
            "system-state-logs": tmp,
            "system-runtime-logs": os.path.join(tmp, "run"),
        }[name]
        out = []
        for sc in args_scenarios():
            kwargs = sub(sc["kwargs"], tmp)
            env = sc.get("env")
            if env is None:
                os.environ.pop("F2B_SYSTEMD_DEFAULT_FLAGS", None)
            else:
                os.environ["F2B_SYSTEMD_DEFAULT_FLAGS"] = env
            rec = {"id": sc["id"], "kwargs": sc["kwargs"], "env_default_flags": env}
            try:
                args = fs.FilterSystemd._getJournalArgs(dict(kwargs))
                flags = args.get("flags")
                path = args.get("path")
                files = args.get("files")
                if flags is None:
                    flags = LOCAL_ONLY if (path is None and files is None) else 0
                rec["ok"] = {
                    "flags": flags,
                    "path": None if path is None else unsub(path, tmp),
                    "files": None if files is None else sorted(unsub(files, tmp)),
                    "namespace": args.get("namespace"),
                }
                # does python-systemd accept this open() call?
                try:
                    Reader(flags=args.get("flags"), path=path, files=files, namespace=args.get("namespace"))
                    rec["ok"]["reader_ok"] = True
                except ValueError as e:
                    rec["ok"]["reader_ok"] = False
                    rec["ok"]["reader_err"] = str(e)
            except Exception as e:
                rec["err"] = exc_name(e)
            out.append(rec)
        os.environ.pop("F2B_SYSTEMD_DEFAULT_FLAGS", None)
        return {"tree": TREE, "euid_placeholder": "EUID", "cases": out}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--upstream", default=str(ROOT / "fail2ban"))
    ap.add_argument("--out", default=str(ROOT / "crates" / "f2b-backend" / "tests" / "fixtures"))
    a = ap.parse_args()
    upstream = Path(a.upstream)
    out = Path(a.out)
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    install_fake_systemd(upstream)
    logging.disable(logging.CRITICAL)

    matches = []
    for i, ops in enumerate(gen_match_scenarios()):
        matches.append({"id": "m%03d" % i, "ops": ops, "results": run_match_scenario(upstream, ops)})
    jdump(out / "journal_matches.json", matches)

    jdump(out / "journal_entries.json", gen_entries(upstream))

    args = gen_args(upstream)
    # the tree contains the effective uid of the generator in file names: make that portable
    uid = str(os.geteuid())
    text = json.dumps(args, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    text = text.replace("user-%s." % uid, "user-@UID@.").replace("user-%s@" % uid, "user-@UID@@")
    (out / "journal_args.json").write_text(text + "\n")

    ents = json.loads((out / "journal_entries.json").read_text())
    print("matches scenarios: %d, entries: %d, formats: %d, args cases: %d" % (
        len(matches), len(ents["entries"]), len(ents["formats"]), len(args["cases"])))


if __name__ == "__main__":
    main()
