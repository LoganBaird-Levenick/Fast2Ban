"""Config scenarios for the config oracle (tools/dump_oracle.py).

Each scenario is `name -> {relative path inside the config dir: file text}`,
applied as an overlay on a copy of the stock config tree. They exercise what
real deployments do: `.local`/`jail.d` overrides, action/filter parameters,
include chains, malformed files, odd encodings and bad values. Upstream's
answer (including its errors) is recorded as the expected result.
"""
import random
import re
from pathlib import Path

ENABLE = lambda *names: "".join(f"[{n}]\nenabled = true\n" for n in names)

SCENARIOS = {
    "jaild-overrides": {
        "jail.d/10-enable.conf": "[sshd]\nenabled = true\nmaxretry = 3\n",
        "jail.d/20-more.local": "[sshd]\nbantime = 1h\nignoreip = 127.0.0.1/8 ::1 192.168.0.0/16\n",
        "jail.local": "[DEFAULT]\nbantime = 1d\nfindtime = 2h\n",
    },
    "action-params-multiline": {
        "jail.local": (
            "[sshd]\nenabled = true\nbackend = polling\nlogpath = /dev/null\n"
            "action = iptables-multiport[name=SSH, port=\"ssh,2222\", protocol=tcp]\n"
            "         iptables-allports[name=all, chain=FORWARD]\n"
        ),
    },
    "action-macros": {
        "jail.local": (
            "[DEFAULT]\ndestemail = root@example.org\nsender = f2b@example.org\n"
            "[sshd]\nenabled = true\nbackend = polling\nlogpath = /dev/null\naction = %(action_mwl)s\n"
            "[apache-auth]\nenabled = true\nbackend = polling\nlogpath = /dev/null\naction = %(action_cf_mwl)s\n"
        ),
    },
    "banaction-override": {
        "jail.local": (
            "[DEFAULT]\nbanaction = nftables\nbanaction_allports = nftables[type=allports]\n"
            + ENABLE("sshd", "recidive")
        ),
    },
    "filter-local-override": {
        "filter.d/sshd.local": (
            "[Definition]\nfailregex = ^bad <HOST>$\nignoreregex = ^ok\nmaxlines = 2\n"
            "datepattern = ^%%Y-%%m-%%d\njournalmatch = _SYSTEMD_UNIT=sshd.service + \"_COMM=a b\"\n"
        ),
        "jail.local": "[sshd]\nenabled = true\nbackend = polling\nlogpath = /dev/null\n",
    },
    "filter-params": {
        "jail.local": (
            "[a]\nenabled = true\nfilter = sshd[mode=aggressive]\nlogpath = /dev/null\nbackend = polling\n"
            "[b]\nenabled = true\nfilter = %(__name__)s[mode=ddos, logtype=journal]\nlogpath = /dev/null\n"
            "[c]\nenabled = true\nfilter = sshd[ mode = extra ]\nbackend = systemd\n"
        ),
    },
    "action-local-override": {
        "action.d/iptables-multiport.local": (
            "[Definition]\nactionban = echo ban <ip>\n[Init]\nport = 1234\n"
        ),
        "jail.local": "[sshd]\nenabled = true\nbackend = polling\nlogpath = /dev/null\naction = iptables-multiport\n",
    },
    "interpolation": {
        "jail.local": (
            "[DEFAULT]\nmyvar = X\n[sshd]\nenabled = true\nbackend = polling\nlogpath = /dev/null\n"
            "bantime = %(myvar)s%%\nfindtime = %(bantime)s-%(myvar)s\n"
        ),
    },
    "logpath-multi": {
        "jail.local": (
            "[sshd]\nenabled = true\nbackend = polling\n"
            "logpath = /dev/null\n          /nonexistent/x\n          /dev/null tail\n"
        ),
    },
    "skip-if-nologs": {
        "jail.local": "[sshd]\nenabled = true\nbackend = polling\nlogpath = /nonexistent/x\nskip_if_nologs = true\n",
    },
    "missing-logs": {
        "jail.local": "[sshd]\nenabled = true\nbackend = polling\nlogpath = /nonexistent/x\n",
    },
    "systemd-if-nologs": {
        "jail.local": (
            "[sshd]\nenabled = true\nbackend = auto\nlogpath = /nonexistent/x\n"
            "journalmatch = _SYSTEMD_UNIT=x.service\n"
        ),
    },
    "bad-values": {
        "jail.local": (
            "[sshd]\nenabled = true\nbackend = polling\nlogpath = /dev/null\nmaxretry = abc\n"
            "maxmatches = 1_0\nbantime.increment = yes\nignoreself = off\nbantime.factor = 2\n"
            "bantime.multipliers = 1 2 4\nbantime.overalljails = Maybe\n"
        ),
    },
    "err-interpolation-missing": {
        "jail.local": "[sshd]\nenabled = true\nbantime = %(nope)s\n",
    },
    "err-interpolation-syntax": {
        "jail.local": "[sshd]\nenabled = true\nbantime = 10%x\n",
    },
    "err-interpolation-recursion": {
        "jail.local": "[sshd]\nenabled = true\nbantime = %(findtime)s\nfindtime = %(bantime)s\n",
    },
    "err-duplicate-option": {
        "jail.local": "[sshd]\nenabled = true\nenabled = false\n",
    },
    "err-duplicate-section": {
        "jail.local": "[sshd]\nenabled = true\n[sshd]\nmaxretry = 1\n",
    },
    "err-no-section-header": {
        "jail.local": "enabled = true\n[sshd]\nenabled = true\n",
    },
    "err-parse-garbage": {
        "jail.local": "[sshd]\nenabled = true\nthis line has no delimiter\n",
    },
    "err-bad-filter-spec": {
        "jail.local": "[sshd]\nenabled = true\nfilter = sshd[mode=\n",
    },
    "err-bad-action-spec": {
        "jail.local": "[sshd]\nenabled = true\nbackend = polling\nlogpath = /dev/null\naction = iptables[x\n",
    },
    "err-missing-filter": {
        "jail.local": "[sshd]\nenabled = true\nfilter = nonexistent\n",
    },
    "err-missing-action": {
        "jail.local": "[sshd]\nenabled = true\nbackend = polling\nlogpath = /dev/null\naction = nonexistent\n",
    },
    "err-disabled-jail-bad-enabled": {
        "jail.local": "[zzz]\nenabled = %(nope)s\n[sshd]\nenabled = true\n",
    },
    "crlf-bom-tabs-comments": {
        "jail.local": (
            "[sshd]\r\nenabled = true\r\nbackend = polling\r\nlogpath = /dev/null ; trailing\r\n"
            "\tmaxretry = 7\r\n; full comment\r\n# another\r\nbantime = 10m ;inline\r\nport = http;x\r\n"
        ),
        "filter.d/bom.conf": "\ufeff[Definition]\nfailregex = ^x <HOST>$\n",
        "jail.d/bom.local": "[bom]\nenabled = true\nfilter = bom\nlogpath = /dev/null\nbackend = polling\n",
    },
    "bom-jail-local": {
        "jail.local": "\ufeff[sshd]\nenabled = true\n",
    },
    "includes-chain": {
        "jail.local": "[INCLUDES]\nbefore = extra-before.conf\nafter = extra-after.conf\n[sshd]\nenabled = true\nbackend = polling\nlogpath = /dev/null\n",
        "extra-before.conf": "[DEFAULT]\nbantime = 5m\n[sshd]\nmaxretry = 11\n",
        "extra-after.conf": "[sshd]\nmaxretry = 22\nfindtime = 7m\n",
    },
    "includes-loop": {
        "jail.local": "[INCLUDES]\nbefore = loop-a.conf\n[sshd]\nenabled = true\nbackend = polling\nlogpath = /dev/null\n",
        "loop-a.conf": "[INCLUDES]\nbefore = loop-b.conf\n[DEFAULT]\nbantime = 1m\n",
        "loop-b.conf": "[INCLUDES]\nbefore = loop-a.conf\n[DEFAULT]\nfindtime = 2m\n",
    },
    "includes-absolute-and-blank": {
        "jail.local": "[INCLUDES]\nbefore = ABS_INCLUDE\n\n          rel-missing.conf\n[sshd]\nenabled = true\nbackend = polling\nlogpath = /dev/null\n",
        "inc-abs.conf": "[DEFAULT]\nbantime = 9m\n",
    },
    "fail2ban-local": {
        "fail2ban.local": (
            "[Definition]\nloglevel = DEBUG\nlogtarget = SYSLOG\ndbfile = None\ndbmaxmatches = 5\n"
            "allowipv6 = yes\n[Thread]\nstacksize = 128\n"
        ),
    },
    "err-bad-loglevel": {
        "fail2ban.local": "[Definition]\nloglevel = LOUD\n",
    },
    "numeric-loglevel": {
        "fail2ban.local": "[Definition]\nloglevel = 5\n",
    },
    "py-action": {
        "jail.local": (
            "[sshd]\nenabled = true\nbackend = polling\nlogpath = /dev/null\n"
            "action = smtp.py[name=%(__name__)s, host=\"localhost\", port=25]\n"
        ),
    },
    "action-conditional-init": {
        "jail.local": (
            "[sshd]\nenabled = true\nbackend = polling\nlogpath = /dev/null\n"
            "action = iptables[name=x, chain=FWD]\n         iptables[name=y, port=\"http,https\"]\n"
            "         nftables[name=z, table=mine, family=ip6]\n"
        ),
    },
    "shared-filter-two-jails": {
        "jail.local": (
            "[j1]\nenabled = true\nfilter = sshd[mode=normal]\nbackend = polling\nlogpath = /dev/null\n"
            "[j2]\nenabled = true\nfilter = sshd[mode=aggressive]\nbackend = polling\nlogpath = /dev/null\n"
        ),
    },
    "err-tag-recursion": {
        "filter.d/custom.conf": "[Definition]\nfailregex = <a> <HOST>\na = <b>\nb = <a>\n",
        "jail.local": "[c]\nenabled = true\nfilter = custom\nlogpath = /dev/null\nbackend = polling\n",
    },
    "known-failregex": {
        "filter.d/sshd.local": "[Definition]\nfailregex = %(known/failregex)s\n            ^extra <HOST>$\n",
        "jail.local": "[sshd]\nenabled = true\nbackend = polling\nlogpath = /dev/null\n",
    },
    "misc-jail-options": {
        "jail.local": (
            "[sshd]\nenabled = true\nbackend = polling\nlogpath = /dev/null\nignorecommand = /bin/true <ip>\n"
            "ignorecache = key=\"<ip>\", max-count=100, max-time=5m\nlogencoding = utf-8\n"
            "logtimezone = UTC+0200\nusedns = no\nmaxlines = 3\n"
        ),
    },
    "unicode-values": {
        "filter.d/uni.conf": "[Definition]\nfailregex = ^ünï \u2603 <HOST>$\n",
        "jail.local": "[uni]\nenabled = true\nfilter = uni\nlogpath = /dev/null\nbackend = polling\nignoreip = ::1, 2001:db8::/32\n",
    },
    "section-names": {
        "jail.local": (
            "[my jail]\nenabled = true\nfilter = sshd\nlogpath = /dev/null\nbackend = polling\n"
            "[sshd-x]\nenabled = true\nfilter = sshd\nlogpath = /dev/null\nbackend = polling\n"
            "[Mixed.Case]\nEnabled = true\nFilter = sshd\nlogpath = /dev/null\nbackend = polling\n"
        ),
    },
    "enable-all-jails": {
        "jail.local": "[DEFAULT]\nenabled = true\n",
    },
    "enable-all-jails-polling": {
        "jail.local": "[DEFAULT]\nenabled = true\nbackend = polling\nlogpath = /dev/null\n",
    },
    "no-jail-local-empty-defaults": {
        "jail.local": "[DEFAULT]\n",
    },
    "jail-section-case-and-spaces": {
        "jail.local": "[sshd]\nenabled=true\nbackend    =    polling\nlogpath:/dev/null\nmaxretry :  4\n",
    },
}

# placeholder resolved by dump_oracle into the absolute path of the work dir
ABS_PLACEHOLDER = "ABS_INCLUDE"


def _action_choices():
    return [
        "%(action_)s", "%(action_mw)s", "%(action_mwl)s", "%(action_cf_mwl)s",
        "iptables-allports[name=%(__name__)s]", "nftables-multiport[blocktype=DROP, port=\"80,443\"]",
        "route", "", "firewallcmd-ipset[name=X]", "ufw", "hostsdeny",
        "iptables[name=a]\n           iptables-multiport[name=b, port=ssh]",
    ]


def generated(stock: Path, n: int = 150, seed: int = 20260101):
    """Seeded random jail variants over the stock jails."""
    text = (stock / "jail.conf").read_text(encoding="utf-8")
    jails = [m.group(1) for m in re.finditer(r"^\[([^\]]+)\]", text, re.M)
              if m.group(1) not in ("DEFAULT", "INCLUDES")]
    rng = random.Random(seed)
    out = {}
    for i in range(n):
        parts = []
        for j in rng.sample(jails, rng.randint(1, 3)):
            lines = [f"[{j}]", "enabled = true"]
            if rng.random() < .6:
                lines.append("backend = " + rng.choice(["auto", "polling", "systemd", "pyinotify", "gamin"]))
            if rng.random() < .5:
                lines.append("logpath = " + rng.choice(["/dev/null", "/dev/null tail", "/nonexistent/%(__name__)s.log", "/dev/null\n          /nonexistent/y"]))
            if rng.random() < .4:
                lines.append("maxretry = " + rng.choice(["1", "10", "0", "x", " 3 ", "1_0"]))
            if rng.random() < .4:
                lines.append("bantime = " + rng.choice(["10m", "1h 30m", "-1", "1y", "600", "%(findtime)s"]))
            if rng.random() < .3:
                lines.append("findtime = " + rng.choice(["10m", "1d", "3600"]))
            if rng.random() < .5:
                lines.append("action = " + rng.choice(_action_choices()))
            if rng.random() < .3:
                lines.append("filter = %(__name__)s[mode=" + rng.choice(["normal", "aggressive", "ddos", "extra", "more", "auth", "rbl", "errors"]) + "]")
            if rng.random() < .3:
                lines.append("ignoreip = " + rng.choice(["127.0.0.1/8", "::1 10.0.0.0/8, 192.168.1.1", "example.com", ""]))
            if rng.random() < .2:
                lines.append("port = " + rng.choice(["ssh", "http,https", "0:65535"]))
            if rng.random() < .2:
                lines.append("usedns = " + rng.choice(["yes", "no", "warn", "raw"]))
            parts.append("\n".join(lines) + "\n")
        default = ""
        if rng.random() < .4:
            default = "[DEFAULT]\n" + "".join(
                f"{k} = {v}\n" for k, v in rng.sample(
                    [("bantime", "2h"), ("maxretry", "2"), ("banaction", "iptables-allports"),
                     ("banaction_allports", "nftables[type=allports]"), ("ignoreip", "127.0.0.1/8"),
                     ("usedns", "no"), ("destemail", "a@b.c"), ("mta", "mail")], rng.randint(1, 3)))
        out[f"rand-{i:03d}"] = {"jail.local": default + "".join(parts)}
    return out
