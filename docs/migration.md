# Fast2Ban Migration & Compatibility Guide

Fast2Ban is a memory-safe, high-performance Rust rewrite of Fail2Ban v1.1.2. It is designed as a drop-in replacement that operates directly on existing `/etc/fail2ban` configurations, actions, filters, and logs with zero required migration of config files.

---

## 1. Compatibility Overview

| Component | Upstream Fail2Ban (Python) | Fast2Ban (Rust) | Compatibility |
|---|---|---|---|
| **Configuration Files** | `fail2ban.conf`, `jail.conf`, `.local`, `.d/*.conf` | Same, unmodified | 100% compatible |
| **Filter Regexes** | Python `re` + `regex` engine | Rust `regex` + `fancy-regex` | 100% compatible on all 104 stock filters |
| **Date Detection** | `strptime` + regex date templates | `f2b-date` date detector | Bit-identical timestamp extraction |
| **Wire Protocol** | Python pickle over Unix domain socket | Restricted pickle decoder (protocols 2–5) | Bi-directional cross-compatible |
| **Command Line** | `fail2ban-client`, `fail2ban-server`, `fail2ban-regex` | `fast2ban-client`, `fast2ban-server`, `fast2ban-regex` | Identical flags and beautified tree outputs |
| **Database** | SQLite `fail2ban.sqlite3` (schemas v1–v4) | `f2b-db` (auto-migrating to v4) | Reads/writes identical schemas |
| **Systemd Backend** | `python-systemd` (C libsystemd) | `journalctl --output=export` pipe | Match syntax & field conversions preserved |

---

## 2. Performance & Resource Footprint

Benchmark results measured on identical corpora against the Python Phase 0 baseline:

| Workload / Metric | Upstream Fail2Ban (Python 3.14) | Fast2Ban (Rust) | Improvement |
|---|---|---|---|
| `sshd` throughput | 89,976 lines/s | **168,523 lines/s** | **1.87x faster** |
| `apache-auth` throughput | 144,724 lines/s | **276,430 lines/s** | **1.91x faster** |
| `postfix` throughput | 110,019 lines/s | **261,925 lines/s** | **2.38x faster** |
| **Peak Memory (RSS)** | **680,128 KiB (~680 MiB)** | **33,712 KiB (~33 MiB)** | **95% memory reduction (20x less RAM)** |

---

## 3. Deliberate Differences & Security Hardening

1. **Pickle Protocol Sandboxing**:
   - Upstream Python pickle decodes arbitrary global objects, allowing remote code execution if a socket is writable.
   - Fast2Ban implements a strictly sandboxed decoder allowing only data primitives (`None`, `bool`, `int`, `float`, `str`, `bytes`, `list`, `tuple`, `dict`, `set`) and `builtins.Exception` for server error reporting.
   - All arbitrary global opcodes (`GLOBAL`, `REDUCE`, `BUILD`, `NEWOBJ`) are rejected with `CodecError::SecurityViolation`.
   - Hard limits: 64 MiB payload size cap, 512 stack depth limit, 128 mark nesting limit.

2. **Command Injection Prevention**:
   - Foreign untrusted input (e.g. `<matches>`, `<ip>`, `<F-USER>`) in shell action templates is escaped via shell positional parameters (`sh -c '... $f2bV_var ...' var0 var1 ...`), eliminating command injection from crafted hostile log lines.

3. **Socket & File Permissions**:
   - Fast2Ban sets `umask(0o077)` on startup and explicitly sets mode `0600` on the Unix domain socket, restricting communication strictly to the owning root user.

4. **Python Action Scripts Unsupported**:
   - Python-based actions (such as `action.d/smtp.py`) are deliberately not executed. Shell-based actions (such as `nftables.conf`, `iptables.conf`, `sendmail.conf`, `abuseipdb.conf`, `dummy.conf`) are fully supported.

5. **Systemd Journal Subprocess**:
   - Rather than requiring dynamic C linkage against `libsystemd`, Fast2Ban reads journal streams via `journalctl --output=export`.

6. **Per-Jail Lock Isolation**:
   - Each jail maintains its own mutex. A slow or hanging firewall command in one jail cannot block status checks, queries, or execution of other jails.

---

## 4. Installation & Symlinks

To use Fast2Ban as a direct drop-in replacement for Fail2Ban:

### Binary Symlinks
```bash
ln -sf /usr/bin/fast2ban-server /usr/bin/fail2ban-server
ln -sf /usr/bin/fast2ban-client /usr/bin/fail2ban-client
ln -sf /usr/bin/fast2ban-regex  /usr/bin/fail2ban-regex
```

### Systemd Service
Copy `files/fast2ban.service` to `/etc/systemd/system/fast2ban.service` (or alias it to `fail2ban.service`):
```bash
cp files/fast2ban.service /etc/systemd/system/fail2ban.service
systemctl daemon-reload
systemctl enable --now fail2ban
```

### Logrotate Integration
Copy `files/fast2ban.logrotate` to `/etc/logrotate.d/fail2ban`:
```bash
cp files/fast2ban.logrotate /etc/logrotate.d/fail2ban
```

### Shell Completions
- Bash: `cp files/bash-completion/fast2ban /etc/bash_completion.d/fast2ban`
- Zsh: `cp files/zsh-completion/_fast2ban /usr/share/zsh/site-functions/_fast2ban`
