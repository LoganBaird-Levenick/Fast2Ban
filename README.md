# Fast2Ban

[![CI](https://github.com/LoganBaird-Levenick/Fast2Ban/actions/workflows/ci.yml/badge.svg)](https://github.com/LoganBaird-Levenick/Fast2Ban/actions/workflows/ci.yml)
[![License: GPL-2.0-or-later](https://img.shields.io/badge/License-GPL%20v2+-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/LoganBaird-Levenick/Fast2Ban)](https://github.com/LoganBaird-Levenick/Fast2Ban/releases)

**Fast2Ban** is a memory-safe, high-performance Rust drop-in replacement for [Fail2Ban](https://github.com/fail2ban/fail2ban) (reference version `1.1.2`). It monitors system logs and systemd journal streams for authentication failures and automatically bans offending IP addresses by configuring firewall packet filter rules (such as `nftables`, `iptables`, `ipset`, `pf`, or custom actions).

Fast2Ban parses existing Fail2Ban `/etc/fail2ban` configurations as-is with zero configuration migration required.

---

## Performance & Memory

Measured on identical log corpora against Fail2Ban (Python 3.14):

| Metric / Workload | Upstream Fail2Ban (Python) | Fast2Ban (Rust) | Improvement |
|---|---|---|---|
| **`sshd` filter throughput** | 89,976 lines/s | **168,523 lines/s** | **1.87x faster** |
| **`apache-auth` throughput** | 144,724 lines/s | **276,430 lines/s** | **1.91x faster** |
| **`postfix` throughput** | 110,019 lines/s | **261,925 lines/s** | **2.38x faster** |
| **Peak Memory (RSS)** | **680 MiB** | **33 MiB** | **95% memory reduction (20x less RAM)** |

---

## Key Features

- **100% Config & Filter Parity**: Loads existing `fail2ban.conf`, `jail.conf`, `.local`, `jail.d/*.conf`, `filter.d/*.conf`, and `action.d/*.conf` files. All 104 stock filters pass with exact match results.
- **Wire Protocol Compatibility**: Full bidirectional pickle wire protocol compatibility (protocols 2–5). The Python `fail2ban-client` can communicate with `fast2ban-server`, and `fast2ban-client` can manage upstream `fail2ban-server`.
- **Drop-in CLI**: Provides `fast2ban-server`, `fast2ban-client`, and `fast2ban-regex` with identical command-line flags and beautified tree outputs. Symlinking to `fail2ban-*` works seamlessly.
- **SQLite Persistence**: Schema v1–v4 compatible persistence (`fail2ban.sqlite3`). Automatically migrates legacy databases while maintaining ban states and log file offsets across restarts.
- **Backends**: Supports file monitoring via Linux `inotify` and portable `polling`, as well as native `systemd` journal monitoring via `journalctl --output=export`.
- **Dynamic Ban Escalation**: Full support for `bantime.increment`, `bantime.factor`, `bantime.formula`, multipliers, and database-backed `overalljails` tracking.
- **Security Sandboxing**:
  - Sandboxed pickle decoder rejecting arbitrary globals (`GLOBAL`, `REDUCE`, `BUILD`) to eliminate RCE risks over the control socket.
  - Hard caps on pickle payloads (64 MiB), stack depth (512), and mark nesting (128).
  - Shell command injection defense using `$f2bV_*` positional arguments for untrusted log parameters (`<matches>`, `<ip>`, `<F-USER>`).
  - Restrictive file permissions: sets `umask(0077)` and enforces mode `0600` on Unix domain sockets.

---

## Deliberate Differences & Non-Goals

1. **Python Actions Unsupported**: Fast2Ban executes external shell command actions (`action.d/*.conf`). Embedded Python scripts (`action.d/*.py`, such as `smtp.py`) are unsupported and produce an explicit configuration load error.
2. **Gamin Backend Removed**: Obsolete `gamin` backend is omitted; inotify and polling cover all supported use cases.
3. **Per-Jail Mutex Isolation**: Each jail maintains its own mutex. A slow or hanging firewall command in one jail will not block control socket operations or log processing in other jails.

---

## Installation

### Pre-built Binaries (GitHub Releases)

Download pre-compiled release tarballs from the [GitHub Releases](https://github.com/LoganBaird-Levenick/Fast2Ban/releases) page:

```bash
# Example: x86_64 Linux
tar -xzf fast2ban-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
cd fast2ban-v0.1.0-x86_64-unknown-linux-gnu
sudo make install
```

### Building From Source

Prerequisites: Rust 1.85+ stable toolchain.

```bash
git clone https://github.com/LoganBaird-Levenick/Fast2Ban.git
cd Fast2Ban

# Build optimized release binaries
cargo build --release

# Install binaries, man pages, systemd service, logrotate, and completions
sudo make install
```

To install compatibility symlinks (`fail2ban-server`, `fail2ban-client`, `fail2ban-regex`):
```bash
sudo make install-symlinks
```

---

## Quickstart & Service Setup

### 1. Enable Systemd Service

```bash
sudo cp files/fast2ban.service /etc/systemd/system/fast2ban.service
sudo systemctl daemon-reload
sudo systemctl enable --now fast2ban
```

### 2. Logrotate Integration

```bash
sudo cp files/fast2ban.logrotate /etc/logrotate.d/fast2ban
```

### 3. Shell Completions

- **Bash**: `sudo cp files/bash-completion/fast2ban /etc/bash_completion.d/fast2ban`
- **Zsh**: `sudo cp files/zsh-completion/_fast2ban /usr/share/zsh/site-functions/_fast2ban`

---

## CLI Usage

### Server
```bash
# Run in foreground with verbose output
fast2ban-server -f -v

# Run with custom socket and config directory
fast2ban-server -c /etc/fail2ban -s /var/run/fail2ban/fail2ban.sock
```

### Client
```bash
# Check server ping and status
fast2ban-client ping
fast2ban-client status

# Check status of a specific jail
fast2ban-client status sshd

# Manually ban or unban an IP
fast2ban-client set sshd banip 192.0.2.1
fast2ban-client set sshd unbanip 192.0.2.1

# Reload configuration without dropping active bans
fast2ban-client reload
```

### Regex Testing
```bash
# Test a filter regex against an auth log
fast2ban-regex /var/log/auth.log /etc/fail2ban/filter.d/sshd.conf

# Test against systemd journal with journalmatch options
fast2ban-regex "systemd-journal[journalflags=1]" /etc/fail2ban/filter.d/sshd.conf
```

---

## Verification & Conformance

Fast2Ban enforces parity against Fail2Ban via an extensive test matrix:

- **Filter Samples**: 1,841 / 1,841 upstream log sample records matching bit-identically (`1,496` matches and `1,340` timestamps verified).
- **Config Oracle**: 490 / 490 configuration dump golden diffs match upstream `fail2ban-client -d` output character-for-character.
- **Stock Jails**: 161 stock jail scenarios verified against upstream Python daemon execution.
- **Differential Oracle**: Bidirectional cross-compatibility tests between Python and Rust clients and servers.

---

## License

Fast2Ban is licensed under the [GNU General Public License v2.0 or later (GPL-2.0-or-later)](LICENSE).
