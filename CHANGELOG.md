# Changelog

All notable changes to Fast2Ban will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-20

### Added
- **Core Daemons & CLI Tools**:
  - `fast2ban-server`: Full Fail2Ban-compatible server daemon supporting background/foreground operation, signal handling, and multi-jail orchestration.
  - `fast2ban-client`: Complete CLI interface supporting interactive/non-interactive commands, configuration dumping (`-d`/`--dp`), duration expression evaluation (`--str2sec`), and beautified output rendering.
  - `fast2ban-regex`: Filter testing tool with exact character-for-character layout matching Python `fail2ban-regex` output, supporting files and systemd journal streams.
- **Drop-in Configuration Engine (`f2b-config`)**:
  - Hand-written INI parser with universal newline handling, include recursion (`[INCLUDES] before/after`), `.local` and `.d/` overrides, and Python `%(section/option)s` variable interpolation.
  - Verified 100% golden diff match across 490/490 stock and test configuration trees against upstream `fail2ban-client -d`.
- **Dual-Path Regex Engine (`f2b-regex`)**:
  - Linear-time compilation path using the Rust `regex` crate for 79% of stock failregexes.
  - Backtracking fallback path using `fancy-regex` for lookaheads, lookbehinds, named backreferences, and conditional regexes.
  - Bit-identical matching verification across 1,841 upstream `failJSON` sample records.
- **Date & Timestamp Detector (`f2b-date`)**:
  - Epoch timestamp parser supporting 17+ stock template formats, POSIX TZ rule evaluation via `jiff`, hit-count based pattern reordering, and `{^LN-BEG}`/`{DATE}` anchors.
- **Jail Runtime & Backends (`f2b-backend`, `f2b-action`, `f2b-types`)**:
  - Backends: Linux `inotify`, portable `polling`, and `systemd` journal via `journalctl --output=export`.
  - Actions: Dynamic `<tag>` substitution, process-group execution (`setsid`), timeout cleanup, and `$f2bV_*` positional parameter escaping preventing command injection.
  - State managers: Sliding window `FailManager` and ticket-tracking `BanManager`.
  - Ban time escalation: `bantime.increment`, `bantime.factor`, `bantime.formula` compiler, multipliers list, and `overalljails` database lookup.
- **Persistence (`f2b-db`)**:
  - SQLite backend supporting schemas v1 through v4 with automatic migration.
  - Active ban restoration and file position resumption via first-line MD5 matching.
- **Wire Protocol (`f2b-proto`)**:
  - Sandboxed Python pickle codec (protocols 2–5) with hard limits on payload size (64 MiB), stack depth (512), and mark nesting depth (128).
  - Bidirectional cross-compatibility tested against Python Fail2Ban client and server.
- **Packaging & Integration**:
  - Systemd service unit (`fast2ban.service`).
  - Logrotate hook (`fast2ban.logrotate`).
  - Shell completions for Bash and Zsh.
  - Man pages for `fast2ban-server(1)`, `fast2ban-client(1)`, and `fast2ban-regex(1)`.
  - Migration and compatibility guide (`doc/migration.md`).
