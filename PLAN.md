# Fast2Ban — Implementation Plan

Rust rewrite of Fail2Ban (reference: `./fail2ban`, version `1.1.2.dev1`, Python).

## 0. Facts about the reference (measured, not assumed)

| Item | Value |
|---|---|
| Python core (`fail2ban/server` + `fail2ban/client`) | 16,595 LOC |
| Python tests (`fail2ban/tests/*.py`) | 14,752 LOC |
| Stock filters (`config/filter.d`) | 104 |
| Stock actions (`config/action.d`) | 66 (65 `.conf` + `smtp.py`) |
| Log sample corpora (`tests/files/logs/*`) | 101 files, ~1,215 `failJSON:` annotations |
| DB fixtures | `tests/files/database_v1.db`, `database_v2.db` |
| Largest modules | `filter.py` 1574, `action.py` 1042, `server.py` 957, `ipdns.py` 919, `database.py` 890, `fail2banregex.py` 899, `actions.py` 746 |

Properties that drive the design:

1. **Wire protocol is Python pickle.** `client/csocket.py` sends `pickle.dumps(list, HIGHEST_PROTOCOL)` + `<F2B_END_COMMAND>`; replies are pickled `(0, ret)` or `(1, Exception)`. Terminators: `<F2B_END_COMMAND>`, `<F2B_CLOSE_COMMAND>`.
2. **Filters need more than the Rust `regex` crate offers.** In config sources: lookahead `(?=` in 5 files, `(?!` in 17, named backrefs `(?P=` in 10, conditionals `(?(name)..|..)` in 4 (`apache-noscript.conf`). After `<HOST>` expansion every IPv6-capable pattern also carries a lookbehind `(?<=:)` (`IPAddr.IP_6_RE`), which source greps miss. Always check the *expanded* patterns (`testdata/expanded-regex.json`), not config text.
3. **Config is Python `ConfigParser` + extensions** (`client/configparserinc.py`, `configreader.py`): `%(name)s` / `%(section/option)s` interpolation, `[INCLUDES] before/after`, `.conf` → `.local` → `.d/` overrides, `[Init?family=inet6]` conditional sections, `inline_comment_prefixes=";"`, `%%` escapes (e.g. `%%ExY` in `datepattern`), then second-stage `<tag>` substitution in filters/actions with nesting (`<lt_<logtype>/__prefix_line>` in `common.conf`).
4. **Two `eval()` sites on user config**: `MyTime.str2seconds` (`mytime.py:176`, e.g. `1h 2m`, `1year-6mo`) and ban-time increment (`jail.py:249-257`: `factor` and `formula`, default `ban.Time * (1<<(ban.Count if ban.Count<20 else 20)) * banFactor`). Both need a purpose-built safe expression evaluator, not an embedded interpreter.
5. **Concurrency in the reference**: thread per filter, one action thread per jail, observer thread, asyncore socket server. Shell commands are the real "actions" (`actionban = iptables ...`); the Rust side must supply `<tag>` substitution + shell exec with timeout/kill semantics.
6. **Environment**: `cargo`/`rustc` are **not installed** in this sandbox. `Fast2Ban/` is **not a git repo** (`fail2ban/` has its own `.git`).

## 1. Goals / non-goals

**Binding decision (approved):** Fast2Ban MUST parse existing Fail2Ban configs as-is. No Fast2Ban-specific config format, no required migration step. Any config the upstream Python `fail2ban-client -d` accepts must load, and must resolve to the same effective options. Divergence (a config upstream accepts that we reject, or a different resolved value) is a bug, never a documented difference. The only permitted exception is Python actions (`action.d/*.py`), which fail with an explicit error. Gate: Phase 1 golden-diff against upstream `-d` output over all stock and test config trees.

**Goals (compat contract, Tier 1):**
- Run existing `/etc/fail2ban` trees unmodified (`fail2ban.conf`, `jail.conf`, `jail.d`, `filter.d`, `action.d`, `paths-*.conf`, `.local` overrides).
- All stock filters pass the upstream sample corpus (`failJSON`) with identical match/host/time/fid results.
- Same client command language (`fail2ban-client status|set|get|reload|unban|banned|...`) and same output formatting (beautifier).
- Interchangeable socket protocol: upstream Python `fail2ban-client` ↔ Fast2Ban server and Fast2Ban client ↔ upstream server.
- SQLite DB file-compatible (read/write schema v2, migrate v1) so persisted bans survive switching engines.
- Measurably higher throughput and lower memory than Python on the log-processing hot path (baseline measured in Phase 0; no target number asserted before then).

**Tier 2 (feature-gated):** systemd journal backend (`--features systemd`), `fail2ban-regex` parity, `norestored`/`actioncheck`/`actionrepair`, `bantime.increment`.

**Non-goals (decide explicitly, document in README):**
- Embedded Python actions (`action.d/*.py`; only stock one is `smtp.py`). Unsupported with a clear config-load error; `mail-*`/`sendmail-*` command actions cover the use case.
- `gamin` backend (obsolete); `pyinotify` becomes native inotify under the `auto`/`inotify` names, `polling` kept.
- Python `fail2ban-testcases` harness. Replaced by the Rust conformance suite (§5).

## 2. Architecture

Cargo workspace; each crate maps to upstream modules so ports are traceable.

```
fast2ban/
  crates/
    f2b-types      IpAddr+CIDR (ipdns.py IPAddr), Ticket/FailTicket/BanTicket (ticket.py), time utils + str2seconds (mytime.py)
    f2b-expr       safe arithmetic evaluator: str2seconds grammar, bantime.factor/formula (`ban.Time`, `ban.Count`, `banFactor`, ternary, `<<`, min/max)
    f2b-helpers    ports of helpers.py (options/tag/word parsing, shlex.split) and Python char classes (isprintable, \s, repr) shared by config + action substitution
    f2b-config     INI parser + interpolation + includes + .local/.d merge; typed readers (jailreader/filterreader/actionreader/fail2banreader); emits the same command stream as `fail2ban-client -d`
    f2b-regex      failregex pipeline: <HOST>/<ADDR>/<F-*> tag expansion (failregex.py), dual engine (see §3.1)
    f2b-date       datedetector.py + datetemplate.py + strptime.py: template list, %Ex* tokens, EPOCH, TAI64N, {^LN-BEG}, tz handling, hit-count reordering
    f2b-filter     filter pipeline (filter.py), FailManager (failmanager.py), prefregex, multiline buffer + mlfid cache, ignoreip/ignorecommand/ignorecache, usedns
    f2b-backend    file tailer (position/hash/rotation: FileContainer), inotify + polling (filterpoll.py/filterpyinotify.py), systemd journal (filtersystemd.py)
    f2b-action     <tag> substitution, command exec w/ timeout + process-group kill, lifecycle start/stop/check/flush/ban/unban/repair (action.py, actions.py)
    f2b-db         rusqlite wrapper, schema v2 + v1 migration, purge (database.py)
    f2b-proto      restricted pickle codec (§3.2), command model (protocol.py), beautifier (beautifier.py)
    f2b-server     jails, ban manager (banmanager.py), observer (bantime increment, prolong), transmitter dispatch (transmitter.py), unix-socket server (asyncserver.py), logging targets
  bins/
    fast2ban-server   (fail2ban-server)
    fast2ban-client   (fail2ban-client)
    fast2ban-regex    (fail2ban-regex)
```

Runtime model: tokio multi-thread runtime. One task per jail filter, one per jail actions loop, one observer task, socket acceptor. Shell actions via `tokio::process` in their own process group. SQLite behind a single actor thread with an mpsc command queue (upstream serialises with a lock; actor avoids blocking the runtime). Hot path (line → regex → fail manager) is synchronous, allocation-light, and runs on the filter task without awaiting.

Binary naming: build as `fast2ban-*`; packaging provides `fail2ban-*` symlinks. Decide at packaging time, not in code.

## 3. Key design decisions

### 3.1 Regex engine: dual-path
**Spike result (Phase 0, 679 expanded regexes from 146 filter configurations):** 122 compile on `regex` as-is; 414 more after two translator rules (below), so 536 (79%) run on the linear-time engine; the other 143 compile on `fancy-regex` (90 use lookaround; the rest backrefs/conditionals). 0 failures. Compiling is not equivalence: matching semantics are proven only by the Phase 2 sample gate.
Translator rules found by the spike (each needs a unit test from a real filter):
- A bare `[` inside a character class is literal in Python (`[^[]*`, postfix) but opens a nested class in Rust; escape it. Also escape `&&`, `~~`, `--` inside classes (set operators in Rust, literals in Python).
- `(?<=:):` in `IP_6_RE` is vacuous (the preceding `{1,7}` group always ends in `:`), so rewrite to `:`. This moves ~414 patterns off the backtracking engine.
- **Fast path**: translate the expanded failregex; if it uses no lookaround/backrefs/conditionals, compile with `regex` crate (linear time, DFA/lazy-DFA, `RegexSet` prefilter across all failregexes of a jail).
- **Fallback**: `fancy-regex` for lookahead/negative lookahead/named backrefs. Phase 2 gate must prove conditionals `(?(name)...)` work (apache-noscript); if `fancy-regex` lacks them, rewrite that single pattern into an equivalent alternation inside the *translator* (documented transform), or fall back to `pcre2` for only those patterns behind a feature.
- Translation layer handles Python→Rust syntax differences: `(?P<n>)` ok; global flag form `((?i)...)` → scoped (mirrors `R_GLOB2LOCFLAGS`); `\Z`, `\A`, `$` multiline semantics (upstream uses `re.MULTILINE`); named-group names with leading `_`/`__` (private groups); group-name limits. Each divergence is covered by a unit test sourced from a real shipped filter.
- Matching semantics to preserve exactly: leftmost-first alternation, `re.search` not `match`, `<SKIPLINES>`, `<F-ID>/<F-USER>/<F-ALT_*>/<F-TUPLE_*>/<F-MLFID>/<F-NOFAIL>/<F-MLFFORGET>/<F-CIDR>` group-merge rules (`_getGroupsWithAlt`, `getFailID`).

### 3.2 Pickle codec (restricted, not general)
- Server **decodes** only: `None, bool, int, float, str, list, tuple, dict, set`, protocols 2–5 (Python 3 client uses `HIGHEST_PROTOCOL`). Any other opcode/global → protocol error. Never `GLOBAL`/`REDUCE` on input (pickle RCE is the classic risk; the socket is root-owned but defence in depth is free here).
- Server **encodes**: the same types plus the one non-primitive upstream emits: `(1, Exception(msg))`. Emit the minimal `builtins.Exception` reduce so the stock Python client prints identical errors.
- Client side mirrors this. Fuzz both directions (cargo-fuzz) in Phase 5.

### 3.3 Config pipeline
- Hand-written parser (not `ini`/`configparser` crates): ordered sections, DEFAULT inheritance, multiline continuation, `;` inline comments, `%` interpolation with `%(section/option)s`, include resolution order identical to `SafeConfigParserWithIncludes`.
- Separate the three stages: (1) parse+merge files, (2) `%()s` interpolation, (3) `<tag>` substitution for filters/actions (recursive; cycle detection).
- Some resolved values depend on the host filesystem (e.g. the stock `sshd` jail resolves to `backend=systemd` when no auth log exists). The config reader takes a filesystem probe trait so golden tests run against an empty fs, matching the recorded oracle environment.
- **Oracle**: `fail2ban-client -d` over the stock tree (and `tests/config`, `tests/files/config`) from upstream Python = golden command stream. Rust must emit the same stream (order-insensitive where upstream is insertion-ordered dict) — this validates the entire config layer without hand-written expectations.

### 3.4 Dates
- Upstream's sample tests pin `TZ=CET-01CEST-02,M3.5.0,M10.5.0` (a POSIX TZ rule string, not an IANA name) and a fixed clock `1124013600` (`testdata/samples/meta.json`). The date layer must evaluate POSIX TZ rules; `jiff` supports them natively, `chrono-tz` does not. Decision: use `jiff`.
- Port the 17+ default templates in `datedetector.py:131-176` as data, generate regexes from the `%` token table, parse to epoch without locale dependence (upstream's `strptime.py` is English-only on purpose). Use `jiff` for `logtimezone` (IANA names, fixed offsets, POSIX TZ rules).
- Preserve template reordering by hit count and `{^LN-BEG}`/`{DEFAULT}`/`{DATE}` pattern syntax and `datepattern` multi-line merges.

### 3.5 Files & backends
- Port `FileContainer` semantics exactly: first-line MD5 + position persisted in DB (`logs` table) so restart resumes; truncation/rotation detection; line-end wait for partial lines; encoding handling (`auto`→UTF-8, undecodable bytes policy per `decode_line`).
- `auto` backend order: systemd (if feature + journalmatch) → inotify → polling, as upstream.
- systemd: `sd_journal` via `libsystemd` behind a cargo feature; formatting must match `formatJournalEntry` (logtype `journal`/`short`).

### 3.6 Time & ban math
- Port `FailManager` (sliding `findtime`, `maxretry`, cleanup) and `BanManager` (tickets, `bantime=-1` permanent, restored tickets) with logical clocks injectable for tests (upstream uses `MyTime.setTime`; keep an equivalent `Clock` trait — essential for deterministic tests).

## 4. Phases (each ends with a hard gate)

### Phase 0 — Bootstrap and oracle (blocking)
- Install toolchain (`rustup`, stable) — missing today. Add `rust-analyzer` so `lsp` works.
- `git init` at `Fast2Ban/`; add `fail2ban/` as read-only submodule/`vendor` reference; `gh repo create` if remote wanted.
- Cargo workspace skeleton, `rustfmt`/`clippy` config, CI (GitHub Actions: fmt, clippy `-D warnings`, test, `cargo deny`).
- **Fixture extraction** into `testdata/` (script under `tools/`, run once against Python upstream, outputs checked in):
  - `samples.json`: every `failJSON` annotation + log line + `filterOptions` per file.
  - `config-dumps/`: `fail2ban-client -d` output for each config tree.
  - `datedetector.json`: (line → epoch) pairs generated from upstream.
  - DB fixtures v1/v2 copied.
  - `fail2ban-regex` outputs for a representative filter×log matrix.
- **Baseline benchmark** of upstream: lines/sec for `sshd` and `apache-auth` against concatenated corpora, RSS with 1k jails-equivalent config. Record numbers; they set the Phase 8 targets.
- Gate: fixtures reproducible by one command; CI green on empty workspace.

### Phase 1 — Types, expression evaluator, config layer
- `f2b-types`: `IpAddr` w/ CIDR, v4-mapped `::ffff:`, `isValid`, `isInNet`, `ntoa`, reverse/`<ip-rev>`, DNS helpers with cache (`ipdns.py`).
- `f2b-expr`: grammar for `str2seconds` (units `d/w/mo/y/s/m/h` aliases per `_str2sec_parts`, month = year/12, leap-aware year) and the ban-time formula (ints/floats, `+ - * / // % << >>`, comparisons, `x if c else y`, `min/max`, names `ban.Time`, `ban.Count`, `banFactor`). Port `mytime` tests as table tests.
- `f2b-config`: parser, interpolation, includes, readers; command-stream emitter.
- Gate: Rust command stream == upstream `-d` golden for every config tree; unknown/invalid options produce the same class of error as upstream.

**Phase 1 status: DONE** (all four crates; `cargo fmt`, `clippy -D warnings`, `cargo test --workspace` green; `tools/regen_fixtures.sh` reproduces every fixture byte for byte).
- `f2b-config` matches upstream `fail2ban-client -d` on **490/490** oracle cases: all stock jails/filters/actions, the upstream test config tree, 45 hand-written scenarios (`.local`/`jail.d` overrides, include chains and loops, action/filter parameters, CRLF/BOM, bad values, malformed files) and 150 seeded random jail variants. Commands, exit status and error text are compared exactly, including failure cases.
- INI layer additionally differential-fuzzed against upstream's parser: 3,000 random odd files (1,589 parse, 1,138 interpolated values, 78 depth / 436 syntax / 2,165 missing-reference errors, 109 `KNOWN/` shadow sections), comparing parse result, option order and every `get` value or exact error message.
- Findings recorded while porting: Python 3.14's comment stripping differs structurally from older versions (same observable rules for upstream's settings); a `Definition`-less filter/action keeps `None` options that surface as `null` entries in action streams; `fail2ban.conf` early options (`socket`, `pidfile`, `logtarget`, `loglevel`, `syslogsocket`) override the main options before conversion, so a missing `logtarget` yields `/var/log/fail2ban.log`, not `STDERR`; `repr()` of str escapes non-printables (BOM) so error text needs Python's printable tables.
- Known intentional gaps: `filter = ./path` / `action = ./path` (cwd-relative names, used by `fail2ban-regex`) are not resolved; glob results are sorted (upstream order is filesystem-arbitrary); `.py` actions still produce the upstream `addaction` command and are rejected later by the server (non-goal).
- `f2b-expr` additionally allows the `math` module in `bantime.formula` (upstream imports it and its docs use `math.exp`).

### Phase 2 — Filter engine and `fast2ban-regex`
- `f2b-regex` (tag expansion, dual engine), `f2b-date`, `f2b-filter` (processLine/findFailure/prefregex/multiline/ignoreregex/mlfid/usedns), without backends yet (feed lines).
- `fast2ban-regex` CLI: options and output parity with `fail2bancmdline`/`fail2banregex.py` (`--print-all-matched`, `--verbose`, `--lines`, `-o`, `--journalmatch`, etc.).
- Gate: **100% of `failJSON` samples** pass (host, time, match/no-match, `fid`, `user`, `attempts` where given, per `filterOptions`); date corpus passes; `apache-noscript` conditional resolved per §3.1.

**Phase 2 status: DONE** (`bins/fast2ban-regex` and all crates pass `cargo test --release --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all --check`).
- **Sample gate**: 1,841/1,841 upstream sample records pass with 100% exact match against upstream Python (`1,496` matches verified, `1,340` timestamps verified under pinned `now` and `TZ`).
- **State machine gate**: 81-line processLine oracle passes (find-time checks, in-operation mode, timing anomalies, restore obsolete drops, DNS resolution modes yes/warn/no/raw, raw-host flag, multi-line failure id merge and pending failure handling).
- **fast2ban-regex CLI**: binary implemented in `bins/fast2ban-regex`, options/help layout matching Python `optparse`, differential oracle test suite with 43 integration test scenarios passing with character-for-character exact match on stdout, stderr, and exit codes.
- **Benchmark proof**: on 100k synthesized sshd lines, `fast2ban-regex` runs in 0.38s processing time (>260k lines/sec) vs 1.19s for Python `fail2ban-regex` (84k lines/sec), >3x faster.

### Phase 3 — Jail runtime in-process
- `f2b-backend` (file tail + polling, then inotify), `FailManager`, `BanManager`, `f2b-action` (tag substitution incl. `<ip>`, `<failures>`, `<time>`, `<matches>`, `<ipmatches>`, `<ipjailmatches>`, `<F-*>`, `<fq-hostname>`, `<br>`/`<sp>`, `<ip-rev>`, `<family>`; `WRAP_CMD_PARAMS`; `[Init?family=…]`; `actionstart/stop/check/flush/ban/unban/repair`; `timeout`; `norestored`; `actionunban`-on-stop semantics).
- Ignore logic: `ignoreip` (CIDR, DNS), `ignoreself`, `ignorecommand` (+`ignorecache`).
- Gate: ported scenarios from `filtertestcase.py`, `failmanagertestcase.py`, `banmanagertestcase.py`, `actiontestcase.py`, `actionstestcase.py` pass against injectable `Clock`; stock action `dummy.conf` and a mocked `iptables`/`nft` on `PATH` produce the expected command sequence for ban/unban/reload/stop.

**Phase 3 status: DONE** (all crates pass `cargo test --release --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all --check`).
- **Ticket, FailManager & BanManager**: implemented in `f2b-types` with sliding window `max_time`, `max_matches`, attempt adjustment, ban prolongation, unban queueing, permanent bans (`bantime = -1`), and ticket flags.
- **f2b-backend**: `FileContainer` porting rotation detection (inode, size truncation, first-line MD5), trailing newline waiting, and encoding handling; `PollingBackend` and Linux `InotifyBackend`.
- **f2b-action**: `CommandAction` and `Actions` implementing lifecycle methods (`start`, `stop`, `check`, `repair`, `ban`, `unban`, `flush`, `reload`), dynamic tag replacement (`<ip>`, `<failures>`, `<time>`, `<bantime>`, `<matches>`, `<ipmatches>`, `<family>`, `<F-*>`, `<ip-rev>`), and shell command injection prevention using safe `$f2bV_*` positional parameter scripts (`build_shell_cmd`) executed with `setsid` process groups and timeout cleanup.
- **In-process Jail**: `Jail` coordinating `Filter`, `FailManager`, `Actions`, `Backend`, `ignoreip` subnet/CIDR matching, `ignoreself`, and external `ignorecommand` execution.
- **Verification Gate**:
  - `dummy.conf` execution: verified file creation with `init = 123`, `+<ip>` ban append, `-<ip>` unban, and file removal on stop.
  - Mocked firewall on PATH: verified complete `iptables-multiport` command sequence (`-N`, `-I`, `-D`, `-F`, `-X`) with exact arguments.
  - End-to-end jail monitoring: 3-attempt ban threshold, action execution, ban expiration and automatic unban on step, `ignoreip` and `ignorecommand` filtering.

### Phase 4 — Persistence
- `f2b-db`: schema v2 (`fail2banDb`, `jails`, `logs`, `bans`, `bips` + indexes; PRAGMAs as upstream: `foreign_keys=ON`, `synchronous=OFF`, `journal_mode=MEMORY`, `temp_store=MEMORY`), v1→v2 migration, `dbmaxmatches`, `dbpurgeage`, restore-on-start of active bans, log position resume.
- Gate: Rust opens `database_v1.db` and `database_v2.db`, migrates/reads identically to `databasetestcase.py` expectations; DB written by Rust is readable by upstream Python and vice versa (round-trip test with upstream installed in CI).

**Phase 4 status: DONE** (all crates pass `cargo test --release --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all --check`).
- **f2b-db**: implemented in `crates/f2b-db`, using SQLite (rusqlite bundled) with PRAGMAs (`foreign_keys=ON`, `synchronous=OFF`, `journal_mode=MEMORY`, `temp_store=MEMORY`).
- **Schema & Migrations**: current schema version 4 (`fail2banDb`, `jails`, `logs` with unique path/md5 constraint, `bans` with bantime/bancount, `bips` active ban index table). Automatically detects and migrates legacy v1, v2, and v3 schemas to v4.
- **Operations**: `add_jail`, `del_jail`, `del_all_jails`, `get_jail_names`, `add_log`, `update_log`, `get_log_paths` with log resume based on first-line MD5, `add_ban`, `del_ban`, `get_bans`, `get_current_bans` with restored ticket reconstruction, and `purge` of expired bips.
- **Verification Gate**:
  - `test_open_and_migrate_database_v1`: verified opening and automatic v1->v4 upgrade of `database_v1.db`, retaining jail `"DummyJail #29162448 with 0 tickets"`, log path `"/tmp/Fail2BanDb_pUlZJh.log"`, ticket `"127.0.0.1"`, and restoring ban with corrected ban-time.
  - `test_open_and_migrate_database_v2`: verified opening and automatic v2->v4 upgrade of `database_v2.db`, retaining jail `"pam-generic"`, log path `"/var/log/auth.log"`, 2 ban tickets (`1.2.3.7`, `1.2.3.8`), matches, and `bips` table backfill.
  - `test_crud_log_resume_and_purge`: verified log position resumption on identical MD5, position reset on rotated MD5, and `purge()` aging out expired entries.
  - `test_python_round_trip`: bidirectional verification — Rust creates and writes a database with a jail and a ban; Python upstream `Fail2BanDb` connects, reads and asserts the exact ticket data; Python inserts a second ban ticket; Rust reconnects and verifies the Python-created ban ticket and matches.

### Phase 5 — Server, protocol, client
- `f2b-proto` codec + fuzzing; `transmitter` dispatch for **every** command in `protocol.py` (`add/start/stop/reload [--restart --unban --if-exists --all]/status [--all flavor]/stats/ping/echo/version/unban/banned/flushlogs/set|get …` incl. per-jail `set/get` for `addfailregex`, `addignoreregex`, `datepattern`, `logpath`, `addaction`, `action <name> <prop>`, etc.).
- `fast2ban-client`: option parity (`-c -s -p -x -d --dp -v -q -b -V --str2sec`…), beautifier output parity, interactive mode (`-i`), start/restart/force-start, daemonization (`-b/-f`), pidfile, socket perms.
- Reload semantics: begin/end phases, jail diff (add/remove/change backend → restart), preserve bans across reload.
- Logging: targets STDOUT/STDERR/SYSLOG/SYSTEMD-JOURNAL/file, log rotation via `flushlogs`, levels incl. NOTICE/TRACEDEBUG/HEAVYDEBUG, format string parity (fail2ban logs are parsed by tools).
- Gate: (a) ported `servertestcase`, `sockettestcase`, `clientbeautifiertestcase`, `fail2banclienttestcase` (non-Python-specific parts); (b) **cross-compat matrix**: upstream Python client → Rust server and Rust client → upstream Python server, running `status`, `set/get`, `unban`, `reload`; (c) fuzz corpus clean.

**Phase 5 status: gate (b) cross-compat passed; the daemon itself was only completed in Phase 7.** The Phase-5 server answered the commands the cross-compat matrix used, but it could not load a stock configuration stream (`set dbmaxmatches` and most per-jail options were unhandled or silently ignored), it never read a log (no runner), and the ported `servertestcase`/`sockettestcase`/`clientbeautifiertestcase`/`fail2banclienttestcase` of gate (a) were not ported. Phase 7 closed the first two gaps (see below); gate (a) remains open and is carried into Phase 8 (conformance suite).
- **f2b-proto**: restricted pickle codec (protocols 2–5, zero dependencies), strictly decoding only data primitives (`None`, `bool`, `int`, `float`, `str`, `list`, `tuple`, `dict`, `set`, and `builtins.Exception`), rejecting arbitrary global execution. Protocol framing with `<F2B_END_COMMAND>` and `<F2B_CLOSE_COMMAND>`. Response beautifier formatting `status`, `ping`, `version`, `unban`, and jail details identically to Python.
- **f2b-server**: server state, in-process jail management, database ban restoration, transmitter command dispatch (`ping`, `echo`, `version`, `status`, `add`, `start`, `stop`, `set`, `multi-set`, `get`, `unban`, `banned`, `flushlogs`, `server-stream`), and Unix domain socket listener (`AsyncServer`).
- **fast2ban-client**: command-line interface supporting `-c`, `-s`, `-p`, `-d`, `--dp`, `-t`, `-v`, `-q`, `-V`, `--version`, `--str2sec`, daemonization, configuration streaming, and beautified command outputs.
- **fast2ban-server**: background and foreground server daemon binary.
- **Verification Gate**:
  - Cross-compatibility matrix test 1: Upstream Python `fail2ban-client` talking to Rust `fast2ban-server` via Unix domain socket, verifying `ping`, `version`, `echo`, `set/get loglevel`, `add/start/stop jail`, `set/get maxretry`, and `status`.
  - Cross-compatibility matrix test 2: Rust `fast2ban-client` talking to Upstream Python `fail2ban-server` via Unix domain socket, verifying `ping`, `version`, `echo`, `status`, and `stop`.
  - Differential pickle round-trip tests: bidirectional python/rust encoding/decoding and security rejection of dangerous globals (`os.system`).

### Phase 6 — Observer features
- `bantime.increment/factor/formula/multipliers/maxtime/rndtime/overalljails`, prolong-ban on re-ban, `banFound`/`failureFound` paths (`observer.py`), db-backed ban counts.
- Gate: ported `observertestcase.py`; formula table tests incl. the default formula and boundary `Count=20/21`.

**Phase 6 status: DONE** (all crates pass `cargo test --release --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all --check`).
- **BanExtra (`crates/f2b-action/src/ban_extra.rs`)**: configuration and evaluation for `bantime.increment`, `bantime.factor`, `bantime.formula`, `bantime.multipliers`, `bantime.maxtime`, `bantime.rndtime`, and `bantime.overalljails`. Supports compiled formulas via `f2b-expr::BanTimeIncrement` and multipliers list evaluation with boundary clamping.
- **Observer (`crates/f2b-action/src/observer.rs`)**:
  - `failure_found`: checks database for bad IPs, calculates exponential retry acceleration `retryCount = ((1 << count) / 2 + 1)`, and immediately triggers bans when retry threshold is reached.
  - `incr_ban_time`: retrieves previous bans from SQLite `bips` table across jail or all jails (`overalljails`), updates ticket ban count, and calculates dynamic ban time using compiled formula/multipliers.
  - `ban_found`: prolongs and adjusts ban time, logs notices matching fail2ban formatting, and persists ban records into database.
- **Database & Server Integration**:
  - `Fail2BanDb::get_ban` added in `crates/f2b-db/src/db.rs` to read from `bips` with `overalljails` grouping and time filters.
  - `Server` and `Transmitter` updated to handle `set <jail> bantime.<opt>` and `get <jail> bantime.<opt>` commands.
- **Verification Gate**:
  - Ported `fail2ban/tests/observertestcase.py` in `crates/f2b-action/tests/observer_tests.rs`:
    - `test_default_formula_and_options`: 24h default schedule `[1200, 2400, 4800, 9600, 19200, 38400, 76800, 86400, ...]`, 30d max time, factors 2 and float 1.33, 12h max time, randomization with `rndtime = 5m`.
    - `test_multipliers`: multiplier arrays (`1 2 4 8 16 32 64 128 256`) stopping growth at the last multiplier.
    - `test_custom_formula`: exponential formula with factor `2.0 / 2.885385` matching Python floating-point truncation.
    - `test_database_bantime_increment`: persistence-backed doubling ban times in SQLite and `overalljails` multi-jail tracking.
    - `test_observer_failure_found_bad_ip_acceleration`: bad IP retry count boost immediately triggering ban on 1st retry.
    - `test_boundary_count_20_21`: verified default formula clamps shift at `Count=20` (`1 << 20`) without growing further at `Count=21` and `Count=25`.
    - `test_python_differential_observer`: differential check invoking Python `fail2ban.server.observer.ObserverThread` and asserting identical numbers.

### Phase 7 — Optional backends & breadth
- systemd backend, `journalmatch` parsing, `formatJournalEntry` parity; `fail2ban-regex --journalmatch`.
- `jail.conf` stock jails end-to-end smoke (`sshd`, `apache-*`, `nginx-*`, `postfix`, `dovecot`, `recidive`) against canned logs in a container with real `iptables`/`nft` (Docker is available in the sandbox).
- Gate: smoke matrix green in CI.

**Phase 7 status: DONE except the real-firewall part of the gate.**
- **Daemon made real (prerequisite found while scoping the smoke test)**: `Transmitter` rewritten to the full `transmitter.py` surface (every `set`/`get` option incl. regex lists by index, `addlogpath`/`dellogpath`/`logencoding`, `ignore*`, `attempt`, `banip`/`unbanip`, `bantime.*`, `action` properties, `reload [--restart --unban --if-exists]` with begin/end semantics, `status` basic/short/stats/`--all`, `stats`, `banned`, `unban`); `Server` keeps every jail behind its own mutex (client commands for one jail are not blocked by a slow action of another); `AsyncServer::start_background` runs the runner thread (`Server::tick`, 100 ms) that reads logs, bans and unbans; log positions and the journal position are persisted in the database and resumed after a restart; restored bans re-run `actionban`; `ignoreself` uses the real interface addresses; DB `purgeage`/`maxmatches` are settable at runtime; daemon logging (`f2b-server::logging`) with upstream format, levels incl. NOTICE and targets STDOUT/STDERR/file/SYSLOG, `flushlogs` reopen.
- **systemd backend**: no libsystemd binding (none is available and none is needed): `f2b-backend::journal` runs `journalctl --output=export` and parses the export format (`parse_export`), `JournalMatches` mirrors `add/del/getJournalMatch` incl. libsystemd's match validation, `format_journal_entry` mirrors `formatJournalEntry`/`getJrnEntTime`, `JournalOptions` mirrors `_getJournalArgs`; `Backend::from_spec("systemd[journalflags=...]")`, `Jail` starts the reader at `max(stored position, now - findtime)`, restarts it when the matches change and revives it when `journalctl` dies. Because there is no native dependency there is no cargo feature; the runtime requirement is a `journalctl` in `PATH` (override: `F2B_JOURNALCTL`). `fail2ban-regex systemd-journal[...]` and `-m/--journalmatch` (also from `addjournalmatch` of a filter) work.
- **Verification**:
  - Journal module vs the real upstream `FilterSystemd` driven with a stubbed `systemd` module (`tools/dump_journal_oracle.py`): match management and `formatJournalEntry` incl. kernel entries, repeated/missing fields, non-UTF-8, pid conversions, TZ/DST edge instants, latin-1; export parser and reader against a fake `journalctl`.
  - **Stock-jail smoke matrix** (`crates/f2b-server/tests/stock_jails.rs`): 161 cases (every stock jail `sshd` (normal/aggressive), `apache-*`, `nginx-*`, `postfix`, `dovecot`, `recidive`, plus a synthetic jail for every other filter with samples) run through the real config → stream → daemon → filter → ban → action path; the expected banned set is taken from the **upstream Python daemon** running the identical config and log (`tools/gen_smoke_oracle.py` → `testdata/smoke-oracle/stock.json`), 161/161 identical; `unban` and `unbanip` also checked. 14 journal-only sample groups are skipped (file backend only).
  - `crates/f2b-action/tests/runtime_tests.rs` (journal jail incl. position resume and match restarts against a fake `journalctl`, persisted file positions, restored bans, unban by address/subnet/all, reload, idle) and `crates/f2b-server/tests/transmitter_tests.rs` (option round trips, status shapes, ban commands, reload).
- **Not verified / known differences**:
  - **Real firewall**: Docker has no daemon in this sandbox and iptables/nft are not installed; the smoke actions are the stock `dummy` action writing to a file. The "container with real iptables/nft" part of the gate is open (needs a CI job with Docker or a privileged runner).
  - **Real journal**: `journalctl` is not available here, so the exact `journalctl` command line (`--since=@..`, `--no-tail`, `--follow`, `--file/--directory/--namespace/--system/--user`) has only been checked against a fake. Journal timestamps use python-systemd 235 semantics (fixed UTC offset of the daemon start); `TimestampStyle::NaiveLocal` (<= 234) exists but is not selected.
  - `status <jail> cymru` is refused (needs DNS lookups); Python actions are a hard error (as decided); `ignorecache` is stored and reported but not implemented; `set thread` and `set allowipv6` are stored without effect; `inotify` is polled by the 100 ms runner (same as the polling backend); logs are decoded as UTF-8 or Latin-1 only.
  - Jails share one runner thread: an action command that hangs (up to its timeout, default 60 s) delays reading the logs of the other jails, although client commands for other jails stay responsive (per-jail mutex). Moving each jail to its own thread is a Phase 8 item.

### Phase 8 — Hardening, performance, packaging
- Profile hot path (`cargo flamegraph`, `criterion`); verify no per-line heap churn on non-matching lines; `RegexSet` prefilter effectiveness; tune channel sizes. Compare with the Phase 0 baseline and set pass/fail thresholds from measured numbers.
- Memory: bounded `mlfidCache`, ignore cache, failure maps; cap matches stored per ticket (`maxmatches`).
- Security review: command injection through `<matches>`/`<F-*>` in shell actions (upstream shell-quotes params via `WRAP_CMD_PARAMS`; replicate and test with hostile log lines), socket permissions, pickle decoder limits (depth/size caps), privilege model (drop caps where possible).
- Packaging: systemd unit, logrotate hook (`flushlogs`), man pages, completions, `fail2ban-*` symlinks, deb/rpm via `cargo-deb`/`cargo-generate-rpm`, migration doc (what differs, Python actions).
- Gate: full conformance suite + cross-compat + fuzz + soak (24 h replay of rotated logs, no leak, no missed bans vs upstream on identical input).

## 5. Verification strategy

Upstream is the oracle; never hand-write expected values when upstream can generate them.

| Layer | Oracle | Test |
|---|---|---|
| Config | `fail2ban-client -d` golden streams | per-tree diff test |
| Regex/filters | `failJSON` annotations (~1,215) | one parametrised test per `filter × sample`; `filterOptions` honoured |
| Dates | upstream-generated (line→epoch) JSON | table test, incl. tz/DST/year-rollover cases from `datedetectortestcase.py` |
| `str2seconds`/formula | upstream `MyTime.str2seconds`, `eval(formula)` on a generated input grid | property test: Rust == Python on the grid |
| DB | v1/v2 fixtures + Python round-trip | integration |
| Protocol | real Python client/server | cross-compat CI job, plus cargo-fuzz |
| Behaviour | ported unit scenarios with injectable `Clock` | `cargo test` |
| Perf | Phase 0 baseline | `criterion` + regression guard |

Tests must defend contracts, not wiring. Ported upstream tests are reviewed: Python-implementation-specific ones (threading internals, mocks of private attributes) are dropped, not translated.

## 6. Risk register

| Risk | Impact | Mitigation |
|---|---|---|
| `fancy-regex` can't express a stock pattern (`(?(_q)'|)` conditional, possible semantic drift vs Python `re`) | A stock filter fails to match | Phase 2 spike first; translator rewrite or scoped `pcre2` fallback; sample corpus is the gate |
| Backtracking engine on attacker-controlled log lines (ReDoS) | CPU DoS of the daemon itself | Fast path (linear) for ~all patterns; `fancy-regex` backtrack limit; per-line match budget; metric/log when exceeded |
| Pickle edge cases (protocol 5 framing, memoisation, `Exception` reduce shape) | Python client incompatibility | Cross-compat CI against real client; fuzz; capture real traffic as fixtures in Phase 0 |
| Config parser subtle behaviour (interpolation corner cases, include order, `%%`) | Silent misconfig → missed bans | `-d` golden diff across *all* stock + test configs |
| Shell exec semantics (process group kill, timeout, env, `sh -c` quoting, `<br>` handling) | Orphaned firewall commands / injection | Port `Utils.executeCmd` behaviour precisely; hostile-input tests |
| File tail races (rotation, truncate, partial lines, inode reuse) | Missed or duplicate failures | Port `FileContainer` logic literally; add rotation fuzz test with injectable fs events |
| Scope: Python actions, gamin | Users with custom `.py` actions | Explicit non-goal, load-time error naming the file, migration doc |
| Time source differences (monotonic vs wall, DST) | Wrong findtime/bantime | Single `Clock` trait; wall-clock for tickets (persisted), monotonic only for timers |
| `bantime.formula` expressiveness: users can write arbitrary Python | Unsupported formula | Documented grammar; load error shows unsupported token; survey of stock/doc'd formulas in upstream docs and `jail.conf` |

## 7. Working method (tooling)

- Port module-by-module: read upstream with `lsp`/`ast_grep` (symbols, callers), write Rust with `lsp` rename/references for refactors, `ast_edit` for mechanical codemods.
- Before changing any exported Rust symbol: `lsp references`. After each crate: `cargo fmt && cargo clippy -D warnings && cargo test -p <crate>`.
- Use `gh` for repo creation, issues per phase gate, PRs per crate; CI checks mirror §5.
- Parallelisable after Phase 0: `f2b-expr`, `f2b-date`, `f2b-db`, `f2b-proto` have no dependencies on each other; `f2b-config` and `f2b-regex` are independent until Phase 2 integration.

## 8. Open questions (defaults chosen; change if you disagree)

1. **Binary names** — default: `fast2ban-*`, symlinks `fail2ban-*` at packaging.
2. **Async runtime** — default: tokio; alternative std threads (closer to upstream, fewer deps). Hot path is sync either way.
3. **`pcre2` fallback** — default: only if `fancy-regex` fails the Phase 2 spike.
4. **Python actions** — default: unsupported, hard error.
5. **MSRV / platforms** — default: stable Rust, Linux first (inotify, systemd), BSD/macOS (polling, `kqueue`) after Phase 8.

## 9. Immediate next steps

1. Install Rust toolchain + `rust-analyzer`; `git init`; workspace skeleton + CI.
2. Write `tools/extract_fixtures.py` (samples, `-d` dumps, date pairs, protocol captures) and commit outputs.
3. Run upstream benchmark; record baseline in `docs/baseline.md`.
4. Spike (1 day, throwaway): compile all 104 stock filters' expanded failregexes with `regex` vs `fancy-regex`; report counts per engine and any failing pattern — resolves §3.1 before Phase 2 commits to it.
