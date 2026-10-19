# Upstream performance baseline (Phase 0)

Single-threaded `Filter.processLine` throughput of upstream Fail2Ban `1.1.2.dev1` on CPython 3.14.4,
aarch64 sandbox VM (8 vCPU). Measured with `tools/bench_baseline.py` (best of 5 rounds; run-to-run
variance observed ~10%). Config: stock filters, sample-corpus lines x20, `matched` > 0 verified.

| filter | lines | matched | lines/sec |
|---|---|---|---|
| sshd | 3180 | 1340 | ~82k-92k |
| apache-auth | 900 | 720 | ~138k-146k |
| nginx-http-auth | 360 | 160 | ~143k-150k |
| postfix | 1260 | 660 | ~102k-111k |

Peak RSS of the benchmark process: ~360 MiB (includes interpreter and imports of the whole package).

Scope: this isolates regex + date detection. It excludes file reading, failure manager, ban
actions and DB. Phase 8 targets are set relative to these numbers on the same hardware.

Reproduce: `python3 tools/bench_baseline.py`
