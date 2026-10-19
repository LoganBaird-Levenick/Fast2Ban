#!/bin/sh
# Regenerate every golden fixture from the upstream Python checkout in ./fail2ban.
# Output is deterministic: a clean `git diff testdata/` after running means fixtures are current.
set -eu
cd "$(dirname "$0")/.."
rm -rf testdata/config-oracle testdata/samples
python3 tools/dump_oracle.py
python3 tools/extract_samples.py
python3 tools/dump_expanded_regex.py
python3 tools/gen_f2b_config_fuzz.py
python3 tools/gen_f2b_helpers_fixtures.py
python3 tools/gen_f2b_types_fixtures.py
python3 tools/gen_f2b_expr_fixtures.py
python3 tools/gen_f2b_regex_fixtures.py
python3 tools/gen_f2b_date_fixtures.py
python3 tools/gen_f2b_filter_fixtures.py
python3 tools/gen_fast2ban_regex_fixtures.py
# systemd journal backend (stubbed `systemd` module, real FilterSystemd); writes
# crates/f2b-backend/tests/fixtures/ (check `git diff crates/f2b-backend/tests/fixtures`)
python3 tools/dump_journal_oracle.py
# stock-jails smoke matrix: bans of the real upstream daemon per sample group
# (runs ~130 Python daemons, about a minute); writes testdata/smoke-oracle/stock.json
python3 tools/gen_smoke_oracle.py
