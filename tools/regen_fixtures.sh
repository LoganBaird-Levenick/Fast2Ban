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
