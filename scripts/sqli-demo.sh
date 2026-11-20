#!/usr/bin/env bash
# Controlled SQL-injection lab (Phase 4/5): before / impact / root cause / fix / same test after.
# Runs only against the disposable grants_test database. Evidence: docs/evidence/sqli-demo.txt
. "$(dirname "$0")/lib.sh"
load_secrets
db_exists grants_test || { echo "grants_test missing: run scripts/test.sh first" >&2; exit 2; }
mkdir -p docs/evidence
ops_run -e DB_NAME=grants_test -e PENTEST_LAB=1 ops php scripts/sqli-demo.php | tee docs/evidence/sqli-demo.txt
exit "${PIPESTATUS[0]}"
