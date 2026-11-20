#!/usr/bin/env bash
# Full verification suite. Rebuilds the grants_test database from the SQL
# scripts, seeds it, then runs every test as the restricted accounts.
#   scripts/test.sh            all tests
#   scripts/test.sh RLS        only tests whose name contains "RLS"
. "$(dirname "$0")/lib.sh"
load_secrets
scripts/db-apply.sh grants_test --reset >/dev/null
scripts/seed.sh grants_test >/dev/null
psql_admin grants_test < tests/fixtures.sql
mkdir -p docs/evidence
set +e
{
  ops_run -e DB_NAME=grants_test ops php tests/run.php "$@"
  status=$?
  # Backstop triggers and constraints, exercised as the schema owner (see the file header).
  if [ $# -eq 0 ] || [[ "OWNER" == *"$1"* ]]; then
    echo "--- owner_guards.sql"
    psql_admin grants_test -At < tests/owner_guards.sql || status=1
  fi
  echo "exit code: $status"
  exit "$status"
} | tee docs/evidence/test-results.txt
status=${PIPESTATUS[0]}
exit "$status"
