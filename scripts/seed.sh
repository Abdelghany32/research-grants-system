#!/usr/bin/env bash
# Load the fictional demo users and walk demo proposals through the real workflow.
. "$(dirname "$0")/lib.sh"
DB="${1:-grants}"; valid_db_name "$DB"
load_secrets

if [ "$(psql_admin "$DB" -Atc 'SELECT count(*) FROM grants.users')" != "0" ]; then
  echo "$DB already has users; run 'scripts/db-apply.sh $DB --reset' first to reseed." >&2
  exit 1
fi

# Passwords are hashed by PHP in the web container; only the hashes reach
# PostgreSQL. COPY loads the rows as data, so no SQL is assembled from text.
ops_run ops php scripts/seed_users.php \
  | psql_admin "$DB" -c "SET ROLE grants_owner" \
      -c "\copy grants.users (email, full_name, department, role, password_hash) FROM pstdin WITH (FORMAT csv)"

ops_run -e DB_NAME="$DB" ops php scripts/seed_workflow.php

# Two-step sign-in for the demo officers and auditor; the secrets are shared by every database and kept in
# secrets/demo-totp.txt (never committed). Use scripts/totp.py <e-mail> for the current code.
libsecret=secrets/demo-totp.txt
# Written IN PLACE (cat >, not mv): the file is bind-mounted into the web container, and a replaced file would
# leave the container looking at the old one.
( umask 077; new=$(mktemp); ops_run -e DB_NAME="$DB" ops php scripts/seed_mfa.php > "$new" && cat "$new" > "$libsecret"; rm -f "$new" )
