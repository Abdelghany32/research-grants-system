#!/usr/bin/env bash
# Create or update one database from the SQL scripts in database/
# (order: 00 database, 02 schema, 03 RLS, 05 remediation F01-F04, 06 identity binding + audit,
#  07 review deadlines, 08 MFA, 09 notifications, 10 identity split, 04 grants).
#   scripts/db-apply.sh grants            create if missing, re-apply roles and grants
#   scripts/db-apply.sh grants --reset    DROP and rebuild (all data in it is lost)
. "$(dirname "$0")/lib.sh"
DB="${1:?usage: db-apply.sh <database> [--reset]}"; valid_db_name "$DB"
load_secrets

psql_admin postgres < database/01_roles.sql
psql_admin postgres < database/12_pgaudit.sql

# Keep the live pg_hba.conf identical to the versioned file (it is only copied at first initialisation).
dc exec -T -u postgres db sh -c 'cmp -s /etc/grants-db/pg_hba.conf "$PGDATA/pg_hba.conf" || { cp /etc/grants-db/pg_hba.conf "$PGDATA/pg_hba.conf" && psql -X -q -c "SELECT pg_reload_conf()" >/dev/null; }'

if [ "${2:-}" = "--reset" ]; then
  psql_admin postgres -c "DROP DATABASE IF EXISTS $DB WITH (FORCE)"
fi

if ! db_exists "$DB"; then
  psql_admin postgres -c "CREATE DATABASE $DB OWNER grants_owner TEMPLATE template0 ENCODING 'UTF8'"
  psql_admin "$DB" < database/00_database.sql
  psql_admin "$DB" < database/02_schema.sql
  psql_admin "$DB" < database/03_rls.sql
  psql_admin "$DB" < database/05_remediation.sql
  psql_admin "$DB" < database/06_identity_and_audit.sql
  psql_admin "$DB" < database/07_review_deadlines.sql
  psql_admin "$DB" < database/08_mfa.sql
  psql_admin "$DB" < database/09_notifications.sql
  psql_admin "$DB" < database/10_identity_split.sql
  psql_admin "$DB" < database/11_webauthn.sql
  psql_admin "$DB" < database/04_grants.sql
  echo "database $DB created"
else
  # Existing database: bring it to the current release (idempotent), then re-apply privileges.
  psql_admin "$DB" < database/00_database.sql
  psql_admin "$DB" < database/05_remediation.sql
  psql_admin "$DB" < database/06_identity_and_audit.sql
  psql_admin "$DB" < database/07_review_deadlines.sql
  psql_admin "$DB" < database/08_mfa.sql
  psql_admin "$DB" < database/09_notifications.sql
  psql_admin "$DB" < database/10_identity_split.sql
  psql_admin "$DB" < database/11_webauthn.sql
  psql_admin "$DB" < database/04_grants.sql
  echo "database $DB already exists: remediation functions and privileges re-applied, data untouched"
fi
