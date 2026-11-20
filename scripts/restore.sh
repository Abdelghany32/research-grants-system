#!/usr/bin/env bash
# Restore an encrypted backup into a SEPARATE database (never over "grants").
#   scripts/restore.sh backups/grants-....dump.gpg [grants_restore|grants_drill]
# Order matters: roles are cluster-wide and not inside the archive, so the role
# script runs first; then the database and its connection rules; then the data.
. "$(dirname "$0")/lib.sh"
FILE="${1:?usage: restore.sh <backup.dump.gpg> [target-database]}"
TARGET="${2:-grants_restore}"; valid_db_name "$TARGET"
[ "$TARGET" != "grants" ] || { echo "refusing to restore over the live database" >&2; exit 2; }
load_secrets
export GNUPGHOME="$PWD/secrets/gnupg"
T0=$(date +%s.%N)

sha256sum --check --quiet "$FILE.sha256"                       # the archive is the one we wrote
psql_admin postgres < database/01_roles.sql 2>/dev/null        # 1. roles (idempotent)
psql_admin postgres -c "DROP DATABASE IF EXISTS $TARGET WITH (FORCE)" 2>/dev/null
psql_admin postgres -c "CREATE DATABASE $TARGET OWNER grants_owner TEMPLATE template0 ENCODING 'UTF8'"
psql_admin "$TARGET" < database/00_database.sql                # 2. who may connect
mapfile -t UNLOCK < <(gpg_unlock_opts)
gpg --list-secret-keys --batch >/dev/null 2>&1 || { echo "the backup private key is not on this host: scripts/backup-key.sh import <file>" >&2; exit 2; }
gpg --batch --quiet "${UNLOCK[@]}" --decrypt "$FILE" \
  | dc exec -T -u postgres db pg_restore --exit-on-error -d "$TARGET"   # 3. schema, data, privileges, policies

T1=$(date +%s.%N)
printf 'restored %s into %s in %.1f seconds\n' "$FILE" "$TARGET" "$(echo "$T1 - $T0" | bc)"
