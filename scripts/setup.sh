#!/usr/bin/env bash
# One-command local setup. Safe to re-run: existing secrets and data are kept.
#   scripts/setup.sh
. "$(dirname "$0")/lib.sh"
umask 077
mkdir -p secrets/tls logs backups
: >> logs/php-error.log; : >> logs/app-error.log          # exists before Docker bind-mounts it into the log shipper (else Docker would create a directory)

# --- 1. Local secrets (never committed; see .gitignore) -----------------------
[ -s secrets/postgres_password ] || openssl rand -hex 24 > secrets/postgres_password
[ -s secrets/web.env ] || printf 'APP_DB_PASSWORD=%s\nAUDITOR_DB_PASSWORD=%s\n' \
    "$(openssl rand -hex 24)" "$(openssl rand -hex 24)" > secrets/web.env
ensure_secrets    # audit-writer and notifier passwords, actor-binding key
[ -s secrets/backup.env ] || printf 'BACKUP_DB_PASSWORD=%s\n' "$(openssl rand -hex 24)" > secrets/backup.env
# 256-bit key for the encrypted review comments. Kept apart from the database.
[ -s secrets/field.key ] || openssl rand -base64 32 > secrets/field.key
[ -s secrets/tls/server.key ] || openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    -keyout secrets/tls/server.key -out secrets/tls/server.crt 2>/dev/null
if [ ! -s secrets/demo-credentials.txt ]; then
  tail -n +2 database/seed_users.tsv | cut -f1 | while read -r email; do
    printf '%s\t%s\n' "$email" "$(openssl rand -base64 15 | tr '+/' '-_')"
  done > secrets/demo-credentials.txt
fi
[ -e secrets/db-ca.crt ] || : > secrets/db-ca.crt
# The db container reads its bootstrap password as root; the rest stay 0600.
chmod 600 secrets/*.env secrets/field.key secrets/tls/server.key secrets/demo-credentials.txt

# Build the application image first: the web front end, the identity service, the notifier and the operator
# container all use it.
dc build web

# --- 2. Database first, then export its TLS certificate for the web service ---
dc up -d --build --wait db
dc exec -T -u postgres db sh -c 'cat "$PGDATA/server.crt"' > secrets/db-ca.crt

# --- 3. Roles, schema, policies, privileges ------------------------------------
scripts/db-apply.sh grants

# --- 4. Web service -------------------------------------------------------------
dc up -d --build web notifier logship      # web starts the identity service first (dependency)
for _ in $(seq 1 30); do
  curl -ksf -o /dev/null "https://localhost:${HTTPS_PORT:-8443}/login" && break
  sleep 1
done

# --- 5. Demo data (first run only) ----------------------------------------------
load_secrets
if [ "$(psql_admin grants -Atc 'SELECT count(*) FROM grants.users')" = "0" ]; then
  scripts/seed.sh grants
fi

echo
echo "Application : https://localhost:${HTTPS_PORT:-8443}  (self-signed certificate: accept the browser warning)"
echo "Demo logins : secrets/demo-credentials.txt  (generated locally, not in Git)"
echo "Tests       : scripts/test.sh"
