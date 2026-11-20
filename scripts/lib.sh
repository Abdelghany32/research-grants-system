# Shared helpers for the scripts in this directory. Source it, do not run it.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export APP_UID="${APP_UID:-$(id -u)}"

dc() { docker compose "$@"; }

# Secrets are split by who may hold them. Existing installations are upgraded in place and nothing existing is
# regenerated; secrets that a process must NOT hold are moved out of its file:
#   secrets/web.env       the web front end: APP_DB_PASSWORD, AUDITOR_DB_PASSWORD, IDENTITY_API_KEY
#   secrets/identity.env  the identity service: IDENTITY_DB_PASSWORD, AUDIT_WRITER_DB_PASSWORD, IDENTITY_API_KEY
#   secrets/notifier.env  the notifier: NOTIFIER_DB_PASSWORD
#   secrets/actor.key     the actor-binding key: identity service only
env_get() { sed -n "s/^$2=//p" "$1" 2>/dev/null | head -1; }
env_drop() { local f="$1" v="$2"; { grep -v "^$v=" "$f" || true; } > "$f.tmp"; mv "$f.tmp" "$f"; }
env_put() { env_drop "$1" "$2"; printf '%s=%s\n' "$2" "$3" >> "$1"; }
ensure_secrets() {
  mkdir -p secrets
  ( umask 077
    touch secrets/web.env secrets/identity.env secrets/notifier.env
    local v
    v=$(env_get secrets/web.env AUDIT_WRITER_DB_PASSWORD); [ -z "$v" ] || { env_put secrets/identity.env AUDIT_WRITER_DB_PASSWORD "$v"; env_drop secrets/web.env AUDIT_WRITER_DB_PASSWORD; }
    v=$(env_get secrets/web.env NOTIFIER_DB_PASSWORD);     [ -z "$v" ] || { env_put secrets/notifier.env NOTIFIER_DB_PASSWORD "$v"; env_drop secrets/web.env NOTIFIER_DB_PASSWORD; }
    [ -n "$(env_get secrets/identity.env AUDIT_WRITER_DB_PASSWORD)" ] || env_put secrets/identity.env AUDIT_WRITER_DB_PASSWORD "$(openssl rand -hex 24)"
    [ -n "$(env_get secrets/identity.env IDENTITY_DB_PASSWORD)" ]     || env_put secrets/identity.env IDENTITY_DB_PASSWORD "$(openssl rand -hex 24)"
    [ -n "$(env_get secrets/notifier.env NOTIFIER_DB_PASSWORD)" ]     || env_put secrets/notifier.env NOTIFIER_DB_PASSWORD "$(openssl rand -hex 24)"
    v=$(env_get secrets/identity.env IDENTITY_API_KEY); [ -n "$v" ] || v=$(openssl rand -hex 32)
    env_put secrets/identity.env IDENTITY_API_KEY "$v"; env_put secrets/web.env IDENTITY_API_KEY "$v"
    [ -s secrets/actor.key ] || openssl rand -hex 32 > secrets/actor.key
    [ -e secrets/demo-totp.txt ] || : > secrets/demo-totp.txt
    chmod 600 secrets/web.env secrets/identity.env secrets/notifier.env secrets/actor.key secrets/demo-totp.txt )
}

load_secrets() {
  ensure_secrets
  set -a
  # shellcheck disable=SC1091
  . ./secrets/web.env
  . ./secrets/identity.env
  . ./secrets/notifier.env
  . ./secrets/backup.env
  ACTOR_KEY="$(cat secrets/actor.key)"
  set +a
}

# The operator tool container: holds EVERY secret and the whole repository, so the tests, the seed scripts, the labs
# and the drills can run. It is not a service (profile "ops"): the web front end and the identity service never
# receive what only the operator needs. Remove it with: docker compose --profile ops down
ops_up() { docker compose --profile ops up -d --no-recreate ops >/dev/null 2>&1; }
# Run a command in the operator container as the application user:  ops_run [-e VAR=value ...] ops php scripts/x.php
ops_run() { ops_up; docker compose exec -T -u grantsweb "$@"; }

# psql as the cluster administrator: OS user "postgres" inside the db
# container, peer-authenticated over the local socket (no password, no network).
# Role passwords travel as environment variables, never as command-line text.
psql_admin() {
  local db="$1"; shift
  dc exec -T -u postgres -e APP_DB_PASSWORD -e AUDITOR_DB_PASSWORD -e BACKUP_DB_PASSWORD \
     -e AUDIT_WRITER_DB_PASSWORD -e NOTIFIER_DB_PASSWORD -e IDENTITY_DB_PASSWORD -e ACTOR_KEY \
     db psql -X -q -v ON_ERROR_STOP=1 -d "$db" "$@"
}

db_exists() {
  [ "$(psql_admin postgres -Atc "SELECT 1 FROM pg_database WHERE datname = '$1'")" = "1" ]
}

valid_db_name() {
  case "$1" in grants|grants_test|grants_restore|grants_drill) ;; *) echo "unknown database: $1" >&2; exit 2 ;; esac
}

# GnuPG options that unlock the backup private key when a passphrase file exists
# (see scripts/backup-key.sh). Empty when the lab key has no passphrase.
gpg_unlock_opts() {
  if [ -s secrets/gpg-passphrase ]; then printf '%s\n' --pinentry-mode loopback --passphrase-file secrets/gpg-passphrase; fi
}
