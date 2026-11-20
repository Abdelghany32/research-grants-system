#!/usr/bin/env bash
# Verifies, in the RUNNING stack, that every process holds only the secrets its job needs:
#   web (front end)  - no actor key, no identity / audit-writer / notifier credential, no operator tools,
#                      and its own database password is refused every identity function (finding O01)
#   identity         - the actor key and its own credentials, nothing about the business data account
#   notifier         - one credential
# Evidence: docs/evidence/isolation.txt   (exit 1 when any check fails)
. "$(dirname "$0")/lib.sh"
load_secrets
OUT=docs/evidence/isolation.txt
R=0; F=0
ok()  { R=$((R+1)); printf 'PASS  %s\n' "$1"; }
bad() { F=$((F+1)); printf 'FAIL  %s\n' "$1"; }
check() { if eval "$2" >/dev/null 2>&1; then ok "$1"; else bad "$1"; fi; }
names() { dc exec -T "$1" sh -c 'env | cut -d= -f1 | sort | tr "\n" " "'; }
{
echo "PROCESS ISOLATION - $(date -u +%Y-%m-%dT%H:%M:%SZ) (UTC)"
echo; echo "== web front end"
echo "environment variable names: $(names web)"
for v in ACTOR_KEY_FILE AUDIT_WRITER_DB_PASSWORD IDENTITY_DB_PASSWORD NOTIFIER_DB_PASSWORD BACKUP_DB_PASSWORD POSTGRES_PASSWORD; do
  check "web has no $v" "! dc exec -T web sh -c 'env | grep -q \"^$v=\"'"
done
check "web has IDENTITY_MODE=remote" "dc exec -T web sh -c 'test \"\$IDENTITY_MODE\" = remote'"
for f in /run/grants/actor.key /run/grants/demo-totp.txt /run/grants/demo-credentials.txt /srv/grants/tests /srv/grants/scripts /srv/grants/database /srv/grants/identity; do
  check "web has no $f" "! dc exec -T web test -e $f"
done
echo "-- the web account's own database password, from inside the web container:"
for q in "SELECT * FROM auth_find_credentials('amina.elidrissi@uni.example')" "SELECT password_hash FROM users" "SELECT * FROM identity_sessions" "SELECT * FROM mfa_recovery_codes" "SELECT * FROM webauthn_credentials" "SELECT * FROM webauthn_list(1)" "SELECT * FROM actor_key"; do
  r=$(dc exec -T -e Q="$q" web php -r '
    try { $p = new PDO("pgsql:host=db;dbname=grants;sslmode=verify-full;sslrootcert=/run/grants/db-ca.crt", "grants_app", getenv("APP_DB_PASSWORD"), [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
          $p->query(getenv("Q")); echo "OK"; } catch (PDOException $e) { echo "REFUSED ", $e->getCode(); }')
  [ "$r" = "REFUSED 42501" ] && ok "web account refused: $q" || bad "web account NOT refused ($r): $q"
done

echo; echo "== identity service"
echo "environment variable names: $(names identity)"
check "identity holds the actor key" "dc exec -T identity test -r /run/grants/actor.key"
for v in APP_DB_PASSWORD AUDITOR_DB_PASSWORD NOTIFIER_DB_PASSWORD BACKUP_DB_PASSWORD; do
  check "identity has no $v" "! dc exec -T identity sh -c 'env | grep -q \"^$v=\"'"
done
for f in /srv/grants/public /srv/grants/templates /srv/grants/tests /srv/grants/scripts /srv/grants/database; do
  check "identity has no $f" "! dc exec -T identity test -e $f"
done
check "identity is not published on the host" "[ -z \"\$(dc port identity 8081 2>/dev/null)\" ]"
check "identity answers the web container (internal network)" "dc exec -T web php -r 'exit(@fsockopen(\"identity\", 8081) ? 0 : 1);'"
check "identity does not answer the host" "! curl -s --max-time 2 http://localhost:8081/health"
check "a call without a valid signature is refused (HTTP 401)" "[ \"\$(dc exec -T web php -r '\$c=curl_init(\"http://identity:8081/v1/call\"); curl_setopt_array(\$c,[CURLOPT_POST=>1,CURLOPT_POSTFIELDS=>\"{}\",CURLOPT_RETURNTRANSFER=>1]); curl_exec(\$c); echo curl_getinfo(\$c,CURLINFO_RESPONSE_CODE);')\" = 401 ]"

echo; echo "== notifier"
echo "environment variable names: $(names notifier)"
check "notifier has only its own credential" "dc exec -T notifier sh -c 'env | grep -q \"^NOTIFIER_DB_PASSWORD=\" && ! env | grep -qE \"^(APP_DB|AUDITOR_DB|IDENTITY_DB|AUDIT_WRITER_DB|IDENTITY_API_KEY)\"'"
check "notifier has no key files" "! dc exec -T notifier test -e /run/grants/actor.key && ! dc exec -T notifier test -e /run/grants/field.key"

echo; echo "== operator container"
if dc --profile ops ps --status running --services 2>/dev/null | grep -qx ops; then
  echo "NOTE  the operator container 'ops' is running: it holds every secret for tests and labs and must not exist in production (docker compose --profile ops down)"
else
  ok "no operator container is running"
fi
echo; echo "SUMMARY: $R checks passed, $F failed"
[ "$F" -eq 0 ]
} 2>&1 | tee "$OUT"
exit "${PIPESTATUS[0]}"
