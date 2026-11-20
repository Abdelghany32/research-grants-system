#!/usr/bin/env bash
# Collects psql and configuration evidence into docs/evidence/.
#   privileges.txt        roles, memberships, grants, policies, and the same
#                         operations attempted under each restricted account
#   hardening.txt         before (untouched images) vs after (this project)
. "$(dirname "$0")/lib.sh"
load_secrets
mkdir -p docs/evidence

# ------------------------------------------------------------------ privileges
{
echo "DATABASE ROLES AND PRIVILEGES - $(date -u +%Y-%m-%dT%H:%M:%SZ) (UTC), $(psql_admin grants -Atc 'SELECT version()' | cut -d' ' -f1-2)"
echo; echo '== \du  (role attributes and memberships)'
psql_admin grants -c '\du grants_*'
echo '== \dn+ grants  (schema ownership and access)'
psql_admin grants -c '\dn+ grants'
echo '== \dp grants.*  (table and column privileges; RLS policies)'
psql_admin grants -c '\dp grants.*'
echo '== Who owns what; which tables have RLS'
psql_admin grants -c "SELECT c.relname, pg_get_userbyid(c.relowner) AS owner, c.relkind, c.relrowsecurity AS rls, c.relforcerowsecurity AS forced
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'grants' AND c.relkind IN ('r','v') ORDER BY 1"
echo '== Database-level access'
psql_admin grants -c "SELECT datname, datacl FROM pg_database WHERE datname LIKE 'grants%' ORDER BY 1"

echo '== Operations attempted under the real restricted accounts'
try() {  # try <account> <password-env> <sql>   (over TLS from the web container, exactly like the application)
  printf '%-15s %-78s => ' "$1" "$3"
  dc exec -T -e PGPASSWORD="${!2}" -e Q="$3" web php -r '
    try { $p = new PDO("pgsql:host=db;dbname=grants;sslmode=verify-full;sslrootcert=/run/grants/db-ca.crt", $argv[1], getenv("PGPASSWORD"), [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
          $s = $p->query(getenv("Q")); echo "OK (", $s->columnCount() ? "value: " . json_encode($s->fetchColumn()) : $s->rowCount() . " rows", ")\n"; }
    catch (PDOException $e) { echo "REFUSED ", preg_replace("/\s+/", " ", substr($e->getMessage(), 0, 95)), "\n"; }' "$1"
}
try grants_app APP_DB_PASSWORD "SELECT count(*) FROM proposals  -- no actor set"
try grants_app APP_DB_PASSWORD "SELECT count(*) FROM users"
try grants_app APP_DB_PASSWORD "SELECT password_hash FROM users LIMIT 1"
try grants_app APP_DB_PASSWORD "SELECT count(*) FROM audit_events"
try grants_app APP_DB_PASSWORD "DELETE FROM audit_events"
try grants_app APP_DB_PASSWORD "UPDATE decisions SET awarded_amount = 0"
try grants_app APP_DB_PASSWORD "UPDATE users SET role = 'officer'"
try grants_app APP_DB_PASSWORD "CREATE TABLE grants.t (x int)"
try grants_app APP_DB_PASSWORD "ALTER TABLE proposals DISABLE ROW LEVEL SECURITY"
try grants_app APP_DB_PASSWORD "SELECT * FROM auth_find_credentials('amina.elidrissi@uni.example')"
try grants_identity IDENTITY_DB_PASSWORD "SELECT count(*) FROM auth_find_credentials('amina.elidrissi@uni.example')"
try grants_identity IDENTITY_DB_PASSWORD "SELECT count(*) FROM proposals"
try grants_identity IDENTITY_DB_PASSWORD "SELECT * FROM actor_key"
try grants_audit_write AUDIT_WRITER_DB_PASSWORD "SELECT count(*) FROM users"
try grants_notifier NOTIFIER_DB_PASSWORD "SELECT count(*) FROM notifications"
try grants_notifier NOTIFIER_DB_PASSWORD "SELECT password_hash FROM users LIMIT 1"
try grants_auditor AUDITOR_DB_PASSWORD "SELECT count(*) FROM audit_timeline"
try grants_auditor AUDITOR_DB_PASSWORD "SELECT count(*) FROM proposals"
try grants_auditor AUDITOR_DB_PASSWORD "SELECT count(*) FROM audit_events"
try grants_auditor AUDITOR_DB_PASSWORD "DELETE FROM audit_timeline"
try grants_backup BACKUP_DB_PASSWORD "SELECT 1  -- over the network"
printf '%-15s %-78s => ' grants_backup "SELECT count(*) FROM proposals  -- local socket, as pg_dump connects"
dc exec -T -e PGPASSWORD="$BACKUP_DB_PASSWORD" db psql -U grants_backup -d grants -XAtc "SELECT 'OK (value: ' || count(*) || ')' FROM grants.proposals"
printf '%-15s %-78s => ' grants_backup "DELETE FROM proposals  -- local socket"
dc exec -T -e PGPASSWORD="$BACKUP_DB_PASSWORD" db psql -U grants_backup -d grants -XAtc "DELETE FROM grants.proposals" 2>&1 | sed 's/^ERROR: */REFUSED /' || true
echo; echo '== Even the schema owner cannot rewrite the audit trail (trigger), shown in a rolled-back transaction'
psql_admin grants -c "BEGIN" -c "SET ROLE grants_owner" -c "DELETE FROM grants.audit_events WHERE id = 1" -c "ROLLBACK" 2>&1 | grep -E 'ERROR|DELETE' || true
psql_admin grants -c "BEGIN" -c "SET ROLE grants_owner" -c "TRUNCATE grants.audit_events" -c "ROLLBACK" 2>&1 | grep -E 'ERROR|TRUNCATE' || true
echo; echo '== Revocation demonstrated in a rolled-back transaction (nothing is changed)'
psql_admin grants -c "BEGIN" \
  -c "SELECT has_table_privilege('grants_app', 'grants.decisions', 'INSERT') AS app_may_insert_decisions_f01_never, has_function_privilege('grants_app', 'grants.record_decision(bigint,text,numeric,text,uuid,inet)', 'EXECUTE') AS app_may_call_record_decision" \
  -c "SELECT has_table_privilege('grants_app', 'grants.proposals', 'INSERT') AS app_may_insert_proposals_before" \
  -c "REVOKE INSERT ON grants.proposals FROM grants_runtime" \
  -c "SELECT has_table_privilege('grants_app', 'grants.proposals', 'INSERT') AS after_revoke_from_group" \
  -c "REVOKE grants_runtime FROM grants_app" \
  -c "SELECT has_table_privilege('grants_app', 'grants.proposals', 'SELECT') AS app_may_read_proposals_after_losing_membership" \
  -c "ROLLBACK" 2>&1 | grep -v '^$'
} > docs/evidence/privileges.txt 2>&1

# ------------------------------------------------------------------- hardening
pg_settings="SELECT name, setting FROM pg_settings WHERE name IN ('listen_addresses','ssl','ssl_min_protocol_version','password_encryption','log_connections','log_disconnections','log_statement','log_lock_waits','data_checksums','row_security') ORDER BY 1"
{
echo "HARDENING: BEFORE (untouched images) vs AFTER (this project) - $(date -u +%Y-%m-%dT%H:%M:%SZ) (UTC)"
echo; echo '######## BEFORE: postgres:18 started with defaults (throw-away container)'
docker rm -f grants-baseline >/dev/null 2>&1 || true
docker run -d --name grants-baseline -e POSTGRES_PASSWORD=baseline postgres:18 >/dev/null
for _ in $(seq 1 40); do docker exec grants-baseline pg_isready -q -h 127.0.0.1 2>/dev/null && break; sleep 1; done; sleep 2
docker exec -u postgres grants-baseline psql -X -c "$pg_settings"
echo '-- pg_hba.conf (active lines)'; docker exec grants-baseline sh -c 'grep -vE "^\s*(#|$)" "$PGDATA/pg_hba.conf"'
echo '-- login roles'; docker exec -u postgres grants-baseline psql -X -c "SELECT rolname, rolsuper, rolbypassrls, rolcanlogin FROM pg_roles WHERE rolcanlogin ORDER BY 1"
echo '-- PUBLIC may connect to a new database?'; docker exec -u postgres grants-baseline psql -X -Atc "SELECT has_database_privilege('public', 'postgres', 'CONNECT')"
docker rm -f grants-baseline >/dev/null
echo; echo '######## BEFORE: php:8.5-apache with defaults'
docker run --rm php:8.5-apache sh -c 'echo "-- loaded Apache modules: $(apache2ctl -M 2>/dev/null | grep -c _module)"; apache2ctl -M 2>/dev/null | grep -E "autoindex|status|ssl|headers" | tr "\n" " "; echo;
  echo "-- php.ini present: $(ls /usr/local/etc/php/php.ini 2>/dev/null || echo none)"; php -i | grep -E "^(expose_php|display_errors|allow_url_fopen|session.use_strict_mode|session.cookie_httponly|session.cookie_samesite) ";
  echo "-- worker user: $(. /etc/apache2/envvars 2>/dev/null; echo $APACHE_RUN_USER)"; grep -hE "^(ServerTokens|ServerSignature|TraceEnable)" /etc/apache2/conf-enabled/*.conf'

echo; echo '######## AFTER: grants-db'
psql_admin postgres -c "$pg_settings"
echo '-- pg_hba.conf (active lines)'; dc exec -T db sh -c 'grep -vE "^\s*(#|$)" "$PGDATA/pg_hba.conf"'
echo '-- login roles'; psql_admin postgres -c "SELECT rolname, rolsuper, rolbypassrls, rolcanlogin, rolconnlimit FROM pg_roles WHERE rolcanlogin ORDER BY 1"
echo '-- PUBLIC may connect to grants?'; psql_admin postgres -Atc "SELECT has_database_privilege('public', 'grants', 'CONNECT')"
echo '-- PUBLIC may use schema public in grants?'; psql_admin grants -Atc "SELECT has_schema_privilege('public', 'public', 'USAGE')"
echo '-- superuser over the network (password is set, but pg_hba has no network line for it):'
dc exec -T web php -r 'try { new PDO("pgsql:host=db;dbname=postgres;sslmode=require", "postgres", "x"); } catch (PDOException $e) { echo "  ", preg_replace("/\s+/", " ", substr($e->getMessage(), 0, 130)), "\n"; }'
echo '-- connection without TLS:'
dc exec -T -e PGPASSWORD="$APP_DB_PASSWORD" web php -r 'try { new PDO("pgsql:host=db;dbname=grants;sslmode=disable", "grants_app", getenv("PGPASSWORD")); echo "  ACCEPTED\n"; } catch (PDOException $e) { echo "  ", preg_replace("/\s+/", " ", substr($e->getMessage(), 0, 130)), "\n"; }'
echo '-- TLS in use by the application connection:'
dc exec -T -e PGPASSWORD="$APP_DB_PASSWORD" web php -r '$p = new PDO("pgsql:host=db;dbname=grants;sslmode=verify-full;sslrootcert=/run/grants/db-ca.crt", "grants_app", getenv("PGPASSWORD")); echo "  ", json_encode($p->query("SELECT ssl, version, cipher FROM pg_stat_ssl WHERE pid = pg_backend_pid()")->fetch(PDO::FETCH_ASSOC)), "\n";'
echo '-- file permissions inside PGDATA'; dc exec -T db sh -c 'stat -c "%A %U %n" "$PGDATA" "$PGDATA/server.key" "$PGDATA/pg_hba.conf"'
echo '-- published ports (db has none; web is loopback only)'; dc ps --format '{{.Service}}: {{.Ports}}'
echo '-- sample of the connection log'; dc exec -T logship php /srv/ship/logship.php export 2026-01-01 db 2>&1 | grep -E 'connection authorized|FATAL' | tail -4 | cut -c1-200

echo; echo '######## AFTER: grants-web'
dc exec -T web sh -c 'echo "-- loaded Apache modules: $(apache2ctl -M 2>/dev/null | grep -c _module)"; apache2ctl -M 2>/dev/null | grep -E "autoindex|status|ssl|headers" | tr "\n" " "; echo;
  php -i | grep -E "^(expose_php|display_errors|allow_url_fopen|session.use_strict_mode|session.cookie_httponly|session.cookie_samesite) ";
  echo "-- worker user: $APACHE_RUN_USER (uid $(id -u $APACHE_RUN_USER))"; grep -hE "^(ServerTokens|ServerSignature|TraceEnable)" /etc/apache2/sites-enabled/*.conf;
  echo "-- code mounted read-only: $(touch /srv/grants/src/x 2>&1 | grep -o "Read-only file system")"; echo "-- session directory: $(stat -c "%A %U" /var/lib/grants/sessions)"'
echo '-- response headers over HTTPS'; curl -ksI https://localhost:8443/login | grep -iE '^(HTTP|server|strict-transport|content-security|x-content-type|x-frame|referrer|cache-control|set-cookie|x-powered)'
echo '-- plain HTTP only redirects'; curl -sI http://localhost:8080/login | grep -iE '^(HTTP|location)'
echo '-- TLS protocol check'; for v in tls1_1 tls1_2 tls1_3; do printf '  %s: ' $v; (echo | openssl s_client -connect localhost:8443 -$v 2>&1 | grep -qE 'Cipher is [A-Z0-9]' && echo accepted) || echo refused; done
echo '-- files outside the web root are not served'; for p in /../config/config.php /config/config.php /src/App.php /secrets/web.env /database/02_schema.sql /.git/config; do printf '  GET %-28s -> ' "$p"; curl -ks -o /dev/null -w '%{http_code}\n' --path-as-is "https://localhost:8443$p"; done

echo; echo '######## AFTER: host files'
stat -c '%A %U %n' secrets secrets/* secrets/tls/* backups/*.gpg | grep -v gnupg/
echo "-- tracked by Git? $(git status --porcelain --ignored secrets backups logs | grep -c '^!!') ignored paths, $(git ls-files secrets backups/*.gpg logs/*.log 2>/dev/null | wc -l) tracked secret files"

echo; echo '######## Patch status (image versions in use; pending Debian updates inside each container)'
dc exec -T db sh -c 'postgres --version; apt-get update -qq 2>/dev/null; echo "pending package upgrades: $(apt-get -s upgrade 2>/dev/null | grep -c ^Inst)"'
dc exec -T web sh -c 'php -v | head -1; apache2 -v | head -1; apt-get update -qq 2>/dev/null; echo "pending package upgrades: $(apt-get -s upgrade 2>/dev/null | grep -c ^Inst)"'
docker image inspect postgres:18 php:8.5-apache --format '{{index .RepoTags 0}} {{index .RepoDigests 0}}'
} > docs/evidence/hardening.txt 2>&1
wc -l docs/evidence/privileges.txt docs/evidence/hardening.txt
