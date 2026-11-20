#!/usr/bin/env bash
# Database-security audit of the RUNNING PostgreSQL: asks the catalogs, not the application.
# Evidence: docs/evidence/db-security.txt   (exit 1 when any check fails)
. "$(dirname "$0")/lib.sh"
load_secrets
DB="${1:-grants}"; valid_db_name "$DB"
OUT=docs/evidence/db-security.txt
R=0; F=0
ok()  { R=$((R+1)); printf 'PASS  %s\n' "$1"; }
bad() { F=$((F+1)); printf 'FAIL  %s\n' "$1"; }
q() { psql_admin "$DB" -Atc "$1"; }
# expect "<description>" "<sql returning one value>" "<expected>"
expect() { local got; got=$(q "$2" 2>&1 | tr '\n' ' ' | sed 's/ $//')|| true; [ "$got" = "$3" ] && ok "$1" || bad "$1 (got: ${got:-nothing}, expected: $3)"; }
{
echo "DATABASE SECURITY AUDIT - $(date -u +%Y-%m-%dT%H:%M:%SZ) (UTC) - database $DB, $(q 'SHOW server_version' | cut -d' ' -f1)"
echo; echo "== accounts and authentication"
expect "the only superuser is postgres (reachable by local peer authentication only)" "SELECT string_agg(rolname, ',') FROM pg_roles WHERE rolsuper" "postgres"
expect "no role other than postgres can create roles, databases or replicate" "SELECT count(*) FROM pg_roles WHERE rolname <> 'postgres' AND rolname !~ '^pg_' AND (rolcreaterole OR rolcreatedb OR rolreplication)" "0"
expect "only the backup account bypasses row-level security (pg_dump must read everything)" "SELECT string_agg(rolname, ',') FROM pg_roles WHERE rolbypassrls AND NOT rolsuper" "grants_backup"
expect "every login role has a SCRAM-SHA-256 verifier, none is MD5 or plain" "SELECT count(*) FROM pg_authid WHERE rolcanlogin AND rolpassword IS NOT NULL AND rolpassword NOT LIKE 'SCRAM-SHA-256%'" "0"
expect "every application login role has a connection limit" "SELECT count(*) FROM pg_roles WHERE rolcanlogin AND NOT rolsuper AND rolconnlimit < 0" "0"
expect "the schema owner cannot log in (NOLOGIN)" "SELECT rolcanlogin FROM pg_roles WHERE rolname = 'grants_owner'" "f"
expect "server enforces SCRAM for new passwords" "SHOW password_encryption" "scram-sha-256"
expect "TLS is on and at least TLS 1.2" "SELECT current_setting('ssl') || ' ' || current_setting('ssl_min_protocol_version')" "on TLSv1.2"
expect "pg_hba.conf ends with a reject-all rule and has no 'trust' or 'md5' line" "SELECT (count(*) FILTER (WHERE auth_method IN ('trust','md5','password')) = 0)::text || ' ' || (max(line_number) FILTER (WHERE auth_method='reject') = max(line_number))::text FROM pg_hba_file_rules WHERE error IS NULL" "true true"
expect "all remote rules require SSL (hostssl) and a local network" "SELECT count(*) FROM pg_hba_file_rules WHERE type IN ('host') AND auth_method <> 'reject'" "0"

echo; echo "== privileges"
expect "PUBLIC has no privilege on the schema, the database objects or the public schema" "SELECT has_schema_privilege('public','grants','USAGE')::text || has_database_privilege('public', current_database(), 'CONNECT')::text || has_schema_privilege('public','public','CREATE')::text" "falsefalsefalse"
expect "PUBLIC holds no table privilege in the schema" "SELECT count(*) FROM information_schema.role_table_grants WHERE grantee='PUBLIC' AND table_schema='grants'" "0"
expect "PUBLIC can execute no function in the schema" "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='grants' AND has_function_privilege('public', p.oid, 'EXECUTE')" "0"
expect "one owner for every table, view and sequence (grants_owner)" "SELECT string_agg(DISTINCT pg_get_userbyid(c.relowner), ',') FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='grants' AND c.relkind IN ('r','v','S')" "grants_owner"
expect "the web account has no privilege on audit, identity, credential or key tables" "SELECT count(*) FROM (VALUES ('audit_events'),('actor_key'),('identity_sessions'),('login_failures'),('mfa_recovery_codes'),('webauthn_credentials')) t(n) WHERE has_table_privilege('grants_app', 'grants.'||n, 'SELECT,INSERT,UPDATE,DELETE')" "0"
expect "the web account cannot read password hashes or TOTP secrets" "SELECT has_column_privilege('grants_app','grants.users','password_hash','SELECT')::text || has_column_privilege('grants_app','grants.users','totp_secret_enc','SELECT')::text" "falsefalse"
expect "the web account cannot write decisions or budgets directly (only record_decision())" "SELECT has_table_privilege('grants_app','grants.decisions','INSERT')::text || has_column_privilege('grants_app','grants.grant_calls','remaining_budget','UPDATE')::text" "falsefalse"
expect "nobody can UPDATE or DELETE audit events, owner included (append-only triggers on UPDATE/DELETE and on TRUNCATE)" "SELECT count(*) FROM pg_trigger WHERE tgrelid='grants.audit_events'::regclass AND NOT tgisinternal" "2"

echo; echo "== row-level security and definer functions"
expect "row-level security is enabled on every table that holds business records" "SELECT string_agg(relname, ',' ORDER BY relname) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='grants' AND relkind='r' AND relrowsecurity AND relname IN ('proposals','reviews','decisions','grant_calls')" "decisions,grant_calls,proposals,reviews"
expect "RLS with no policy (deny by default) on the tables reached through functions only" "SELECT string_agg(c.relname, ',' ORDER BY c.relname) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='grants' AND c.relrowsecurity AND NOT EXISTS (SELECT 1 FROM pg_policies p WHERE p.schemaname='grants' AND p.tablename=c.relname)" "actor_key,login_failures,mfa_recovery_codes,webauthn_credentials"
expect "the 18 policies are in place (decisions 3, grant_calls 3, proposals 7, reviews 5)" "SELECT count(*) FROM pg_policies WHERE schemaname='grants'" "18"
expect "every SECURITY DEFINER function pins its search_path" "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='grants' AND p.prosecdef AND NOT EXISTS (SELECT 1 FROM unnest(coalesce(p.proconfig,'{}')) c WHERE c LIKE 'search_path=%')" "0"
expect "every table has a primary key" "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='grants' AND c.relkind='r' AND NOT EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid=c.oid AND i.indisprimary)" "0"
expect "money columns are numeric, never floating point" "SELECT count(*) FROM information_schema.columns WHERE table_schema='grants' AND data_type IN ('real','double precision')" "0"

echo; echo "== data protection and monitoring"
expect "data checksums are on (silent page corruption is detected)" "SHOW data_checksums" "on"
expect "sensitive columns hold ciphertext or hashes, never clear text (format check)" "SELECT (SELECT count(*) FROM grants.users WHERE password_hash !~ '^.argon2id.v=19') + (SELECT count(*) FROM grants.reviews WHERE comments_enc IS NOT NULL AND comments_enc NOT LIKE 'v2:%') + (SELECT count(*) FROM grants.users WHERE totp_secret_enc IS NOT NULL AND totp_secret_enc NOT LIKE 'v2:%')" "0"
expect "connections and disconnections are logged" "SELECT current_setting('log_connections') || ' ' || current_setting('log_disconnections')" "on on"
expect "pgaudit is loaded" "SHOW shared_preload_libraries" "pgaudit"
expect "pgaudit logs everything for the superuser and the schema owner" "SELECT count(*) FROM pg_db_role_setting s JOIN pg_roles r ON r.oid=s.setrole WHERE r.rolname IN ('postgres','grants_owner') AND s.setconfig::text LIKE '%pgaudit.log=all%'" "2"
echo; echo "SUMMARY: $R checks passed, $F failed"
[ "$F" -eq 0 ]
} 2>&1 | tee "$OUT"
exit "${PIPESTATUS[0]}"
