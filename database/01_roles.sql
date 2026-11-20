-- 01_roles.sql - cluster-wide roles. Run as the postgres superuser.
-- Idempotent: safe to re-run, and re-run before a restore because roles are
-- NOT part of a pg_dump archive.
-- Passwords are read from environment variables so they never appear on a command line.
\getenv app_password APP_DB_PASSWORD
\getenv auditor_password AUDITOR_DB_PASSWORD
\getenv backup_password BACKUP_DB_PASSWORD
\getenv audit_writer_password AUDIT_WRITER_DB_PASSWORD
\getenv notifier_password NOTIFIER_DB_PASSWORD
\getenv identity_password IDENTITY_DB_PASSWORD
\set ON_ERROR_STOP on

SELECT format('CREATE ROLE %I', r)
FROM unnest(ARRAY['grants_owner','grants_runtime','grants_audit_read','grants_backup_read',
                  'grants_audit_writer','grants_notifier_group','grants_identity_group',
                  'grants_app','grants_auditor','grants_backup','grants_audit_write','grants_notifier','grants_identity']) AS r
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = r)
\gexec

-- Schema owner: owns every object, cannot log in. Used only for migrations
-- via "SET ROLE grants_owner" from an administrator session.
ALTER ROLE grants_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

-- Privilege groups (NOLOGIN). Object privileges are granted to these groups,
-- never directly to a login account.
ALTER ROLE grants_runtime     NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE grants_audit_read  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE grants_backup_read NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE grants_audit_writer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE grants_notifier_group NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE grants_identity_group NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

-- Login accounts. Passwords are set with statement logging off so the
-- plaintext never reaches the server log (log_statement = 'ddl').
BEGIN;
SET LOCAL log_statement = 'none';
SET LOCAL log_min_error_statement = 'panic';
ALTER ROLE grants_app     LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
                          CONNECTION LIMIT 30 PASSWORD :'app_password';
ALTER ROLE grants_auditor LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
                          CONNECTION LIMIT 5  PASSWORD :'auditor_password';
-- Audit writer: its own credential, no table privilege at all - it can only call audit_append()
-- (finding O03: the web runtime account can no longer write audit events directly).
ALTER ROLE grants_audit_write LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
                          CONNECTION LIMIT 10 PASSWORD :'audit_writer_password';
-- Notifier: sends the e-mail outbox; sees only what a message needs.
ALTER ROLE grants_notifier LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
                          CONNECTION LIMIT 3 PASSWORD :'notifier_password';
-- Identity service: the only account that can read password hashes and run the sign-in functions.
ALTER ROLE grants_identity LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
                          CONNECTION LIMIT 20 PASSWORD :'identity_password';
-- pg_dump refuses to dump a table whose rows RLS would hide from it, so the
-- backup account needs BYPASSRLS. It is read-only and local-socket-only (pg_hba).
ALTER ROLE grants_backup  LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION BYPASSRLS
                          CONNECTION LIMIT 2  PASSWORD :'backup_password';
COMMIT;

-- Role assignment: each login account is a member of exactly one group.
GRANT grants_runtime     TO grants_app;
GRANT grants_audit_read  TO grants_auditor;
GRANT grants_backup_read TO grants_backup;
GRANT grants_audit_writer TO grants_audit_write;
GRANT grants_notifier_group TO grants_notifier;
GRANT grants_identity_group TO grants_identity;

-- Per-role session defaults.
ALTER ROLE grants_app     SET search_path = grants, pg_catalog;
ALTER ROLE grants_auditor SET search_path = grants, pg_catalog;
ALTER ROLE grants_backup  SET search_path = grants, pg_catalog;
ALTER ROLE grants_app     SET timezone = 'UTC';
ALTER ROLE grants_auditor SET timezone = 'UTC';
ALTER ROLE grants_audit_write SET search_path = grants, pg_catalog;
ALTER ROLE grants_notifier    SET search_path = grants, pg_catalog;
ALTER ROLE grants_identity    SET search_path = grants, pg_catalog;
ALTER ROLE grants_identity    SET statement_timeout = '10s';
ALTER ROLE grants_identity    SET idle_in_transaction_session_timeout = '30s';
ALTER ROLE grants_audit_write SET statement_timeout = '5s';
ALTER ROLE grants_notifier    SET statement_timeout = '15s';
ALTER ROLE grants_app     SET statement_timeout = '15s';
ALTER ROLE grants_app     SET lock_timeout = '10s';
ALTER ROLE grants_app     SET idle_in_transaction_session_timeout = '30s';
ALTER ROLE grants_auditor SET default_transaction_read_only = on;
