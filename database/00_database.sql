-- 00_database.sql - database-level access. Run as superuser while connected to
-- the target database (grants, grants_test or a restore target).
-- Database ACLs are not inside a plain pg_dump archive, so this is re-run on restore.
\set ON_ERROR_STOP on
SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC', current_database()) \gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO grants_runtime, grants_audit_read, grants_backup_read, grants_audit_writer, grants_notifier_group, grants_identity_group', current_database()) \gexec
SELECT format('ALTER DATABASE %I SET timezone = ''UTC''', current_database()) \gexec
-- Nobody but the owner may create objects in or use the default schema.
REVOKE ALL ON SCHEMA public FROM PUBLIC;
