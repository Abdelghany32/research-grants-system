-- 12_pgaudit.sql - session audit by pgaudit (the server is started with shared_preload_libraries=pgaudit, see compose.yaml).
-- Server-wide: DDL, role changes and writes are logged. Below, EVERYTHING (reads included) is logged for the accounts that
-- must never be used in normal operation: the superuser and the schema owner. Their sessions therefore leave a record in the
-- PostgreSQL log, which is shipped off the database host, even though they bypass the application audit trail.
-- Idempotent. Run as the superuser.
\set ON_ERROR_STOP on
ALTER ROLE postgres      SET pgaudit.log = 'all';
ALTER ROLE grants_owner  SET pgaudit.log = 'all';
