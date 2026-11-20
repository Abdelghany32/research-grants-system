-- 04_grants.sql - object privileges (least privilege). Idempotent: everything
-- is revoked first, then only what each group needs is granted back.
\set ON_ERROR_STOP on
SET ROLE grants_owner;
SET search_path = grants, pg_catalog;

REVOKE ALL ON SCHEMA grants FROM PUBLIC;
REVOKE ALL ON ALL TABLES    IN SCHEMA grants FROM PUBLIC, grants_runtime, grants_audit_read, grants_backup_read, grants_audit_writer, grants_notifier_group, grants_identity_group;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA grants FROM PUBLIC, grants_runtime, grants_audit_read, grants_backup_read, grants_audit_writer, grants_notifier_group, grants_identity_group;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA grants FROM PUBLIC, grants_runtime, grants_audit_read, grants_backup_read, grants_audit_writer, grants_notifier_group, grants_identity_group;

GRANT USAGE ON SCHEMA grants TO grants_runtime, grants_audit_read, grants_backup_read, grants_audit_writer, grants_notifier_group, grants_identity_group;

-- ---- grants_runtime: the PHP service ------------------------------------
-- users: no password_hash column, no INSERT/DELETE, NO write at all (sign-in bookkeeping belongs to the identity service).
GRANT SELECT (id, email, full_name, department, role, is_active,
              locked_until, last_login_at, created_at) ON users TO grants_runtime;

GRANT SELECT, INSERT ON grant_calls TO grants_runtime;
-- remaining_budget is NOT writable: only record_decision() moves money (finding F01).
GRANT UPDATE (title, description, closes_at, status) ON grant_calls TO grants_runtime;

GRANT SELECT, INSERT, DELETE ON proposals TO grants_runtime;
GRANT UPDATE (title, abstract, requested_amount, status) ON proposals TO grants_runtime;

GRANT SELECT, INSERT ON reviews TO grants_runtime;          -- no DELETE
GRANT UPDATE (score, comments_enc, status, due_at) ON reviews TO grants_runtime;   -- due_at: officers only, forwards only (trigger)

GRANT SELECT ON decisions TO grants_runtime;                -- no INSERT, UPDATE or DELETE: rows appear only through record_decision() (F01)

-- audit_events: NO privilege at all for the runtime account (finding O03). It can only call audit_append(), and that
-- function accepts an event only with a valid actor token, which the database password alone cannot produce.

GRANT EXECUTE ON FUNCTION current_actor_id(), current_actor_role(),
                          is_assigned_reviewer(bigint), owns_proposal(bigint),
                          record_decision(bigint, text, numeric, text, uuid, inet),
                          audit_append(text, text, bigint, text, jsonb, uuid, inet, bigint, text),
                          notify_enqueue(text, bigint, text) TO grants_runtime;
-- Everything about passwords, the sign-in throttle and the second factor is NOT granted to the web account: it belongs
-- to the identity service (finding O01: a stolen web credential yields no password hash).

-- ---- grants_identity_group: the identity service ------------------------------
GRANT SELECT (id, email, full_name, department, role, is_active, locked_until, last_login_at, created_at) ON users TO grants_identity_group;
GRANT UPDATE (last_login_at) ON users TO grants_identity_group;
GRANT SELECT, INSERT, UPDATE, DELETE ON identity_sessions TO grants_identity_group;
GRANT EXECUTE ON FUNCTION current_actor_id(),
                          auth_find_credentials(text),
                          auth_login_gate(bigint, inet, integer, integer, integer, integer),
                          auth_record_failure(bigint, inet, integer, integer),
                          auth_clear_failures(bigint, inet),
                          mfa_state(bigint), mfa_enroll(bigint, text, text[]), mfa_accept_step(bigint, bigint),
                          mfa_recovery_hashes(bigint), mfa_consume_recovery(bigint, bigint),
                          webauthn_list(bigint), webauthn_register(bigint, bytea, text, integer, bigint, boolean, text, text),
                          webauthn_use(bigint, bigint, bigint), webauthn_delete(bigint, bigint) TO grants_identity_group;

-- ---- grants_audit_writer: the audit-writer account (finding O03) -------------
-- No table privilege. It may record events that have no authenticated actor (login failures, throttling, CSRF
-- rejections) and refusals; audit_append() enforces that and flags such events actor_verified = false.
GRANT EXECUTE ON FUNCTION audit_append(text, text, bigint, text, jsonb, uuid, inet, bigint, text) TO grants_audit_writer;

-- ---- grants_notifier_group: delivers the e-mail outbox ----------------------
-- Reads the outbox and the recipient's address and name, marks messages sent, queues due-date reminders. Nothing else:
-- no proposals, no reviews, no password hashes, no audit trail.
GRANT SELECT ON notifications TO grants_notifier_group;
GRANT UPDATE (sent_at, attempts, last_error) ON notifications TO grants_notifier_group;
GRANT SELECT (id, email, full_name) ON users TO grants_notifier_group;
GRANT EXECUTE ON FUNCTION notify_enqueue_reminders(text) TO grants_notifier_group;

-- ---- grants_audit_read: the auditor's read-only window -------------------
GRANT SELECT ON audit_timeline TO grants_audit_read;

-- ---- grants_backup_read: pg_dump ----------------------------------------
GRANT SELECT ON ALL TABLES    IN SCHEMA grants TO grants_backup_read;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA grants TO grants_backup_read;

-- ---- a second lock on the tables that are reachable through functions only ---------------------------------
-- Row-level security is enabled with NO policy: should a table privilege ever be granted by mistake, the grantee
-- still sees no row. The SECURITY DEFINER functions run as the table owner, which is exempt, so nothing changes for them.
-- (The business tables have their policies in 03_rls.sql; backups use the BYPASSRLS backup account.)
ALTER TABLE actor_key             ENABLE ROW LEVEL SECURITY;
ALTER TABLE login_failures        ENABLE ROW LEVEL SECURITY;
ALTER TABLE mfa_recovery_codes    ENABLE ROW LEVEL SECURITY;
ALTER TABLE webauthn_credentials  ENABLE ROW LEVEL SECURITY;
