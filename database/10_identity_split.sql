-- 10_identity_split.sql - the identity service gets its own account and its own session store; the web account
-- loses everything that belongs to identity.
--
--  * grants_identity (group grants_identity_group) is used ONLY by the identity service. It can read password hashes
--    through auth_find_credentials(), run the sign-in throttle and the second-factor functions, update last_login_at,
--    and use the session table below. It cannot read proposals, reviews, decisions, the audit trail or the actor key.
--  * The web account (grants_app) can no longer call any of those functions: a stolen web credential yields no password
--    hash (finding O01 closed), cannot touch the throttle or anyone's second factor, and cannot read or forge sessions.
--  * identity_sessions: one row per session, keyed by the SHA-256 of an opaque handle, the data encrypted by the service.
-- Idempotent. Applied before 04_grants.sql.
\set ON_ERROR_STOP on
SET ROLE grants_owner;
SET search_path = grants, pg_catalog;

CREATE TABLE IF NOT EXISTS identity_sessions (
    handle_hash  bytea       PRIMARY KEY CHECK (length(handle_hash) = 32),
    data_enc     text        NOT NULL,
    user_id      bigint      REFERENCES users (id),            -- NULL while the sign-in is still pending (second factor owed)
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS identity_sessions_expiry_idx ON identity_sessions (expires_at);
CREATE INDEX IF NOT EXISTS identity_sessions_user_idx   ON identity_sessions (user_id);
