-- 08_mfa.sql - multi-factor authentication (TOTP, RFC 6238) for officers and auditors.
--
-- The shared secret is stored ENCRYPTED by the application (XChaCha20-Poly1305, the field-key keyring); the
-- database never sees it in clear. The runtime account cannot read these columns or the recovery-code table. Everything
-- goes through SECURITY DEFINER functions that require a valid actor token for the same user (06_identity_and_audit.sql),
-- so a stolen database password cannot enrol, read or disable anybody's second factor.
-- Idempotent. Applied before 04_grants.sql.
\set ON_ERROR_STOP on
SET ROLE grants_owner;
SET search_path = grants, pg_catalog;

ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret_enc   text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enrolled_at  timestamptz;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_last_step    bigint NOT NULL DEFAULT 0;   -- replay protection: the last 30-second step accepted

CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id    bigint      NOT NULL REFERENCES users (id),
    code_hash  text        NOT NULL,               -- Argon2id, like a password: a code is shown once and never stored in clear
    created_at timestamptz NOT NULL DEFAULT now(),
    used_at    timestamptz
);
CREATE INDEX IF NOT EXISTS mfa_recovery_codes_user_idx ON mfa_recovery_codes (user_id) WHERE used_at IS NULL;

CREATE OR REPLACE FUNCTION mfa_require_self(p_user bigint) RETURNS void
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = grants, pg_temp AS $$
BEGIN
    IF p_user IS NULL OR current_actor_id() IS DISTINCT FROM p_user THEN
        RAISE EXCEPTION 'a valid actor token for this user is required' USING ERRCODE = 'insufficient_privilege';
    END IF;
END $$;

CREATE OR REPLACE FUNCTION mfa_state(p_user bigint)
RETURNS TABLE (enrolled boolean, secret_enc text, last_step bigint)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = grants, pg_temp AS $$
BEGIN
    PERFORM mfa_require_self(p_user);
    RETURN QUERY SELECT u.totp_enrolled_at IS NOT NULL, u.totp_secret_enc, u.totp_last_step FROM users u WHERE u.id = p_user;
END $$;

-- Enrol once. A second enrolment is refused (an operator resets with scripts/mfa-reset.sh).
CREATE OR REPLACE FUNCTION mfa_enroll(p_user bigint, p_secret_enc text, p_code_hashes text[]) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = grants, pg_temp AS $$
BEGIN
    PERFORM mfa_require_self(p_user);
    IF EXISTS (SELECT 1 FROM users WHERE id = p_user AND totp_enrolled_at IS NOT NULL) THEN
        RAISE EXCEPTION 'multi-factor authentication is already enrolled for this account' USING ERRCODE = 'check_violation';
    END IF;
    IF p_secret_enc IS NULL OR p_secret_enc !~ '^v[12]:' THEN
        RAISE EXCEPTION 'the secret must be stored encrypted' USING ERRCODE = 'check_violation';
    END IF;
    UPDATE users SET totp_secret_enc = p_secret_enc, totp_enrolled_at = now(), totp_last_step = 0 WHERE id = p_user;
    DELETE FROM mfa_recovery_codes WHERE user_id = p_user;
    INSERT INTO mfa_recovery_codes (user_id, code_hash) SELECT p_user, h FROM unnest(p_code_hashes) AS h;
END $$;

-- Atomic replay protection: a step is accepted once, and never an older one.
CREATE OR REPLACE FUNCTION mfa_accept_step(p_user bigint, p_step bigint) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = grants, pg_temp AS $$
BEGIN
    PERFORM mfa_require_self(p_user);
    UPDATE users SET totp_last_step = p_step WHERE id = p_user AND totp_last_step < p_step;
    RETURN FOUND;
END $$;

CREATE OR REPLACE FUNCTION mfa_recovery_hashes(p_user bigint) RETURNS TABLE (id bigint, code_hash text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = grants, pg_temp AS $$
BEGIN
    PERFORM mfa_require_self(p_user);
    RETURN QUERY SELECT c.id, c.code_hash FROM mfa_recovery_codes c WHERE c.user_id = p_user AND c.used_at IS NULL ORDER BY c.id;
END $$;

CREATE OR REPLACE FUNCTION mfa_consume_recovery(p_user bigint, p_id bigint) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = grants, pg_temp AS $$
BEGIN
    PERFORM mfa_require_self(p_user);
    UPDATE mfa_recovery_codes SET used_at = now() WHERE id = p_id AND user_id = p_user AND used_at IS NULL;
    RETURN FOUND;
END $$;
