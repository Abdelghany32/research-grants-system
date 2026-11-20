-- 11_webauthn.sql - security keys (WebAuthn / FIDO2) as a phishing-resistant second factor.
--
-- Only the identity service touches these objects (every function needs a valid actor token for the same user, like the
-- TOTP functions). A credential stores the PUBLIC key only: a stolen database yields nothing that signs in.
--  * sign_count: the authenticator's counter; a value that does not move forward is a cloned key and is refused.
--  * A user cannot delete their last second factor.
-- Idempotent. Applied before 04_grants.sql.
\set ON_ERROR_STOP on
SET ROLE grants_owner;
SET search_path = grants, pg_catalog;

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id       bigint      NOT NULL REFERENCES users (id),
    credential_id bytea       NOT NULL UNIQUE CHECK (length(credential_id) BETWEEN 16 AND 1023),
    public_key_pem text       NOT NULL CHECK (length(public_key_pem) BETWEEN 100 AND 2000),
    alg           smallint    NOT NULL CHECK (alg IN (-7, -257)),            -- ES256, RS256
    sign_count    bigint      NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
    user_verified boolean     NOT NULL,
    name          text        NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 60),
    transports    text        CHECK (length(transports) <= 100),
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz
);
CREATE INDEX IF NOT EXISTS webauthn_credentials_user_idx ON webauthn_credentials (user_id);

CREATE OR REPLACE FUNCTION webauthn_list(p_user bigint)
RETURNS TABLE (id bigint, credential_id bytea, public_key_pem text, alg smallint, sign_count bigint, user_verified boolean,
               name text, created_at timestamptz, last_used_at timestamptz)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = grants, pg_temp AS $$
BEGIN
    PERFORM mfa_require_self(p_user);
    RETURN QUERY SELECT c.id, c.credential_id, c.public_key_pem, c.alg, c.sign_count, c.user_verified, c.name, c.created_at, c.last_used_at
                   FROM webauthn_credentials c WHERE c.user_id = p_user ORDER BY c.id;
END $$;

CREATE OR REPLACE FUNCTION webauthn_register(p_user bigint, p_credential_id bytea, p_pem text, p_alg integer, p_sign_count bigint,
                                             p_uv boolean, p_name text, p_transports text) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = grants, pg_temp AS $$
DECLARE v_id bigint;
BEGIN
    PERFORM mfa_require_self(p_user);
    IF (SELECT count(*) FROM webauthn_credentials WHERE user_id = p_user) >= 10 THEN
        RAISE EXCEPTION 'at most 10 security keys per account' USING ERRCODE = 'check_violation';
    END IF;
    INSERT INTO webauthn_credentials (user_id, credential_id, public_key_pem, alg, sign_count, user_verified, name, transports)
    VALUES (p_user, p_credential_id, p_pem, p_alg, p_sign_count, p_uv, btrim(p_name), p_transports) RETURNING id INTO v_id;
    RETURN v_id;
END $$;

-- Moves the counter forward; refuses a counter that did not (a cloned authenticator). Counters that are always 0 are fine.
CREATE OR REPLACE FUNCTION webauthn_use(p_user bigint, p_id bigint, p_new_count bigint) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = grants, pg_temp AS $$
DECLARE v_old bigint;
BEGIN
    PERFORM mfa_require_self(p_user);
    SELECT sign_count INTO v_old FROM webauthn_credentials WHERE id = p_id AND user_id = p_user FOR UPDATE;
    IF NOT FOUND THEN RETURN false; END IF;
    IF NOT ((p_new_count = 0 AND v_old = 0) OR p_new_count > v_old) THEN RETURN false; END IF;
    UPDATE webauthn_credentials SET sign_count = p_new_count, last_used_at = now() WHERE id = p_id;
    RETURN true;
END $$;

-- Deleting a key is refused when it would leave the account with no second factor at all.
CREATE OR REPLACE FUNCTION webauthn_delete(p_user bigint, p_id bigint) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = grants, pg_temp AS $$
BEGIN
    PERFORM mfa_require_self(p_user);
    IF NOT EXISTS (SELECT 1 FROM webauthn_credentials WHERE id = p_id AND user_id = p_user) THEN RETURN false; END IF;
    IF NOT EXISTS (SELECT 1 FROM users WHERE id = p_user AND totp_enrolled_at IS NOT NULL)
       AND (SELECT count(*) FROM webauthn_credentials WHERE user_id = p_user) <= 1 THEN
        RAISE EXCEPTION 'this is the last second factor of the account' USING ERRCODE = 'check_violation';
    END IF;
    DELETE FROM webauthn_credentials WHERE id = p_id AND user_id = p_user;
    RETURN true;
END $$;
