-- 06_identity_and_audit.sql - closes observations O02 and O03.
--
-- O02 (self-asserted identity): until now the web service stated WHO was acting with
--     set_config('app.user_id', ...), so anyone holding the runtime database password could claim to be any
--     officer. Now the service presents an ACTOR TOKEN - "v1.<user id>.<expiry>.<nonce>.<HMAC-SHA256>" - signed
--     with a key that lives in the web process (secrets/actor.key) and, for verification, in a table that only
--     the schema owner can read. The database verifies the signature itself; a token that is missing, forged,
--     expired or signed for someone else yields NO identity, and every row-level policy then answers "no rows".
--     A stolen DATABASE credential is therefore no longer enough to act as a user.
--
-- O03 (forged audit events): the runtime account loses its INSERT on audit_events. Events are written only through
--     audit_append(): an event that names an actor needs a valid actor token for that actor (the role is looked up
--     in the database, never supplied); events with no authenticated actor (login failures, throttling, CSRF
--     rejections) may be written only by the separate audit-writer account, only for pre-authentication action
--     names or denials, and are flagged actor_verified = false.
--
-- Idempotent. Applied after 05_remediation.sql and before 04_grants.sql.
\set ON_ERROR_STOP on
\getenv actor_key ACTOR_KEY
SET ROLE grants_owner;
SET search_path = grants, pg_catalog;

CREATE TABLE IF NOT EXISTS actor_key (
    id     smallint PRIMARY KEY CHECK (id = 1),
    secret bytea    NOT NULL CHECK (length(secret) >= 32)
);
-- The key is loaded by the administrator from secrets/actor.key; re-running this script with a new file rotates it.
INSERT INTO actor_key (id, secret) VALUES (1, decode(:'actor_key', 'hex'))
ON CONFLICT (id) DO UPDATE SET secret = EXCLUDED.secret;

-- HMAC-SHA256 (RFC 2104) from the built-in sha256(): no extension needed. Checked against RFC 4231 in tests/owner_guards.sql.
CREATE OR REPLACE FUNCTION hmac_sha256(p_key bytea, p_msg bytea) RETURNS bytea
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog AS $$
DECLARE
    k bytea := p_key; ipad bytea; opad bytea; i integer;
BEGIN
    IF length(k) > 64 THEN k := sha256(k); END IF;
    k := k || decode(repeat('00', 64 - length(k)), 'hex');
    ipad := k; opad := k;
    FOR i IN 0..63 LOOP
        ipad := set_byte(ipad, i, get_byte(k, i) # 54);    -- 0x36
        opad := set_byte(opad, i, get_byte(k, i) # 92);    -- 0x5c
    END LOOP;
    RETURN sha256(opad || sha256(ipad || p_msg));
END $$;

-- The user id proved by a token, or NULL. Format v1.<uid>.<exp epoch>.<nonce hex>.<hmac hex>.
CREATE OR REPLACE FUNCTION actor_verify_token(p_token text) RETURNS bigint
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = grants, pg_temp AS $$
DECLARE
    parts text[]; k bytea; now_s double precision := extract(epoch FROM clock_timestamp());
    msg bytea; expected bytea;
BEGIN
    IF p_token IS NULL OR p_token = '' THEN RETURN NULL; END IF;
    parts := string_to_array(p_token, '.');
    IF array_length(parts, 1) IS DISTINCT FROM 5 OR parts[1] <> 'v1'
       OR parts[2] !~ '^[0-9]{1,18}$' OR parts[3] !~ '^[0-9]{1,12}$'
       OR parts[4] !~ '^[0-9a-f]{8,64}$' OR parts[5] !~ '^[0-9a-f]{64}$' THEN
        RETURN NULL;
    END IF;
    -- short-lived: it must not have expired, and cannot claim more than 10 minutes of life
    IF parts[3]::bigint < now_s OR parts[3]::bigint > now_s + 600 THEN RETURN NULL; END IF;
    SELECT secret INTO k FROM actor_key WHERE id = 1;
    IF k IS NULL THEN RETURN NULL; END IF;
    msg := convert_to(format('v1|%s|%s|%s', parts[2], parts[3], parts[4]), 'UTF8');
    expected := hmac_sha256(k, msg);
    -- compare the HMACs of both values (equal-time comparison pattern)
    IF hmac_sha256(k, expected) = hmac_sha256(k, decode(parts[5], 'hex')) THEN
        RETURN parts[2]::bigint;
    END IF;
    RETURN NULL;
END $$;

-- The acting user for this transaction: only ever what a valid token proves. app.user_id is no longer read.
CREATE OR REPLACE FUNCTION current_actor_id() RETURNS bigint
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = grants, pg_temp AS
$$ SELECT actor_verify_token(current_setting('app.actor', true)) $$;

-- ------------------------------------------------------------------ audit
-- The only way to write an audit event (apart from SECURITY DEFINER business functions such as record_decision).
CREATE OR REPLACE FUNCTION audit_append(
    p_action text, p_resource_type text, p_resource_id bigint, p_outcome text, p_details jsonb,
    p_correlation uuid, p_ip inet, p_claimed_actor bigint DEFAULT NULL, p_token text DEFAULT NULL)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path = grants, pg_temp AS $$
DECLARE
    v_actor bigint := actor_verify_token(p_token);
    v_verified boolean := false;
    v_role text;
    v_id bigint;
BEGIN
    IF length(coalesce(p_details, '{}'::jsonb)::text) > 4000 THEN
        RAISE EXCEPTION 'audit details are limited to 4000 characters' USING ERRCODE = 'check_violation';
    END IF;
    IF v_actor IS NOT NULL THEN
        IF p_claimed_actor IS NOT NULL AND p_claimed_actor <> v_actor THEN
            RAISE EXCEPTION 'the named actor differs from the actor proved by the token' USING ERRCODE = 'insufficient_privilege';
        END IF;
        v_verified := true;
    ELSE
        -- No proof of identity: only the dedicated audit-writer account may record such an event, and only
        -- events that happen without an authenticated actor, or refusals.
        IF NOT pg_has_role(session_user, 'grants_audit_writer', 'member') THEN
            RAISE EXCEPTION 'an audit event needs a valid actor token' USING ERRCODE = 'insufficient_privilege';
        END IF;
        IF NOT (p_action ~ '^(auth|request)\.' OR p_outcome = 'denied') THEN
            RAISE EXCEPTION 'this kind of event needs a verified actor' USING ERRCODE = 'insufficient_privilege';
        END IF;
        v_actor := p_claimed_actor;
    END IF;
    SELECT role INTO v_role FROM users WHERE id = v_actor;      -- the role is never supplied by the caller
    INSERT INTO audit_events (actor_id, actor_role, action, resource_type, resource_id, outcome, correlation_id,
                              source_ip, details, actor_verified)
    VALUES (v_actor, v_role, p_action, p_resource_type, p_resource_id, p_outcome, p_correlation, p_ip,
            coalesce(p_details, '{}'::jsonb), v_verified)
    RETURNING id INTO v_id;
    RETURN v_id;
END $$;
