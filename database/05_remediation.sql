-- 05_remediation.sql - fixes for the penetration-test findings F01-F04.
-- Idempotent: runs on a fresh database (after 02 and 03) and on an existing one.
-- 04_grants.sql must be applied AFTER this file (it grants EXECUTE on the new
-- functions and removes the privileges that made F01 possible).
\set ON_ERROR_STOP on
SET ROLE grants_owner;
SET search_path = grants, pg_catalog;

-- Each audit event says whether its actor was PROVED (a valid actor token, see 06_identity_and_audit.sql) or only
-- CLAIMED (login failures name an account that did not authenticate). Rows written before the identity binding
-- release are false.
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS actor_verified boolean NOT NULL DEFAULT false;
CREATE OR REPLACE VIEW audit_timeline AS
SELECT e.id, e.occurred_at, e.actor_id, u.email AS actor_email, u.full_name AS actor_name,
       e.actor_role, e.action, e.resource_type, e.resource_id, e.outcome,
       e.correlation_id, e.source_ip, e.details, e.actor_verified
FROM audit_events e LEFT JOIN users u ON u.id = e.actor_id;

-- ============================================================================
-- F01  The financial decision is ONE database operation.
--
-- Before: the runtime account could INSERT a decision and UPDATE the call
-- balance separately, so a caller with raw SQL could commit only the first
-- step (a 1.00 award while the balance and the proposal status stayed
-- unchanged). Now the runtime account has neither privilege; it can only call
-- record_decision(), which re-checks everything under a row lock and writes
-- the decision, the balance, the proposal status AND the audit event in the
-- caller's transaction. A SQL-level attacker therefore cannot produce a
-- partial award, and cannot skip the audit record of a decision.
--
-- Failures use SQLSTATE GR001 and the message "<reason>|<detail>" so that the
-- PHP layer can translate them without parsing prose.
-- ============================================================================
CREATE OR REPLACE FUNCTION record_decision(
    p_proposal_id bigint, p_outcome text, p_amount numeric, p_rationale text,
    p_correlation uuid DEFAULT NULL, p_ip inet DEFAULT NULL,
    OUT decision_id bigint, OUT remaining numeric)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = grants, pg_temp AS $$
DECLARE
    v_actor     bigint := current_actor_id();
    v_role      text   := current_actor_role();
    v_amount    numeric(14,2);
    v_prop      proposals%ROWTYPE;
    v_budget    numeric(14,2);
BEGIN
    -- The role is looked up in the database, never taken from the caller.
    IF v_role IS DISTINCT FROM 'officer' THEN
        RAISE EXCEPTION 'record_decision requires an active officer' USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF p_outcome NOT IN ('approved', 'declined') THEN
        RAISE EXCEPTION USING ERRCODE = 'GR001', MESSAGE = 'invalid_outcome|Choose Approve or Decline.';
    END IF;
    v_amount := CASE WHEN p_outcome = 'declined' THEN 0 ELSE round(p_amount, 2) END;
    IF v_amount IS NULL OR v_amount < 0 OR (p_outcome = 'approved' AND v_amount <= 0) THEN
        RAISE EXCEPTION USING ERRCODE = 'GR001', MESSAGE = 'invalid_amount|The award must be a positive amount.';
    END IF;

    SELECT * INTO v_prop FROM proposals WHERE id = p_proposal_id;
    IF NOT FOUND OR v_prop.status = 'draft' THEN
        RAISE EXCEPTION USING ERRCODE = 'GR001', MESSAGE = 'not_visible|Proposal not found.';
    END IF;

    -- 1. Serialize: one decision at a time per grant call. NO KEY UPDATE blocks
    --    other writers of the row but not researchers inserting proposals.
    SELECT remaining_budget INTO v_budget FROM grant_calls WHERE id = v_prop.call_id FOR NO KEY UPDATE;

    -- 2. Re-read the proposal AFTER the lock was granted (READ COMMITTED sees the other commit).
    SELECT * INTO v_prop FROM proposals WHERE id = p_proposal_id;
    IF EXISTS (SELECT 1 FROM decisions d WHERE d.proposal_id = p_proposal_id) THEN
        RAISE EXCEPTION USING ERRCODE = 'GR001', MESSAGE = 'already_decided|A final decision has already been recorded for this proposal.';
    END IF;
    IF v_prop.status <> 'under_review' THEN
        RAISE EXCEPTION USING ERRCODE = 'GR001', MESSAGE = 'not_under_review|Only a proposal under review can be decided.';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM reviews r WHERE r.proposal_id = p_proposal_id AND r.status = 'submitted') THEN
        RAISE EXCEPTION USING ERRCODE = 'GR001', MESSAGE = 'review_missing|A completed review is required before a decision.';
    END IF;

    -- 3. Money limits, in exact numeric arithmetic.
    IF v_amount > v_prop.requested_amount THEN
        RAISE EXCEPTION USING ERRCODE = 'GR001', MESSAGE = 'exceeds_requested|The award cannot exceed the requested amount.';
    END IF;
    IF v_amount > v_budget THEN
        RAISE EXCEPTION USING ERRCODE = 'GR001',
            MESSAGE = format('insufficient_funds|Only %s %s remains in this call.', to_char(v_budget, 'FM999,999,999,999,990.00'), v_prop.currency);
    END IF;

    -- 4. Decision, balance, status and audit event: all or nothing.
    INSERT INTO decisions (proposal_id, outcome, awarded_amount, currency, rationale, decided_by)
    VALUES (p_proposal_id, p_outcome, v_amount, v_prop.currency, coalesce(p_rationale, ''), v_actor)
    RETURNING id INTO decision_id;

    UPDATE grant_calls SET remaining_budget = remaining_budget - v_amount
     WHERE id = v_prop.call_id RETURNING remaining_budget INTO remaining;

    UPDATE proposals SET status = p_outcome WHERE id = p_proposal_id AND status = 'under_review';

    INSERT INTO audit_events (actor_id, actor_role, action, resource_type, resource_id, outcome, correlation_id, source_ip, details, actor_verified)
    VALUES (v_actor, v_role, 'decision.record', 'proposal', p_proposal_id, 'success', p_correlation, p_ip,
            jsonb_build_object('decision_id', decision_id, 'outcome', p_outcome, 'awarded_amount', v_amount::text,
                               'currency', v_prop.currency, 'remaining_after', remaining::text), true);
END $$;

-- ============================================================================
-- F02 / F03 / F04  Login throttling, kept in the database.
--
-- Before: five failures locked the ACCOUNT for 15 minutes for everybody, so any
-- anonymous visitor could lock a known colleague out (F02); locked accounts
-- answered ~10x faster than others (F03); and nothing limited the attempts per
-- source address (F04).
-- Now failures are recorded per (account, source address):
--   * the pair (account, address) is locked after N failures, so an attacker
--     cannot lock the real owner out from another address;
--   * a source address is throttled after M failures against any account,
--     refusing it cheaply before any password hashing.
-- The table is reachable only through these functions; the runtime account has
-- no privilege on it. users.locked_until stays as an ADMINISTRATIVE lock that
-- an operator can set during an incident; the application only reads it.
-- ============================================================================
CREATE TABLE IF NOT EXISTS login_failures (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    user_id     bigint REFERENCES users (id),        -- NULL: unknown e-mail address
    source_ip   inet        NOT NULL
);
CREATE INDEX IF NOT EXISTS login_failures_ip_idx   ON login_failures (source_ip, occurred_at);
CREATE INDEX IF NOT EXISTS login_failures_pair_idx ON login_failures (user_id, source_ip, occurred_at);
CREATE INDEX IF NOT EXISTS login_failures_time_idx ON login_failures (occurred_at);

-- NULL = allowed, otherwise the reason ('ip_throttled' or 'pair_locked').
CREATE OR REPLACE FUNCTION auth_login_gate(
    p_user_id bigint, p_ip inet, p_pair_max integer, p_pair_minutes integer, p_ip_max integer, p_ip_minutes integer)
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path = grants, pg_temp AS $$
    SELECT CASE
        WHEN (SELECT count(*) FROM login_failures
               WHERE source_ip = p_ip AND occurred_at > clock_timestamp() - make_interval(mins => p_ip_minutes)) >= p_ip_max
            THEN 'ip_throttled'
        WHEN p_user_id IS NOT NULL AND (SELECT count(*) FROM login_failures
               WHERE user_id = p_user_id AND source_ip = p_ip
                 AND occurred_at > clock_timestamp() - make_interval(mins => p_pair_minutes)) >= p_pair_max
            THEN 'pair_locked'
    END $$;

-- Records one failure and returns the counters the application needs to decide
-- which audit events to write (it writes each threshold event exactly once).
CREATE OR REPLACE FUNCTION auth_record_failure(
    p_user_id bigint, p_ip inet, p_pair_minutes integer, p_ip_minutes integer,
    OUT pair_failures integer, OUT ip_failures integer, OUT account_failures integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = grants, pg_temp AS $$
BEGIN
    INSERT INTO login_failures (user_id, source_ip) VALUES (p_user_id, p_ip);
    DELETE FROM login_failures WHERE occurred_at < clock_timestamp() - interval '1 day';
    SELECT count(*) INTO pair_failures FROM login_failures
     WHERE user_id = p_user_id AND source_ip = p_ip
       AND occurred_at > clock_timestamp() - make_interval(mins => p_pair_minutes);
    SELECT count(*) INTO ip_failures FROM login_failures
     WHERE source_ip = p_ip AND occurred_at > clock_timestamp() - make_interval(mins => p_ip_minutes);
    SELECT count(*) INTO account_failures FROM login_failures
     WHERE user_id = p_user_id AND occurred_at > clock_timestamp() - interval '1 hour';
END $$;

-- A successful sign-in forgives the failures of that (account, address) pair.
CREATE OR REPLACE FUNCTION auth_clear_failures(p_user_id bigint, p_ip inet)
RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = grants, pg_temp AS $$
    DELETE FROM login_failures WHERE user_id IS NOT DISTINCT FROM p_user_id AND source_ip = p_ip $$;

-- The failure counter column is no longer used; the credentials helper loses it.
DROP FUNCTION IF EXISTS auth_find_credentials(text);
CREATE FUNCTION auth_find_credentials(p_email text)
RETURNS TABLE (id bigint, password_hash text, is_active boolean, locked_until timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = grants, pg_temp AS
$$ SELECT u.id, u.password_hash, u.is_active, u.locked_until
   FROM users u WHERE u.email = lower(p_email) $$;
ALTER TABLE users DROP COLUMN IF EXISTS failed_login_count;
