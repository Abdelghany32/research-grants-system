-- Defence in depth: the database guard triggers and constraints still hold when
-- privileges are NOT in the way. Runs as the schema owner on grants_test (called
-- by scripts/test.sh); every block is rolled back. The runtime account can no
-- longer even attempt these writes (finding F01), so this is the only place
-- where the backstops themselves are exercised.
\set ON_ERROR_STOP on
SET ROLE grants_owner;
SET search_path = grants, pg_catalog;

CREATE TEMP TABLE guard_results (ok boolean, claim text);

CREATE FUNCTION pg_temp.expect_error(p_sql text, p_state text, p_claim text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    BEGIN
        EXECUTE p_sql;
        INSERT INTO guard_results VALUES (false, p_claim || ' - statement succeeded');
    EXCEPTION WHEN OTHERS THEN
        INSERT INTO guard_results VALUES (SQLSTATE = p_state, p_claim || ' (SQLSTATE ' || SQLSTATE || ')');
    END;
END $$;

DO $$
DECLARE
    v_decided   bigint; v_call bigint; v_inreview bigint; v_officer bigint;
BEGIN
    SELECT d.proposal_id, p.call_id INTO v_decided, v_call
      FROM decisions d JOIN proposals p ON p.id = d.proposal_id ORDER BY d.id LIMIT 1;
    SELECT id INTO v_inreview FROM proposals WHERE status = 'under_review'
       AND NOT EXISTS (SELECT 1 FROM reviews r WHERE r.proposal_id = proposals.id AND r.status = 'submitted') ORDER BY id LIMIT 1;
    SELECT id INTO v_officer FROM users WHERE role = 'officer' ORDER BY id LIMIT 1;

    PERFORM pg_temp.expect_error(format($f$INSERT INTO decisions (proposal_id, outcome, awarded_amount, currency, decided_by)
        VALUES (%s, 'approved', 1, 'MAD', %s)$f$, v_decided, v_officer), '23514', 'a second decision on a decided proposal is refused (guard)');
    PERFORM pg_temp.expect_error(format($f$INSERT INTO decisions (proposal_id, outcome, awarded_amount, currency, decided_by)
        VALUES (%s, 'approved', 10, 'MAD', %s)$f$, v_inreview, v_officer), '23514', 'a decision without a completed review is refused (guard)');
    PERFORM pg_temp.expect_error(format($f$INSERT INTO decisions (proposal_id, outcome, awarded_amount, currency, decided_by)
        VALUES (%s, 'declined', 10, 'MAD', %s)$f$, v_inreview, v_officer), '23514', 'a decline with a non-zero award is refused (CHECK)');
    -- The currency pin is a foreign key (checked after the BEFORE triggers), so assert its definition.
    INSERT INTO guard_results SELECT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'grants.decisions'::regclass AND contype = 'f'
        AND pg_get_constraintdef(oid) LIKE 'FOREIGN KEY (proposal_id, currency) REFERENCES proposals(id, currency)%'),
        'a decision is pinned to the proposal currency by a composite foreign key (definition checked)';
    PERFORM pg_temp.expect_error(format('UPDATE grant_calls SET remaining_budget = remaining_budget + 1 WHERE id = %s', v_call), '23514', 'the balance can never be raised (trigger)');
    PERFORM pg_temp.expect_error(format('UPDATE grant_calls SET remaining_budget = -1 WHERE id = %s', v_call), '23514', 'the balance can never go negative (constraint)');
    PERFORM pg_temp.expect_error(format('UPDATE grant_calls SET total_budget = total_budget + 1 WHERE id = %s', v_call), '23514', 'the total budget is immutable (trigger)');
    PERFORM pg_temp.expect_error(format($f$UPDATE proposals SET status = 'approved' WHERE id = %s$f$, v_inreview), '23514', 'approved without a decision row is refused (trigger)');
    -- RFC 4231 test case 2: HMAC-SHA256 key "Jefe", data "what do ya want for nothing?"
    INSERT INTO guard_results SELECT encode(hmac_sha256('Jefe'::bytea, 'what do ya want for nothing?'::bytea), 'hex')
        = '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
        'the in-database HMAC-SHA256 matches the RFC 4231 test vector (actor tokens are verified with it)';
    -- A 131-byte key (longer than the block size) must be hashed first: RFC 4231 test case 6
    INSERT INTO guard_results SELECT encode(hmac_sha256(decode(repeat('aa', 131), 'hex'), 'Test Using Larger Than Block-Size Key - Hash Key First'::bytea), 'hex')
        = '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54',
        'the HMAC handles keys longer than the block size (RFC 4231 test case 6)';
    PERFORM pg_temp.expect_error('UPDATE audit_events SET outcome = ''success''', '42501', 'audit events cannot be updated, even by the owner');
    PERFORM pg_temp.expect_error('DELETE FROM audit_events', '42501', 'audit events cannot be deleted, even by the owner');
    PERFORM pg_temp.expect_error('TRUNCATE audit_events', '42501', 'audit events cannot be truncated, even by the owner');
END $$;

SELECT format('%s  OWNER %s', CASE WHEN ok THEN 'PASS' ELSE 'FAIL' END, claim) FROM guard_results;
SELECT format('%s owner-level guard checks, %s failed', count(*), count(*) FILTER (WHERE NOT ok)) FROM guard_results;
DO $$ BEGIN IF EXISTS (SELECT 1 FROM guard_results WHERE NOT ok) THEN RAISE EXCEPTION 'owner guard check failed'; END IF; END $$;
