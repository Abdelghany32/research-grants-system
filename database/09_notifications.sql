-- 09_notifications.sql - e-mail notifications through a database OUTBOX.
--
--  * Messages are queued in the same transaction as the business change (atomic: no mail without the change, no
--    change whose mail was lost) by notify_enqueue(), a SECURITY DEFINER function that
--      - needs a valid actor token, and only lets the actor queue a message about their OWN action
--        (an officer who assigned a review, a reviewer who submitted one, an officer who decided a proposal);
--      - chooses the recipient itself from the database relations (the caller cannot address anyone);
--      - renders subject and body from fixed templates: no proposal title, abstract, amount, score or outcome ever
--        leaves in an e-mail - only "something needs you" and a link.
--    A stolen database password cannot send mail through it (no token), and the unique key means one message per
--    (kind, subject, recipient): it cannot be used to flood anybody.
--  * A separate account, grants_notifier, delivers the outbox (scripts/send-notifications.php). It can read the outbox
--    and the e-mail address and name of the recipient, mark messages sent, and queue due-date reminders. Nothing else.
-- Idempotent. Applied before 04_grants.sql.
\set ON_ERROR_STOP on
SET ROLE grants_owner;
SET search_path = grants, pg_catalog;

CREATE TABLE IF NOT EXISTS notifications (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    created_at  timestamptz NOT NULL DEFAULT now(),
    to_user_id  bigint      NOT NULL REFERENCES users (id),
    kind        text        NOT NULL CHECK (kind IN ('review_assigned', 'review_submitted', 'decision_recorded', 'review_due_soon', 'review_overdue')),
    ref_type    text        NOT NULL CHECK (ref_type IN ('review', 'proposal')),
    ref_id      bigint      NOT NULL,
    subject     text        NOT NULL CHECK (length(subject) BETWEEN 1 AND 200 AND subject !~ '[\r\n]'),
    body        text        NOT NULL CHECK (length(body) BETWEEN 1 AND 2000),
    sent_at     timestamptz,
    attempts    integer     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error  text        CHECK (length(last_error) <= 500),
    UNIQUE (kind, ref_type, ref_id, to_user_id)
);
CREATE INDEX IF NOT EXISTS notifications_pending_idx ON notifications (id) WHERE sent_at IS NULL;

-- Queue a message about the actor's own action. Returns the number of messages queued (0 if it was queued before).
CREATE OR REPLACE FUNCTION notify_enqueue(p_kind text, p_ref_id bigint, p_base_url text) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = grants, pg_temp AS $$
DECLARE
    v_actor bigint := current_actor_id();
    v_role  text   := current_actor_role();
    r       reviews%ROWTYPE;
    pr      proposals%ROWTYPE;
    n       integer := 0;
BEGIN
    IF v_actor IS NULL OR v_role IS NULL THEN
        RAISE EXCEPTION 'a valid actor token is required' USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF p_base_url !~ '^https?://[A-Za-z0-9.-]{1,100}(:[0-9]{1,5})?$' THEN
        RAISE EXCEPTION 'the base address is not a plain http(s) origin' USING ERRCODE = 'check_violation';
    END IF;

    IF p_kind = 'review_assigned' THEN
        SELECT * INTO r FROM reviews WHERE id = p_ref_id;
        IF NOT FOUND OR v_role <> 'officer' OR r.assigned_by <> v_actor THEN
            RAISE EXCEPTION 'you can only notify about a review you assigned' USING ERRCODE = 'insufficient_privilege';
        END IF;
        INSERT INTO notifications (to_user_id, kind, ref_type, ref_id, subject, body)
        VALUES (r.reviewer_id, p_kind, 'review', r.id, 'A proposal has been assigned to you for review',
                format(E'A proposal has been assigned to you for review.%s\n\nSign in to read it: %s/reviews/%s\n\nThis message contains no proposal details.',
                       CASE WHEN r.due_at IS NULL THEN '' ELSE E'\nReview due: ' || to_char(r.due_at AT TIME ZONE 'UTC', 'YYYY-MM-DD') END,
                       p_base_url, r.id))
        ON CONFLICT DO NOTHING;
    ELSIF p_kind = 'review_submitted' THEN
        SELECT * INTO r FROM reviews WHERE id = p_ref_id;
        IF NOT FOUND OR v_role <> 'reviewer' OR r.reviewer_id <> v_actor OR r.status <> 'submitted' THEN
            RAISE EXCEPTION 'you can only notify about a review you submitted' USING ERRCODE = 'insufficient_privilege';
        END IF;
        INSERT INTO notifications (to_user_id, kind, ref_type, ref_id, subject, body)
        VALUES (r.assigned_by, p_kind, 'review', r.id, 'A review has been submitted',
                format(E'A reviewer has submitted a review on a proposal you assigned.\n\nSign in to read it: %s/officer/proposals/%s\n\nThis message contains no proposal details.',
                       p_base_url, r.proposal_id))
        ON CONFLICT DO NOTHING;
    ELSIF p_kind = 'decision_recorded' THEN
        SELECT * INTO pr FROM proposals WHERE id = p_ref_id;
        IF NOT FOUND OR v_role <> 'officer' OR NOT EXISTS (SELECT 1 FROM decisions d WHERE d.proposal_id = pr.id AND d.decided_by = v_actor) THEN
            RAISE EXCEPTION 'you can only notify about a decision you recorded' USING ERRCODE = 'insufficient_privilege';
        END IF;
        INSERT INTO notifications (to_user_id, kind, ref_type, ref_id, subject, body)
        VALUES (pr.owner_id, p_kind, 'proposal', pr.id, 'A decision has been recorded on your proposal',
                format(E'A decision has been recorded on your proposal.\n\nSign in to read it: %s/proposals/%s\n\nThis message does not contain the decision.',
                       p_base_url, pr.id))
        ON CONFLICT DO NOTHING;
    ELSE
        RAISE EXCEPTION 'unknown notification kind' USING ERRCODE = 'check_violation';
    END IF;
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END $$;

-- Due-date reminders, queued by the notifier's periodic run: 48 hours before the deadline, and once it has passed
-- (to the reviewer and to the officer who assigned the review). Each is queued once.
CREATE OR REPLACE FUNCTION notify_enqueue_reminders(p_base_url text) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = grants, pg_temp AS $$
DECLARE
    n integer := 0; total integer := 0;
BEGIN
    IF NOT pg_has_role(session_user, 'grants_notifier_group', 'member') THEN
        RAISE EXCEPTION 'only the notifier account queues reminders' USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF p_base_url !~ '^https?://[A-Za-z0-9.-]{1,100}(:[0-9]{1,5})?$' THEN
        RAISE EXCEPTION 'the base address is not a plain http(s) origin' USING ERRCODE = 'check_violation';
    END IF;

    INSERT INTO notifications (to_user_id, kind, ref_type, ref_id, subject, body)
    SELECT r.reviewer_id, 'review_due_soon', 'review', r.id, 'A review is due within 48 hours',
           format(E'A review assigned to you is due on %s.\n\nSign in to finish it: %s/reviews/%s\n\nThis message contains no proposal details.',
                  to_char(r.due_at AT TIME ZONE 'UTC', 'YYYY-MM-DD'), p_base_url, r.id)
      FROM reviews r JOIN proposals p ON p.id = r.proposal_id
     WHERE r.status = 'assigned' AND p.status = 'under_review' AND r.due_at > now() AND r.due_at <= now() + interval '48 hours'
    ON CONFLICT DO NOTHING;
    GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

    INSERT INTO notifications (to_user_id, kind, ref_type, ref_id, subject, body)
    SELECT r.reviewer_id, 'review_overdue', 'review', r.id, 'A review is overdue',
           format(E'A review assigned to you is past its deadline. Ask the grants office for an extension.\n\nSign in: %s/reviews/%s\n\nThis message contains no proposal details.',
                  p_base_url, r.id)
      FROM reviews r JOIN proposals p ON p.id = r.proposal_id
     WHERE r.status = 'assigned' AND p.status = 'under_review' AND r.due_at < now()
    ON CONFLICT DO NOTHING;
    GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

    INSERT INTO notifications (to_user_id, kind, ref_type, ref_id, subject, body)
    SELECT r.assigned_by, 'review_overdue', 'review', r.id, 'A review you assigned is overdue',
           format(E'A review you assigned is past its deadline. You can extend it on the proposal page.\n\nSign in: %s/officer/proposals/%s\n\nThis message contains no proposal details.',
                  p_base_url, r.proposal_id)
      FROM reviews r JOIN proposals p ON p.id = r.proposal_id
     WHERE r.status = 'assigned' AND p.status = 'under_review' AND r.due_at < now()
    ON CONFLICT DO NOTHING;
    GET DIAGNOSTICS n = ROW_COUNT; total := total + n;
    RETURN total;
END $$;
