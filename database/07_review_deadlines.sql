-- 07_review_deadlines.sql - review deadlines are enforced by the DATABASE, not only by the screens.
--
--  * A reviewer can no longer save or submit a review after its due_at (the guard trigger refuses it, whatever
--    code or SQL tries).
--  * Only a grants officer can move a deadline, only forwards (an extension), and only while the review is still
--    open; an officer acting on a review can change nothing else about it.
--  * A new assignment cannot be created with a deadline in the past.
-- Idempotent. Applied after 06_identity_and_audit.sql and before 04_grants.sql.
\set ON_ERROR_STOP on
SET ROLE grants_owner;
SET search_path = grants, pg_catalog;

CREATE OR REPLACE FUNCTION reviews_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = grants, pg_temp AS $$
DECLARE
    p proposals%ROWTYPE;
    v_role text := current_actor_role();
BEGIN
    SELECT * INTO p FROM proposals WHERE id = NEW.proposal_id;
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'assigned' OR NEW.score IS NOT NULL OR NEW.comments_enc IS NOT NULL THEN
            RAISE EXCEPTION 'an assignment starts empty' USING ERRCODE = 'check_violation';
        END IF;
        IF p.status NOT IN ('submitted','under_review') THEN
            RAISE EXCEPTION 'reviewers can only be assigned to submitted proposals' USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.reviewer_id = p.owner_id THEN
            RAISE EXCEPTION 'self-review is not allowed' USING ERRCODE = 'check_violation';
        END IF;
        IF NOT EXISTS (SELECT 1 FROM users WHERE id = NEW.reviewer_id AND role = 'reviewer' AND is_active) THEN
            RAISE EXCEPTION 'assignee is not an active reviewer' USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.due_at IS NOT NULL AND NEW.due_at <= clock_timestamp() THEN
            RAISE EXCEPTION 'the review deadline must be in the future' USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.status = 'submitted' THEN
        RAISE EXCEPTION 'a finalized review cannot be changed' USING ERRCODE = 'check_violation';
    END IF;
    IF (NEW.proposal_id, NEW.reviewer_id, NEW.assigned_by, NEW.assigned_at)
       IS DISTINCT FROM (OLD.proposal_id, OLD.reviewer_id, OLD.assigned_by, OLD.assigned_at) THEN
        RAISE EXCEPTION 'assignment fields are immutable' USING ERRCODE = 'check_violation';
    END IF;
    IF p.status <> 'under_review' THEN
        RAISE EXCEPTION 'the proposal is no longer under review' USING ERRCODE = 'check_violation';
    END IF;

    -- Moving a deadline: a grants officer only, only later, and nothing else changes in the same statement.
    IF NEW.due_at IS DISTINCT FROM OLD.due_at THEN
        IF v_role IS DISTINCT FROM 'officer' THEN
            RAISE EXCEPTION 'only a grants officer can change a review deadline' USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.due_at IS NULL OR (OLD.due_at IS NOT NULL AND NEW.due_at <= OLD.due_at) THEN
            RAISE EXCEPTION 'a review deadline can only be extended' USING ERRCODE = 'check_violation';
        END IF;
        IF (NEW.score, NEW.comments_enc, NEW.status) IS DISTINCT FROM (OLD.score, OLD.comments_enc, OLD.status) THEN
            RAISE EXCEPTION 'a deadline change cannot also change the review' USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;
    -- An officer has no business editing a review's content (the policy lets officers reach open reviews only to extend them).
    IF v_role = 'officer' THEN
        RAISE EXCEPTION 'officers can only extend the deadline of a review' USING ERRCODE = 'check_violation';
    END IF;

    -- The reviewer's work closes at the deadline (an officer can extend it first).
    IF OLD.due_at IS NOT NULL AND clock_timestamp() > OLD.due_at
       AND (NEW.status = 'submitted' OR NEW.score IS DISTINCT FROM OLD.score OR NEW.comments_enc IS DISTINCT FROM OLD.comments_enc) THEN
        RAISE EXCEPTION 'the review deadline has passed' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.status = 'submitted' THEN
        NEW.submitted_at := now();
    END IF;
    RETURN NEW;
END $$;

DROP POLICY IF EXISTS reviews_officer_extend ON reviews;
CREATE POLICY reviews_officer_extend ON reviews FOR UPDATE TO grants_runtime
    USING (current_actor_role() = 'officer' AND status = 'assigned')
    WITH CHECK (current_actor_role() = 'officer' AND status = 'assigned');
