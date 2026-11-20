-- 02_schema.sql - tables, constraints, helper functions and guard triggers.
-- Run as superuser; everything is created as grants_owner.
\set ON_ERROR_STOP on
SET ROLE grants_owner;
CREATE SCHEMA grants AUTHORIZATION grants_owner;
SET search_path = grants, pg_catalog;

-- ------------------------------------------------------------------ tables
CREATE TABLE users (
    id                 bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    email              text        NOT NULL UNIQUE
                       CHECK (email = lower(email) AND email LIKE '%_@_%'),
    full_name          text        NOT NULL CHECK (length(btrim(full_name)) BETWEEN 1 AND 120),
    department         text        NOT NULL CHECK (length(department) <= 120),
    role               text        NOT NULL CHECK (role IN ('researcher','reviewer','officer','auditor')),
    password_hash      text        NOT NULL,          -- Argon2id PHC string, never plaintext
    is_active          boolean     NOT NULL DEFAULT true,
    failed_login_count integer     NOT NULL DEFAULT 0 CHECK (failed_login_count >= 0),
    locked_until       timestamptz,
    last_login_at      timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE grant_calls (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    title            text          NOT NULL CHECK (length(btrim(title)) BETWEEN 3 AND 200),
    description      text          NOT NULL DEFAULT '' CHECK (length(description) <= 4000),
    currency         text          NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),   -- ISO 4217
    total_budget     numeric(14,2) NOT NULL CHECK (total_budget > 0),
    remaining_budget numeric(14,2) NOT NULL,
    opens_at         timestamptz   NOT NULL DEFAULT now(),
    closes_at        timestamptz   NOT NULL,
    status           text          NOT NULL DEFAULT 'open' CHECK (status IN ('open','closed')),
    created_by       bigint        NOT NULL REFERENCES users (id),
    created_at       timestamptz   NOT NULL DEFAULT now(),
    CONSTRAINT grant_calls_balance_in_range CHECK (remaining_budget >= 0 AND remaining_budget <= total_budget),
    CONSTRAINT grant_calls_window CHECK (closes_at > opens_at),
    UNIQUE (id, currency)          -- target of the composite FK that pins a proposal's currency
);

CREATE TABLE proposals (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    call_id          bigint        NOT NULL,
    owner_id         bigint        NOT NULL REFERENCES users (id),
    title            text          NOT NULL CHECK (length(btrim(title)) BETWEEN 3 AND 200),
    abstract         text          NOT NULL DEFAULT '' CHECK (length(abstract) <= 5000),
    requested_amount numeric(14,2) NOT NULL CHECK (requested_amount > 0),
    currency         text          NOT NULL,
    status           text          NOT NULL DEFAULT 'draft'
                     CHECK (status IN ('draft','submitted','under_review','approved','declined')),
    created_at       timestamptz   NOT NULL DEFAULT now(),
    updated_at       timestamptz   NOT NULL DEFAULT now(),
    submitted_at     timestamptz,
    FOREIGN KEY (call_id, currency) REFERENCES grant_calls (id, currency),
    UNIQUE (id, currency),
    CONSTRAINT proposals_submitted_at_matches_status CHECK ((status = 'draft') = (submitted_at IS NULL))
);
CREATE INDEX proposals_owner_idx ON proposals (owner_id);
CREATE INDEX proposals_call_idx  ON proposals (call_id);

CREATE TABLE reviews (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    proposal_id  bigint      NOT NULL REFERENCES proposals (id),
    reviewer_id  bigint      NOT NULL REFERENCES users (id),
    assigned_by  bigint      NOT NULL REFERENCES users (id),
    assigned_at  timestamptz NOT NULL DEFAULT now(),
    due_at       timestamptz,
    status       text        NOT NULL DEFAULT 'assigned' CHECK (status IN ('assigned','submitted')),
    score        smallint    CHECK (score BETWEEN 1 AND 10),
    comments_enc text,       -- private comments, encrypted by the PHP service (XChaCha20-Poly1305)
    submitted_at timestamptz,
    UNIQUE (proposal_id, reviewer_id),
    CONSTRAINT reviews_final_is_complete
        CHECK (status <> 'submitted' OR (score IS NOT NULL AND submitted_at IS NOT NULL))
);
CREATE INDEX reviews_reviewer_idx ON reviews (reviewer_id);

CREATE TABLE decisions (
    id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    proposal_id    bigint        NOT NULL UNIQUE,        -- one final decision per proposal
    outcome        text          NOT NULL CHECK (outcome IN ('approved','declined')),
    awarded_amount numeric(14,2) NOT NULL CHECK (awarded_amount >= 0),
    currency       text          NOT NULL,
    rationale      text          NOT NULL DEFAULT '' CHECK (length(rationale) <= 2000),
    decided_by     bigint        NOT NULL REFERENCES users (id),
    decided_at     timestamptz   NOT NULL DEFAULT now(),
    FOREIGN KEY (proposal_id, currency) REFERENCES proposals (id, currency),
    CONSTRAINT decisions_amount_matches_outcome
        CHECK ((outcome = 'approved' AND awarded_amount > 0) OR (outcome = 'declined' AND awarded_amount = 0))
);

CREATE TABLE audit_events (
    id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at    timestamptz NOT NULL DEFAULT clock_timestamp(),   -- wall clock, not transaction start
    actor_id       bigint      REFERENCES users (id),                -- NULL: not authenticated
    actor_role     text,                                             -- effective role at that moment
    action         text        NOT NULL CHECK (action ~ '^[a-z_]+\.[a-z_]+$'),
    resource_type  text,
    resource_id    bigint,
    outcome        text        NOT NULL CHECK (outcome IN ('success','denied','failure')),
    correlation_id uuid,                                             -- one per HTTP request
    source_ip      inet,
    details        jsonb       NOT NULL DEFAULT '{}'                 -- metadata only, never proposal text
);
CREATE INDEX audit_events_time_idx        ON audit_events (occurred_at DESC);
CREATE INDEX audit_events_correlation_idx ON audit_events (correlation_id);

-- --------------------------------------------------------- identity helpers
-- The PHP service states WHO is acting (app.user_id, transaction-local).
-- The database decides WHAT that person may do: the role is looked up here,
-- not taken from the application.
CREATE FUNCTION current_actor_id() RETURNS bigint
LANGUAGE sql STABLE AS
$$ SELECT nullif(current_setting('app.user_id', true), '')::bigint $$;

CREATE FUNCTION current_actor_role() RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = grants, pg_temp AS
$$ SELECT role FROM users WHERE id = current_actor_id() AND is_active $$;

-- SECURITY DEFINER helpers let one table's policy consult another table
-- without triggering that table's own policies (avoids policy recursion).
CREATE FUNCTION is_assigned_reviewer(p_proposal_id bigint) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = grants, pg_temp AS
$$ SELECT EXISTS (SELECT 1 FROM reviews
                  WHERE proposal_id = p_proposal_id AND reviewer_id = current_actor_id()) $$;

CREATE FUNCTION owns_proposal(p_proposal_id bigint) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = grants, pg_temp AS
$$ SELECT EXISTS (SELECT 1 FROM proposals
                  WHERE id = p_proposal_id AND owner_id = current_actor_id()) $$;

-- Login happens before an identity exists. The runtime account has no SELECT
-- on users.password_hash; it can only fetch the one row matching an email.
CREATE FUNCTION auth_find_credentials(p_email text)
RETURNS TABLE (id bigint, password_hash text, is_active boolean,
               failed_login_count integer, locked_until timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = grants, pg_temp AS
$$ SELECT u.id, u.password_hash, u.is_active, u.failed_login_count, u.locked_until
   FROM users u WHERE u.email = lower(p_email) $$;

-- ------------------------------------------------------------ guard triggers
-- Backstop for the PHP workflow: even a buggy or bypassed application cannot
-- skip a state, edit submitted content, or rewrite history.
CREATE FUNCTION proposals_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = grants, pg_temp AS $$
DECLARE
    call_open boolean;
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.status <> 'draft' THEN
            RAISE EXCEPTION 'only drafts can be deleted' USING ERRCODE = 'check_violation';
        END IF;
        RETURN OLD;
    END IF;

    SELECT status = 'open' AND now() >= opens_at AND now() < closes_at INTO call_open
    FROM grant_calls WHERE id = NEW.call_id;

    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'draft' THEN
            RAISE EXCEPTION 'a proposal starts as a draft' USING ERRCODE = 'check_violation';
        END IF;
        IF NOT coalesce(call_open, false) THEN
            RAISE EXCEPTION 'the grant call is not open' USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.owner_id <> OLD.owner_id OR NEW.call_id <> OLD.call_id OR NEW.currency <> OLD.currency THEN
        RAISE EXCEPTION 'owner, call and currency are immutable' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.status <> 'draft' AND (NEW.title, NEW.abstract, NEW.requested_amount)
                                 IS DISTINCT FROM (OLD.title, OLD.abstract, OLD.requested_amount) THEN
        RAISE EXCEPTION 'a submitted proposal cannot be edited' USING ERRCODE = 'check_violation';
    END IF;

    IF OLD.status = 'draft' AND NEW.status = 'draft' THEN
        NULL;                                             -- ordinary draft edit
    ELSIF OLD.status = 'draft' AND NEW.status = 'submitted' THEN
        IF NOT coalesce(call_open, false) THEN
            RAISE EXCEPTION 'the submission deadline has passed' USING ERRCODE = 'check_violation';
        END IF;
        IF length(btrim(NEW.abstract)) < 20 THEN
            RAISE EXCEPTION 'an abstract is required to submit' USING ERRCODE = 'check_violation';
        END IF;
        NEW.submitted_at := now();
    ELSIF OLD.status = 'submitted' AND NEW.status = 'under_review' THEN
        NULL;
    ELSIF OLD.status = 'under_review' AND NEW.status IN ('approved','declined') THEN
        IF NOT EXISTS (SELECT 1 FROM decisions d WHERE d.proposal_id = NEW.id AND d.outcome = NEW.status) THEN
            RAISE EXCEPTION 'status % requires a matching decision row', NEW.status USING ERRCODE = 'check_violation';
        END IF;
    ELSE
        RAISE EXCEPTION 'illegal status transition % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END $$;
CREATE TRIGGER proposals_guard BEFORE INSERT OR UPDATE OR DELETE ON proposals
    FOR EACH ROW EXECUTE FUNCTION proposals_guard();

CREATE FUNCTION reviews_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = grants, pg_temp AS $$
DECLARE
    p proposals%ROWTYPE;
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
    IF NEW.status = 'submitted' THEN
        NEW.submitted_at := now();
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER reviews_guard BEFORE INSERT OR UPDATE ON reviews
    FOR EACH ROW EXECUTE FUNCTION reviews_guard();

CREATE FUNCTION decisions_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = grants, pg_temp AS $$
DECLARE
    p proposals%ROWTYPE;
BEGIN
    SELECT * INTO p FROM proposals WHERE id = NEW.proposal_id;
    IF p.status <> 'under_review' THEN
        RAISE EXCEPTION 'only a proposal under review can be decided' USING ERRCODE = 'check_violation';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM reviews WHERE proposal_id = NEW.proposal_id AND status = 'submitted') THEN
        RAISE EXCEPTION 'a completed review is required' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.awarded_amount > p.requested_amount THEN
        RAISE EXCEPTION 'award exceeds the requested amount' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER decisions_guard BEFORE INSERT ON decisions
    FOR EACH ROW EXECUTE FUNCTION decisions_guard();

CREATE FUNCTION grant_calls_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.total_budget, NEW.currency, NEW.created_by) IS DISTINCT FROM (OLD.total_budget, OLD.currency, OLD.created_by) THEN
        RAISE EXCEPTION 'budget total, currency and creator are immutable' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.remaining_budget > OLD.remaining_budget THEN
        RAISE EXCEPTION 'remaining budget can only decrease' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER grant_calls_guard BEFORE UPDATE ON grant_calls
    FOR EACH ROW EXECUTE FUNCTION grant_calls_guard();

-- The audit trail is append-only for everyone, including the table owner.
CREATE FUNCTION audit_events_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only' USING ERRCODE = 'insufficient_privilege';
END $$;
CREATE TRIGGER audit_events_no_change BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_immutable();
CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION audit_events_immutable();

-- What the auditor account may read: event metadata plus the actor's name.
-- No proposal text and no review comments exist in this view or its source.
CREATE VIEW audit_timeline AS
SELECT e.id, e.occurred_at, e.actor_id, u.email AS actor_email, u.full_name AS actor_name,
       e.actor_role, e.action, e.resource_type, e.resource_id, e.outcome,
       e.correlation_id, e.source_ip, e.details
FROM audit_events e LEFT JOIN users u ON u.id = e.actor_id;
