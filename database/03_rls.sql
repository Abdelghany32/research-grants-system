-- 03_rls.sql - row-level security. Policies apply to grants_runtime (the PHP
-- service). With no app.user_id set, current_actor_role() is NULL and every
-- policy evaluates to "no rows": a missing identity fails closed.
-- RLS is ENABLEd but not FORCEd: the owner is NOLOGIN and the SECURITY DEFINER
-- helpers above rely on owner access to avoid policy recursion.
\set ON_ERROR_STOP on
SET ROLE grants_owner;
SET search_path = grants, pg_catalog;

ALTER TABLE grant_calls ENABLE ROW LEVEL SECURITY;
ALTER TABLE proposals   ENABLE ROW LEVEL SECURITY;
ALTER TABLE reviews     ENABLE ROW LEVEL SECURITY;
ALTER TABLE decisions   ENABLE ROW LEVEL SECURITY;

-- grant_calls: readable by the three workflow roles, managed by officers.
CREATE POLICY calls_read ON grant_calls FOR SELECT TO grants_runtime
    USING (current_actor_role() IN ('researcher','reviewer','officer'));
CREATE POLICY calls_create ON grant_calls FOR INSERT TO grants_runtime
    WITH CHECK (current_actor_role() = 'officer' AND created_by = current_actor_id());
CREATE POLICY calls_manage ON grant_calls FOR UPDATE TO grants_runtime
    USING (current_actor_role() = 'officer') WITH CHECK (current_actor_role() = 'officer');

-- proposals
CREATE POLICY proposals_owner_read ON proposals FOR SELECT TO grants_runtime
    USING (current_actor_role() = 'researcher' AND owner_id = current_actor_id());
CREATE POLICY proposals_reviewer_read ON proposals FOR SELECT TO grants_runtime
    USING (current_actor_role() = 'reviewer' AND status <> 'draft' AND is_assigned_reviewer(id));
CREATE POLICY proposals_officer_read ON proposals FOR SELECT TO grants_runtime
    USING (current_actor_role() = 'officer' AND status <> 'draft');
CREATE POLICY proposals_owner_create ON proposals FOR INSERT TO grants_runtime
    WITH CHECK (current_actor_role() = 'researcher' AND owner_id = current_actor_id() AND status = 'draft');
CREATE POLICY proposals_owner_edit ON proposals FOR UPDATE TO grants_runtime
    USING (current_actor_role() = 'researcher' AND owner_id = current_actor_id() AND status = 'draft')
    WITH CHECK (current_actor_role() = 'researcher' AND owner_id = current_actor_id() AND status IN ('draft','submitted'));
CREATE POLICY proposals_officer_progress ON proposals FOR UPDATE TO grants_runtime
    USING (current_actor_role() = 'officer' AND status IN ('submitted','under_review'))
    WITH CHECK (current_actor_role() = 'officer' AND status IN ('under_review','approved','declined'));
CREATE POLICY proposals_owner_delete ON proposals FOR DELETE TO grants_runtime
    USING (current_actor_role() = 'researcher' AND owner_id = current_actor_id() AND status = 'draft');

-- reviews: the researcher has no policy at all, so private notes stay hidden.
CREATE POLICY reviews_reviewer_read ON reviews FOR SELECT TO grants_runtime
    USING (current_actor_role() = 'reviewer' AND reviewer_id = current_actor_id());
CREATE POLICY reviews_officer_read ON reviews FOR SELECT TO grants_runtime
    USING (current_actor_role() = 'officer');
CREATE POLICY reviews_officer_assign ON reviews FOR INSERT TO grants_runtime
    WITH CHECK (current_actor_role() = 'officer' AND assigned_by = current_actor_id());
CREATE POLICY reviews_reviewer_write ON reviews FOR UPDATE TO grants_runtime
    USING (current_actor_role() = 'reviewer' AND reviewer_id = current_actor_id() AND status = 'assigned')
    WITH CHECK (current_actor_role() = 'reviewer' AND reviewer_id = current_actor_id());

-- decisions: officers record them, the proposal owner may read the outcome.
CREATE POLICY decisions_officer_read ON decisions FOR SELECT TO grants_runtime
    USING (current_actor_role() = 'officer');
CREATE POLICY decisions_owner_read ON decisions FOR SELECT TO grants_runtime
    USING (current_actor_role() = 'researcher' AND owns_proposal(proposal_id));
CREATE POLICY decisions_officer_record ON decisions FOR INSERT TO grants_runtime
    WITH CHECK (current_actor_role() = 'officer' AND decided_by = current_actor_id());
