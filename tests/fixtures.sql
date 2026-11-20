-- Test-only fixtures (grants_test). Two situations the normal screens cannot
-- create on demand, built here as the schema owner.
\set ON_ERROR_STOP on
SET ROLE grants_owner;
SET search_path = grants, pg_catalog;

-- (a) A researcher submitted a proposal and LATER became a reviewer.
--     The officer must not be able to assign them to their own proposal.
INSERT INTO users (email, full_name, department, role, password_hash)
VALUES ('rachid.fixture@uni.example', 'Dr. Rachid Fixture', 'Physics', 'researcher', '!no-login');
INSERT INTO proposals (call_id, owner_id, title, abstract, requested_amount, currency)
SELECT (SELECT min(id) FROM grant_calls), u.id, 'Fixture: proposal by a future reviewer', repeat('x', 40), 1000, 'MAD'
FROM users u WHERE u.email = 'rachid.fixture@uni.example';
UPDATE proposals SET status = 'submitted' WHERE title = 'Fixture: proposal by a future reviewer';
UPDATE users SET role = 'reviewer' WHERE email = 'rachid.fixture@uni.example';

-- (b) A call whose deadline has passed while a draft was still open.
INSERT INTO grant_calls (title, currency, total_budget, remaining_budget, opens_at, closes_at, created_by)
SELECT 'Fixture: expired call', 'MAD', 5000, 5000, now() - interval '10 days', now() + interval '1 day', id
FROM users WHERE role = 'officer' LIMIT 1;
INSERT INTO proposals (call_id, owner_id, title, abstract, requested_amount, currency)
SELECT c.id, u.id, 'Fixture: draft in an expired call', repeat('y', 40), 1000, 'MAD'
FROM grant_calls c, users u WHERE c.title = 'Fixture: expired call' AND u.email = 'amina.elidrissi@uni.example';
UPDATE grant_calls SET closes_at = now() - interval '1 day' WHERE title = 'Fixture: expired call';

-- (c) A review whose deadline has already passed by the time the tests run (due 2 seconds after the fixtures load).
INSERT INTO proposals (call_id, owner_id, title, abstract, requested_amount, currency)
SELECT (SELECT min(id) FROM grant_calls WHERE title NOT LIKE 'Fixture%'), u.id, 'Fixture: review past its deadline', repeat('z', 40), 1000, 'MAD'
FROM users u WHERE u.email = 'youssef.benali@uni.example';
UPDATE proposals SET status = 'submitted' WHERE title = 'Fixture: review past its deadline';
INSERT INTO reviews (proposal_id, reviewer_id, assigned_by, due_at)
SELECT p.id, (SELECT id FROM users WHERE email = 'salma.tazi@uni.example'), (SELECT id FROM users WHERE role = 'officer' LIMIT 1), now() + interval '2 seconds'
FROM proposals p WHERE p.title = 'Fixture: review past its deadline';
UPDATE proposals SET status = 'under_review' WHERE title = 'Fixture: review past its deadline';

-- (d) An officer who has not enrolled a second factor yet (test-only account; password "Fixture-Officer-9!").
INSERT INTO users (email, full_name, department, role, password_hash)
VALUES ('newofficer.fixture@uni.example', 'Fixture Officer', 'Research Office', 'officer', '$argon2id$v=19$m=65536,t=4,p=1$WHJFSlFUeFlIbkc0d1lzaw$oXqFEUGK+6tRR1JQ3D+3xoNtbBaDWi4OO25uUdKHKCg');
