<?php
declare(strict_types=1);
// Requirement: RBAC and least privilege - human roles AND database accounts.

use App\Auth\Policy;

test('RBAC runtime account is not owner, not superuser, cannot bypass RLS', function (): void {
    $pdo = T::rawRuntime();
    $r = $pdo->query("SELECT rolsuper, rolbypassrls, rolcreatedb, rolcreaterole FROM pg_roles WHERE rolname = current_user")->fetch();
    same([false, false, false, false], array_values($r), 'no powerful attributes');
    $owners = $pdo->query("SELECT DISTINCT tableowner FROM pg_tables WHERE schemaname = 'grants'")->fetchAll(PDO::FETCH_COLUMN);
    same(['grants_owner'], $owners, 'tables are owned by grants_owner');
    $rls = $pdo->query("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                        WHERE n.nspname = 'grants' AND c.relname IN ('proposals','reviews','decisions','grant_calls') AND c.relrowsecurity")->fetchColumn();
    same(4, $rls, 'RLS enabled on the four workflow tables');
});

test('RBAC runtime account is refused everything outside its needs', function (): void {
    $refused = [
        'read the audit trail'        => 'SELECT * FROM audit_events',
        'insert an audit event (O03)'  => "INSERT INTO audit_events (action, outcome) VALUES ('x.y', 'success')",
        'read the actor key (O02)'     => 'SELECT * FROM actor_key',
        'run the HMAC helper'          => "SELECT hmac_sha256('a'::bytea, 'b'::bytea)",
        'edit the audit trail'        => "UPDATE audit_events SET outcome = 'success'",
        'delete audit events'         => 'DELETE FROM audit_events',
        'truncate audit events'       => 'TRUNCATE audit_events',
        'change a decision'           => 'UPDATE decisions SET awarded_amount = 1',
        'insert a decision directly (F01)' => "INSERT INTO decisions (proposal_id, outcome, awarded_amount, currency, decided_by) VALUES (1, 'approved', 1, 'MAD', 1)",
        'edit a call balance directly (F01)' => 'UPDATE grant_calls SET remaining_budget = 0',
        'read the login-failure table'  => 'SELECT * FROM login_failures',
        'forge a login failure'         => "INSERT INTO login_failures (source_ip) VALUES ('10.0.0.1')",
        'delete login failures'         => 'DELETE FROM login_failures',
        'unlock an account by SQL'      => 'UPDATE users SET locked_until = NULL',
        'delete a decision'           => 'DELETE FROM decisions',
        'delete a review'             => 'DELETE FROM reviews',
        'reassign a review'           => 'UPDATE reviews SET reviewer_id = 1',
        'create a user'               => "INSERT INTO users (email, full_name, department, role, password_hash) VALUES ('x@y.z','x','x','officer','x')",
        'promote a user'              => "UPDATE users SET role = 'officer'",
        'overwrite a password hash'   => "UPDATE users SET password_hash = 'x'",
        'delete a user'               => 'DELETE FROM users',
        'change a call budget total'  => 'UPDATE grant_calls SET total_budget = 1',
        'change a proposal owner'     => 'UPDATE proposals SET owner_id = 1',
        'create a table'              => 'CREATE TABLE grants.loot (x int)',
        'drop a table'                => 'DROP TABLE decisions',
        'disable row security'        => 'ALTER TABLE proposals DISABLE ROW LEVEL SECURITY',
    ];
    foreach ($refused as $what => $sql) {
        sqlstate('42501', fn () => T::rawRuntime()->exec($sql), "runtime account cannot $what");
    }
});

test('RBAC auditor account reads the audit view and nothing else', function (): void {
    $pdo = T::newApp()->auditorDb()->pdo();
    check($pdo->query('SELECT count(*) FROM audit_timeline')->fetchColumn() > 0, 'can read audit_timeline');
    foreach (['proposals', 'reviews', 'decisions', 'users', 'grant_calls', 'audit_events'] as $table) {
        sqlstate('42501', fn () => $pdo->query("SELECT * FROM $table"), "auditor account cannot read $table");
    }
    // First barrier: the account's sessions are read-only by default.
    sqlstate('25006', fn () => $pdo->exec("INSERT INTO audit_events (action, outcome) VALUES ('x.y', 'success')"), 'auditor sessions are read-only by default');
    // A user can switch that default off, so the real control is the missing privilege:
    $pdo->exec('SET default_transaction_read_only = off');
    sqlstate('42501', fn () => $pdo->exec("INSERT INTO audit_events (action, outcome) VALUES ('x.y', 'success')"), 'auditor cannot write events');
    sqlstate('55000', fn () => $pdo->exec('DELETE FROM audit_timeline'), 'the view is not updatable');
    $columns = $pdo->query("SELECT column_name FROM information_schema.columns WHERE table_schema = 'grants' AND table_name = 'audit_timeline'")->fetchAll(PDO::FETCH_COLUMN);
    same([], array_values(array_intersect($columns, ['abstract', 'title', 'comments_enc', 'password_hash', 'rationale'])), 'view exposes no content columns');
});

test('RBAC backup account cannot connect over the network', function (): void {
    $c = T::config()['db'];
    try {
        new PDO(sprintf('pgsql:host=%s;port=%s;dbname=%s;sslmode=require', $c['host'], $c['port'], $c['name']), 'grants_backup', 'any-password');
        check(false, 'connection must be refused');
    } catch (PDOException $e) {
        check(str_contains($e->getMessage(), 'pg_hba.conf rejects connection'), 'pg_hba.conf rejects the connection: ' . $e->getMessage());
    }
});

test('RBAC human-role permission matrix', function (): void {
    $expect = [
        'researcher' => ['proposal.write_own_draft' => true, 'proposal.submit' => true, 'review.write_assigned' => false, 'decision.record' => false, 'audit.read' => false],
        'reviewer'   => ['proposal.write_own_draft' => false, 'review.write_assigned' => true, 'review.assign' => false, 'decision.record' => false, 'audit.read' => false],
        'officer'    => ['proposal.write_own_draft' => false, 'review.write_assigned' => false, 'review.assign' => true, 'decision.record' => true, 'call.manage' => true, 'audit.read' => false],
        'auditor'    => ['proposal.read_own' => false, 'proposal.read_submitted' => false, 'decision.record' => false, 'audit.read' => true],
    ];
    $who = ['researcher' => 'amina.elidrissi', 'reviewer' => 'salma.tazi', 'officer' => 'nadia.berrada', 'auditor' => 'omar.chraibi'];
    foreach ($expect as $role => $permissions) {
        foreach ($permissions as $permission => $allowed) {
            same($allowed, Policy::can(T::user($who[$role]), $permission), "$role / $permission");
        }
    }
});

test('RBAC each role is refused the other roles\' pages (HTTP 403, audited)', function (): void {
    $forbidden = [
        'amina.elidrissi' => ['/officer', '/officer/calls', '/reviews', '/audit'],
        'salma.tazi'      => ['/proposals', '/officer', '/audit'],
        'nadia.berrada'   => ['/proposals', '/reviews', '/audit'],
        'omar.chraibi'    => ['/proposals', '/reviews', '/officer', '/officer/proposals/1'],
    ];
    $count = 0;
    foreach ($forbidden as $who => $paths) {
        $b = (new Browser())->login($who);
        foreach ($paths as $path) {
            same(403, $b->get($path)->status, "$who GET $path");
            $count++;
        }
    }
    check(count(T::audit("action = 'request.forbidden' AND outcome = 'denied'")) >= $count, 'every refusal recorded');
    same(303, (new Browser())->get('/officer')->status, 'anonymous visitor is sent to login');
});

test('RBAC workflow operations refuse the wrong role even when called directly', function (): void {
    $wf = T::app()->workflow();
    $p1 = T::proposalId('Federated Learning');
    denied('role_not_permitted', fn () => $wf->recordDecision(T::user('amina.elidrissi'), $p1, 'approved', '1', ''), 'researcher cannot decide');
    denied('role_not_permitted', fn () => $wf->recordDecision(T::user('salma.tazi'), $p1, 'approved', '1', ''), 'reviewer cannot decide');
    denied('role_not_permitted', fn () => $wf->assignReviewer(T::user('amina.elidrissi'), $p1, T::user('karim.ouazzani')->id, null), 'researcher cannot assign');
    denied('role_not_permitted', fn () => $wf->createDraft(T::user('nadia.berrada'), 1, ['title' => 'Officer draft', 'requested_amount' => '5']), 'officer cannot create proposals');
    denied('role_not_permitted', fn () => $wf->createCall(T::user('omar.chraibi'), ['title' => 'Auditor call', 'currency' => 'MAD', 'total_budget' => '5', 'closes_on' => gmdate('Y-m-d', time() + 86400)]), 'auditor cannot create calls');
});
