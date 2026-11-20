<?php
declare(strict_types=1);
// Requirement: auditing. Events are append-only, survive rollbacks when they
// record a refusal, and never contain proposal text or review comments.
require_once __DIR__ . '/helpers_workflow.php';

test('AUDIT a denied action is recorded although its transaction rolled back', function (): void {
    $nadia = T::user('nadia.berrada');
    $call = make_call('Rollback evidence call', '100');
    $p = make_reviewed_proposal($call, 'amina.elidrissi', 'Asks for more than exists', '100');
    T::app()->workflow()->recordDecision($nadia, make_reviewed_proposal($call, 'youssef.benali', 'Takes most of it', '60', 'karim.ouazzani'), 'approved', '60', '');
    $before = count(T::audit('resource_id = ? AND action = ?', [$p, 'decision.record']));
    denied('insufficient_funds', fn () => T::app()->workflow()->recordDecision($nadia, $p, 'approved', '100', ''), 'award refused');
    $events = T::audit('resource_id = ? AND action = ?', [$p, 'decision.record']);
    same($before + 1, count($events), 'one new event');
    same(['denied', $nadia->id, 'officer'], [$events[0]['outcome'], $events[0]['actor_id'], $events[0]['actor_role']], 'event names the effective actor and outcome');
    same(0, (int) T::sqlAs($nadia, 'SELECT count(*) AS n FROM decisions WHERE proposal_id = ?', [$p])['rows'][0]['n'], 'no decision row exists (rolled back)');
    same('40.00', call_balance($call), 'balance untouched by the refused award');
});

test('AUDIT a success event commits or rolls back together with its change', function (): void {
    $amina = T::user('amina.elidrissi');
    $before = count(T::audit("action = 'proposal.create'"));
    try {
        T::app()->db()->asActor($amina->id, function (PDO $tx) use ($amina): void {
            $tx->exec("INSERT INTO proposals (call_id, owner_id, title, requested_amount, currency) VALUES (1, {$amina->id}, 'Will be rolled back', 10, 'MAD')");
            T::app()->audit()->withChange($tx, $amina, 'proposal.create', 'proposal', null);
            throw new RuntimeException('simulated crash before commit');
        });
    } catch (RuntimeException) {
    }
    same($before, count(T::audit("action = 'proposal.create'")), 'no orphan success event');
    same([], T::sqlAs($amina, "SELECT id FROM proposals WHERE title = 'Will be rolled back'")['rows'], 'no orphan change');
});

test('AUDIT events carry actor, UTC time, action, resource, outcome and a correlation ID', function (): void {
    $b = (new Browser())->login('nadia.berrada');
    $p = T::proposalId('Federated Learning');
    $b->get('/officer/proposals/' . $p);
    $e = T::audit('id = (SELECT max(id) FROM audit_timeline WHERE action = ? AND resource_id = ?)', ['proposal.view', $p])[0];
    same(['nadia.berrada@uni.example', 'officer', 'proposal', 'success'], [$e['actor_email'], $e['actor_role'], $e['resource_type'], $e['outcome']], 'who / what / result');
    check((bool) preg_match('/^[0-9a-f-]{36}$/', $e['correlation_id']), 'correlation ID is a UUID');
    check(str_ends_with($e['occurred_at'], '+00'), 'timestamp is reported in UTC: ' . $e['occurred_at']);
    check(abs(strtotime($e['occurred_at']) - time()) < 30, 'timestamp is the wall-clock time of the event');
    same('127.0.0.1', $e['source_ip'], 'source address recorded');
});

test('AUDIT no proposal text or review comment ever enters the audit trail', function (): void {
    $all = T::audit('true');
    check(count($all) > 100, 'a substantial trail exists (' . count($all) . ' events)');
    $blob = json_encode($all);
    foreach (['doctoral students', 'threat model', 'excellent team', 'Federated Learning', 'Confidential:'] as $secret) {
        check(!str_contains($blob, $secret), "trail does not contain \"$secret\"");
    }
});

test('AUDIT auditor timeline page filters by outcome and shows no content', function (): void {
    $b = (new Browser())->login('omar.chraibi');
    $page = $b->get('/audit?outcome=denied');
    same(200, $page->status, 'timeline loads');
    check(substr_count($page->body, 'class="outcome-denied"') > 5, 'denied events listed');
    same(0, substr_count($page->body, 'class="outcome-success"'), 'no success rows under the denied filter');
    $page = $b->get('/audit?action=decision.record&outcome=success');
    check(substr_count($page->body, 'class="outcome-success"') > 3 && !str_contains($page->body, 'class="outcome-denied"'), 'combined filters work');
    check(!str_contains($page->body, 'Federated Learning') && !str_contains($page->body, 'threat model'), 'no proposal text on the page');
    same(200, $b->get('/audit?from=not-a-date&outcome=' . rawurlencode("' OR 1=1 --") . '&correlation=zzz')->status, 'malformed filters are ignored safely');
    check(count(T::audit("action = 'audit.view' AND actor_email = 'omar.chraibi@uni.example'")) >= 3, 'reading the trail is itself recorded');
    check(!str_contains($b->get('/audit')->body, '<form method="post" action="/audit'), 'the screen offers no way to change events');
});
