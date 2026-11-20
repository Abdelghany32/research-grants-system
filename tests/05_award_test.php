<?php
declare(strict_types=1);
// Requirement: award integrity under concurrency. The workers are separate OS
// processes with independent database connections.
require_once __DIR__ . '/helpers_workflow.php';

test('AWARD two proposals compete for the same funds: one award, 3,000 remains', function (): void {
    $call = make_call('Competition call 10,000', '10000');
    $a = make_reviewed_proposal($call, 'amina.elidrissi', 'Competing proposal A', '7000');
    $b = make_reviewed_proposal($call, 'youssef.benali', 'Competing proposal B', '7000', 'karim.ouazzani');
    same('10000.00', call_balance($call), 'starting balance');

    $go = microtime(true) + 1.0;
    $w1 = start_award_worker($a, '7000.00', $go);
    $w2 = start_award_worker($b, '7000.00', $go);
    $results = [worker_result($w1), worker_result($w2)];

    $ok = array_values(array_filter($results, fn ($r) => $r['ok']));
    $no = array_values(array_filter($results, fn ($r) => !$r['ok']));
    same(1, count($ok), 'exactly one award succeeded');
    same('insufficient_funds', $no[0]['reason'] ?? null, 'the other was refused for insufficient funds');
    same('3000.00', $ok[0]['remaining'], 'winner saw 3,000 remaining');

    $nadia = T::user('nadia.berrada');
    same('3000.00', call_balance($call), 'final balance row');
    $decisions = T::sqlAs($nadia, 'SELECT proposal_id, outcome, awarded_amount FROM decisions WHERE proposal_id IN (?, ?)', [$a, $b])['rows'];
    same(1, count($decisions), 'exactly one decision row');
    same(['approved', '7000.00'], [$decisions[0]['outcome'], $decisions[0]['awarded_amount']], 'decision row values');
    $statuses = array_column(T::sqlAs($nadia, 'SELECT status FROM proposals WHERE id IN (?, ?) ORDER BY status', [$a, $b])['rows'], 'status');
    same(['approved', 'under_review'], $statuses, 'one approved, the other still under review');
    same(1, count(T::audit("action = 'decision.record' AND outcome = 'success' AND resource_id IN (?, ?)", [$a, $b])), 'one success event');
    $deniedEvents = T::audit("action = 'decision.record' AND outcome = 'denied' AND resource_id IN (?, ?)", [$a, $b]);
    same(1, count($deniedEvents), 'one denied event survived the rollback');
    same('insufficient_funds', json_decode($deniedEvents[0]['details'], true)['reason'], 'denied event carries the reason');
});

test('AWARD a duplicate click produces one decision and one deduction', function (): void {
    $call = make_call('Duplicate click call', '10000');
    $p = make_reviewed_proposal($call, 'amina.elidrissi', 'Double-clicked proposal', '4000');
    $go = microtime(true) + 1.0;
    $w1 = start_award_worker($p, '4000.00', $go);
    $w2 = start_award_worker($p, '4000.00', $go);
    $results = [worker_result($w1), worker_result($w2)];
    same(1, count(array_filter($results, fn ($r) => $r['ok'])), 'exactly one click succeeded');
    same('already_decided', array_values(array_filter($results, fn ($r) => !$r['ok']))[0]['reason'] ?? null, 'the other click was refused as already decided');
    same('6000.00', call_balance($call), 'funds deducted once');
    same(1, (int) T::sqlAs(T::user('nadia.berrada'), 'SELECT count(*) AS n FROM decisions WHERE proposal_id = ?', [$p])['rows'][0]['n'], 'one decision row');
});

test('AWARD the second decision really waits on the call lock (deterministic)', function (): void {
    $call = make_call('Lock observation call', '10000');
    $p = make_reviewed_proposal($call, 'youssef.benali', 'Lock observed proposal', '2500');
    $nadia = T::user('nadia.berrada');

    // Hold the call row exactly as recordDecision does, in an open transaction.
    $holder = T::newApp()->db()->pdo();
    $holder->beginTransaction();
    T::bindActor($holder, $nadia);
    $holder->prepare('SELECT 1 FROM grant_calls WHERE id = ? FOR NO KEY UPDATE')->execute([$call]);

    $worker = start_award_worker($p, '2500.00');
    $waiting = false;
    for ($i = 0; $i < 50 && !$waiting; $i++) {
        usleep(100_000);
        $waiting = (bool) T::rawRuntime()->query("SELECT count(*) FROM pg_stat_activity
            WHERE usename = current_user AND wait_event_type = 'Lock' AND query LIKE '%record_decision%'")->fetchColumn();
    }
    check($waiting, 'worker is blocked waiting for the row lock');
    same(0, (int) T::sqlAs($nadia, 'SELECT count(*) AS n FROM decisions WHERE proposal_id = ?', [$p])['rows'][0]['n'], 'nothing written while waiting');
    $holder->commit();
    same(['ok' => true, 'remaining' => '7500.00'], worker_result($worker), 'worker proceeds once the lock is released');
});

test('AWARD limits: requested amount, remaining budget, sequential repeat', function (): void {
    $wf = T::app()->workflow();
    $nadia = T::user('nadia.berrada');
    $call = make_call('Limits call', '5000');
    $big = make_reviewed_proposal($call, 'amina.elidrissi', 'Wants the whole budget', '5000');
    $small = make_reviewed_proposal($call, 'youssef.benali', 'Modest request', '1000', 'karim.ouazzani');
    denied('exceeds_requested', fn () => $wf->recordDecision($nadia, $small, 'approved', '1000.01', ''), 'one cent above the request');
    $wf->recordDecision($nadia, $small, 'approved', '1000', '');
    denied('insufficient_funds', fn () => $wf->recordDecision($nadia, $big, 'approved', '4000.01', ''), 'one cent above the balance');
    same('4000.00', call_balance($call), 'refused award changed nothing');
    $wf->recordDecision($nadia, $big, 'approved', '4000.00', '');
    same('0.00', call_balance($call), 'budget can be spent to exactly zero');
    denied('already_decided', fn () => $wf->recordDecision($nadia, $big, 'approved', '1', ''), 'sequential repeat');
    $declined = make_reviewed_proposal($call, 'amina.elidrissi', 'Arrives after the money is gone', '10');
    $wf->recordDecision($nadia, $declined, 'declined', '999', 'No funds left.');
    same('0.00', T::sqlAs($nadia, 'SELECT awarded_amount FROM decisions WHERE proposal_id = ?', [$declined])['rows'][0]['awarded_amount'], 'a decline always awards zero');
});

test('AWARD finding F01 remediated: the runtime account cannot commit part of an award', function (): void {
    $nadia = T::user('nadia.berrada');
    $inReview = T::proposalId('Seismic Retrofitting');
    // The exact probe of the original finding: insert the decision row on its own ...
    sqlstate('42501', fn () => T::sqlAs($nadia, "INSERT INTO decisions (proposal_id, outcome, awarded_amount, currency, decided_by) VALUES (?, 'approved', 1.00, 'MAD', ?)", [$inReview, $nadia->id]), 'a lone decision row is refused');
    // ... or move money on its own.
    $call = (int) T::sqlAs($nadia, 'SELECT call_id FROM proposals WHERE id = ?', [$inReview])['rows'][0]['call_id'];
    sqlstate('42501', fn () => T::sqlAs($nadia, 'UPDATE grant_calls SET remaining_budget = remaining_budget - 1 WHERE id = ?', [$call]), 'a lone balance change is refused');
    sqlstate('23514', fn () => T::sqlAs($nadia, "UPDATE proposals SET status = 'approved' WHERE id = ?", [$inReview]), 'a status change without the function is refused by the guard trigger (no decision row)');
});

test('AWARD record_decision() itself refuses anyone who is not an active officer, and an unknown actor', function (): void {
    $p = T::proposalId('Seismic Retrofitting');
    foreach (['amina.elidrissi', 'salma.tazi', 'omar.chraibi'] as $who) {
        sqlstate('42501', fn () => T::sqlAs(T::user($who), "SELECT * FROM record_decision(?, 'approved', 1, 'x')", [$p]), "$who cannot call the function");
    }
    sqlstate('42501', fn () => T::rawRuntime()->query("SELECT * FROM record_decision($p, 'approved', 1, 'x')"), 'no identity: refused');
});

test('AWARD record_decision() is atomic and audited by the database itself', function (): void {
    $nadia = T::user('nadia.berrada');
    $call = make_call('Atomic award call', '9000');
    $p = make_reviewed_proposal($call, 'amina.elidrissi', 'Atomic award proposal', '2000');
    // Called directly (no PHP workflow): decision, balance, status and audit event still move together.
    $r = T::sqlAs($nadia, "SELECT * FROM record_decision(?, 'approved', 1500, 'direct call')", [$p])['rows'][0];
    same('7500.00', $r['remaining'], 'balance lowered by the award');
    same('7500.00', call_balance($call), 'balance row agrees');
    same('approved', T::sqlAs($nadia, 'SELECT status FROM proposals WHERE id = ?', [$p])['rows'][0]['status'], 'proposal status moved');
    $events = T::audit("action = 'decision.record' AND outcome = 'success' AND resource_id = ?", [$p]);
    same(1, count($events), 'the function wrote its own audit event');
    same('officer', $events[0]['actor_role'], 'with the role looked up in the database');
    same('1500.00', json_decode($events[0]['details'], true)['awarded_amount'], 'and the amount');
    sqlstate('GR001', fn () => T::sqlAs($nadia, "SELECT * FROM record_decision(?, 'approved', 1, 'again')", [$p]), 'a second call for the same proposal is refused');
});

test('AWARD database backstops: unique decision, balance never rises or goes negative (as schema owner)', function (): void {
    // Runtime cannot even try, so the triggers and constraints are exercised as the
    // schema owner by tests/owner_guards.sql (run by scripts/test.sh). Here we check they exist.
    $r = T::rawRuntime()->query("SELECT count(*) FROM pg_constraint WHERE conrelid = 'grants.decisions'::regclass AND contype = 'u'")->fetchColumn();
    check($r >= 1, 'UNIQUE (proposal_id) exists on decisions');
    $c = T::rawRuntime()->query("SELECT count(*) FROM pg_constraint WHERE conrelid = 'grants.grant_calls'::regclass AND conname = 'grant_calls_balance_in_range'")->fetchColumn();
    same(1, (int) $c, 'balance range constraint exists');
});

test('AWARD invariant: for every call, remaining = total - sum of approved awards', function (): void {
    $rows = T::sqlAs(T::user('nadia.berrada'),
        "SELECT c.id, c.total_budget - c.remaining_budget AS spent,
                coalesce((SELECT sum(d.awarded_amount) FROM decisions d JOIN proposals p ON p.id = d.proposal_id
                           WHERE p.call_id = c.id AND d.outcome = 'approved'), 0)::numeric(14,2) AS awarded
           FROM grant_calls c ORDER BY c.id")['rows'];
    check(count($rows) >= 6, 'all calls inspected');
    foreach ($rows as $r) {
        same($r['awarded'], $r['spent'], "call {$r['id']}: spent equals awarded");
    }
});
