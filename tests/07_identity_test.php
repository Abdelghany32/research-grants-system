<?php
declare(strict_types=1);
// Requirement: observations O02 and O03 closed - identity is PROVED to the database, audit events cannot be forged.

/** Run $body inside a transaction on a fresh runtime connection with $setup applied; always rolled back. */
function with_claim(callable $setup, callable $body): mixed
{
    $pdo = T::rawRuntime();
    $pdo->beginTransaction();
    try {
        $setup($pdo);
        return $body($pdo);
    } finally {
        $pdo->rollBack();
    }
}

test('IDENT a forged, expired, altered or legacy identity claim yields no identity at all', function (): void {
    $officer = T::user('nadia.berrada');
    $count = static fn (PDO $pdo): int => (int) $pdo->query('SELECT count(*) FROM proposals')->fetchColumn();
    $claim = static fn (string $token) => static fn (PDO $pdo) => $pdo->prepare("SELECT set_config('app.actor', ?, true)")->execute([$token]);

    same(0, with_claim(static fn (PDO $p) => $p->exec("SELECT set_config('app.user_id', '{$officer->id}', true)"), $count), 'the old app.user_id claim is ignored');
    $valid = T::actorToken($officer->id);
    check(with_claim($claim($valid), $count) > 0, 'a valid token gives the officer their rows (positive control)');

    $parts = explode('.', $valid);
    $badMac = implode('.', array_merge(array_slice($parts, 0, 4), [str_repeat('0', 64)]));
    same(0, with_claim($claim($badMac), $count), 'wrong signature');
    $otherUser = implode('.', array_merge([$parts[0], (string) T::user('amina.elidrissi')->id], array_slice($parts, 2)));
    same(0, with_claim($claim($otherUser), $count), 'a token re-labelled for another user');
    $asAnother = implode('.', array_merge([$parts[0], (string) ($officer->id + 1000)], array_slice($parts, 2)));
    same(0, with_claim($claim($asAnother), $count), 'a user id that does not exist');
    same(0, with_claim($claim(T::actorToken($officer->id, -5)), $count), 'an expired token');
    same(0, with_claim($claim(T::actorToken($officer->id, 3600)), $count), 'a token claiming an hour of life');
    $foreign = (new App\Security\ActorToken(random_bytes(32)))->mint($officer->id);
    same(0, with_claim($claim($foreign), $count), 'a token signed with a different key');
    foreach (['', 'v1', 'v2.1.2.3.4', str_repeat('a', 5000), "v1.1.9999999999.ab'--.00"] as $junk) {
        same(0, with_claim($claim($junk), $count), 'malformed token ' . substr($junk, 0, 12));
    }
});

test('IDENT a stolen database password cannot act as an officer or move money (O02)', function (): void {
    $officer = T::user('nadia.berrada');
    $p = T::proposalId('Seismic Retrofitting');
    // The attacker has the runtime password but not secrets/actor.key: the claim they CAN make is worthless.
    $seen = with_claim(static fn (PDO $pdo) => $pdo->exec("SELECT set_config('app.user_id', '{$officer->id}', true)"),
        static fn (PDO $pdo): int => (int) $pdo->query('SELECT count(*) FROM proposals')->fetchColumn());
    same(0, $seen, 'claiming to be the officer shows no proposal');
    sqlstate('42501', fn () => with_claim(static fn (PDO $pdo) => $pdo->exec("SELECT set_config('app.user_id', '{$officer->id}', true)"),
        static fn (PDO $pdo) => $pdo->query("SELECT * FROM record_decision($p, 'approved', 1, 'x')")), 'record_decision() refuses a claim without proof');
});

test('IDENT the web account cannot write audit events; a token is required and must match the named actor (O03)', function (): void {
    $amina = T::user('amina.elidrissi');
    $salma = T::user('salma.tazi');
    sqlstate('42501', fn () => T::rawRuntime()->exec("INSERT INTO audit_events (action, outcome) VALUES ('x.y', 'success')"), 'no direct INSERT');
    $call = "SELECT audit_append('proposal.delete', 'proposal', 1, 'success', '{}'::jsonb, NULL, NULL, ?, ?)";
    $pdo = T::rawRuntime();
    sqlstate('42501', function () use ($pdo, $call, $amina): void { $pdo->prepare($call)->execute([$amina->id, null]); }, 'a named actor without a token is refused');
    sqlstate('42501', function () use ($pdo, $call, $amina): void { $pdo->prepare($call)->execute([$amina->id, 'v1.' . $amina->id . '.9999999999.aabbccdd.' . str_repeat('0', 64)]); }, 'a forged token is refused');
    sqlstate('42501', function () use ($pdo, $call, $amina, $salma): void { $pdo->prepare($call)->execute([$amina->id, T::actorToken($salma->id)]); }, 'a valid token for someone else cannot name another actor');
    $id = $pdo->prepare($call);
    $id->execute([$amina->id, T::actorToken($amina->id)]);
    $eventId = (int) $id->fetchColumn();
    $ev = T::audit('id = ?', [$eventId])[0];
    same('researcher', $ev['actor_role'], 'the role comes from the database, not from the caller');
    same(true, $ev['actor_verified'], 'an event backed by a valid token is marked verified');
});

test('IDENT the audit-writer account can record only unauthenticated events and refusals, and nothing else', function (): void {
    $w = T::rawAs('audit_writer_user', 'audit_writer_password');
    same('grants_audit_write', $w->query('SELECT current_user')->fetchColumn(), 'separate account');
    $ins = $w->prepare("SELECT audit_append(?, 'user', ?, ?, '{}'::jsonb, NULL, '203.0.113.9', ?, NULL)");
    $ins->execute(['auth.login', T::user('omar.chraibi')->id, 'denied', T::user('omar.chraibi')->id]);
    $ev = T::audit('id = ?', [(int) $ins->fetchColumn()])[0];
    same(false, $ev['actor_verified'], 'a login failure names an account but proves nothing: unverified');
    same('auditor', $ev['actor_role'], 'role looked up by the database');
    sqlstate('42501', function () use ($w): void { $w->prepare("SELECT audit_append('decision.record', 'proposal', 1, 'success', '{}'::jsonb, NULL, NULL, 5, NULL)")->execute(); }, 'a success event for a decision cannot be written without proof');
    sqlstate('42501', function () use ($w): void { $w->prepare("SELECT audit_append('proposal.delete', 'proposal', 1, 'success', '{}'::jsonb, NULL, NULL, 2, NULL)")->execute(); }, 'nor a deletion by a researcher');
    foreach (['SELECT * FROM users', 'SELECT * FROM audit_events', 'SELECT * FROM proposals', 'SELECT * FROM actor_key', "SELECT * FROM record_decision(1, 'approved', 1, 'x')", "SELECT auth_clear_failures(1, '1.1.1.1')"] as $sql) {
        sqlstate('42501', fn () => $w->query($sql), "writer cannot: $sql");
    }
});

test('IDENT events written by the application say whether their actor was proved', function (): void {
    $b = (new Browser())->login('amina.elidrissi');
    $b->get('/proposals/' . T::proposalId('Seismic'));        // a denied read by an authenticated user
    $denied = T::audit("action = 'proposal.view' AND outcome = 'denied' AND actor_id = ? ", [T::user('amina.elidrissi')->id]);
    same(true, end($denied)['actor_verified'], 'a refusal for a signed-in user is verified');
    (new Browser())->login('amina.elidrissi', 'wrong-password-here');
    $fail = T::audit("action = 'auth.login' AND details->>'reason' = 'bad_password'");
    same(false, end($fail)['actor_verified'], 'a failed sign-in is not');
    $ok = T::audit("action = 'auth.login' AND outcome = 'success' AND actor_id = ?", [T::user('amina.elidrissi')->id]);
    same(true, end($ok)['actor_verified'], 'a successful sign-in is');
    $decision = T::audit("action = 'decision.record' AND outcome = 'success'");
    check(count($decision) > 0, 'a decision event exists');
    same(true, end($decision)['actor_verified'], 'decisions written by record_decision() are verified');
    T::forgiveFailures();
});
