<?php
declare(strict_types=1);
// Behavioural checks against a RESTORED database, as the restricted accounts.
// usage: DB_NAME=grants_drill php scripts/verify_restore.php
require __DIR__ . '/../src/bootstrap.php';
require __DIR__ . '/../tests/support.php';

$db = getenv('DB_NAME');
if (!in_array($db, ['grants_restore', 'grants_drill'], true)) {
    fwrite(STDERR, "DB_NAME must be a restore target\n");
    exit(2);
}
$server = proc_open(['php', '-S', '127.0.0.1:8097', '-t', __DIR__ . '/../public', __DIR__ . '/../public/index.php'],
    [['file', '/dev/null', 'r'], ['file', '/dev/null', 'w'], ['file', '/dev/null', 'w']], $pipes);
register_shutdown_function(static fn () => proc_terminate($server));
for ($i = 0; $i < 50 && !@fsockopen('127.0.0.1', 8097); $i++) { usleep(100_000); }

echo "restored database: $db, runtime account: " . T::rawRuntime()->query('SELECT current_user')->fetchColumn() . "\n";

test('RESTORE row-level security is active: no identity, no rows', function (): void {
    same(0, T::rawRuntime()->query('SELECT count(*) FROM proposals')->fetchColumn(), 'fails closed');
    same(8, T::rawRuntime()->query("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'grants' AND c.relrowsecurity")->fetchColumn(), 'RLS flag restored on 8 tables (4 with policies, 4 deny-by-default)');
    same(18, T::rawRuntime()->query("SELECT count(*) FROM pg_policies WHERE schemaname = 'grants'")->fetchColumn(), 'all 18 policies restored');
});
test('RESTORE researchers still see only their own proposals', function (): void {
    foreach (['amina.elidrissi', 'youssef.benali'] as $who) {
        $u = T::user($who);
        same([['owner_id' => $u->id]], T::sqlAs($u, 'SELECT DISTINCT owner_id FROM proposals')['rows'], $who);
    }
    same(0, T::sqlAs(T::user('karim.ouazzani'), 'SELECT count(*) AS n FROM reviews WHERE id = 1')['rows'][0]['n'], 'unassigned reviewer still blocked');
});
test('RESTORE privileges came back with the data', function (): void {
    sqlstate('42501', fn () => T::rawRuntime()->query('SELECT password_hash FROM users'), 'runtime cannot read hashes');
    sqlstate('42501', fn () => T::rawRuntime()->exec('DELETE FROM audit_events'), 'runtime cannot delete audit events');
    sqlstate('42501', fn () => T::rawRuntime()->exec('UPDATE decisions SET awarded_amount = 0'), 'runtime cannot change decisions');
    sqlstate('42501', fn () => T::app()->auditorDb()->pdo()->query('SELECT * FROM proposals'), 'auditor account cannot read proposals');
    check(T::app()->auditorDb()->pdo()->query('SELECT count(*) FROM audit_timeline')->fetchColumn() > 0, 'auditor account reads the timeline');
});
test('RESTORE guard triggers are back (decisions final, audit append-only)', function (): void {
    $nadia = T::user('nadia.berrada');
    sqlstate('42501', fn () => T::sqlAs($nadia, "INSERT INTO decisions (proposal_id, outcome, awarded_amount, currency, decided_by) VALUES (1, 'approved', 1, 'MAD', ?)", [$nadia->id]), 'a decision cannot be inserted directly (F01)');
    sqlstate('42501', fn () => T::sqlAs($nadia, 'UPDATE grant_calls SET remaining_budget = remaining_budget + 1 WHERE id = 1'), 'the balance cannot be edited directly (F01)');
    $decided = (int) T::sqlAs($nadia, 'SELECT proposal_id FROM decisions ORDER BY id LIMIT 1')['rows'][0]['proposal_id'];
    sqlstate('GR001', fn () => T::sqlAs($nadia, "SELECT * FROM record_decision(?, 'approved', 1, 'x')", [$decided]), 'record_decision() refuses a second decision');
});
test('RESTORE identity binding, audit separation, second factor and outbox came back too', function (): void {
    $officer = T::user('nadia.berrada');
    $pdo = T::rawRuntime();
    $pdo->beginTransaction();
    $pdo->exec("SELECT set_config('app.user_id', '{$officer->id}', true)");
    same(0, (int) $pdo->query('SELECT count(*) FROM proposals')->fetchColumn(), 'a self-asserted identity still shows nothing');
    $pdo->rollBack();
    same($officer->id, (int) T::sqlAs($officer, 'SELECT current_actor_id() AS id')['rows'][0]['id'], 'a valid actor token still proves identity (the key was restored with the data)');
    sqlstate('42501', fn () => T::rawRuntime()->exec("INSERT INTO audit_events (action, outcome) VALUES ('x.y', 'success')"), 'the web account still cannot write audit events');
    same(true, T::identitySqlAs($officer, 'SELECT enrolled FROM mfa_state(?)', [$officer->id])['rows'][0]['enrolled'], 'the officer is still enrolled in two-step sign-in');
    check((int) T::rawAs('notifier_user', 'notifier_password')->query('SELECT count(*) FROM notifications')->fetchColumn() >= 0, 'the notification outbox is readable by the notifier account');
});
test('RESTORE funds remaining and the awarded decision have the expected values', function (): void {
    $nadia = T::user('nadia.berrada');
    same('450000.00', T::sqlAs($nadia, 'SELECT remaining_budget FROM grant_calls WHERE id = 1')['rows'][0]['remaining_budget'], 'AI call balance after the 150,000 award');
    same('195000.00', T::sqlAs($nadia, 'SELECT remaining_budget FROM grant_calls WHERE id = 2')['rows'][0]['remaining_budget'], 'infrastructure call balance');
    same(['approved', '150000.00'], array_values(T::sqlAs($nadia, 'SELECT outcome, awarded_amount FROM decisions WHERE proposal_id = 1')['rows'][0]), 'decision row');
});
test('RESTORE encrypted review comments decrypt with the separately stored key', function (): void {
    $p = T::app()->queries()->proposalForDecision(T::user('nadia.berrada'), 1);
    check(str_contains($p['reviews'][0]['comments'], 'threat model'), 'authorized decryption works on restored data');
    check(preg_match('/^v[12]:/', T::sqlAs(T::user('nadia.berrada'), 'SELECT comments_enc FROM reviews WHERE id = 1')['rows'][0]['comments_enc']) === 1, 'still ciphertext in the restored table');
});
test('RESTORE an authorized user can sign in and work against the restored database', function (): void {
    $b = (new Browser('http://127.0.0.1:8097'))->login('amina.elidrissi');
    same(303, $b->status, 'login succeeds with the original password');
    $page = $b->get('/proposals');
    check(str_contains($page->body, 'Federated Learning') && str_contains($page->body, 'Approved'), 'inbox shows the restored, approved proposal');
    check(!str_contains($page->body, 'Seismic'), 'and nothing from another researcher');
    same(401, (new Browser('http://127.0.0.1:8097'))->login('amina.elidrissi', 'wrong')->status, 'wrong password still refused');
});

$failed = count(array_filter(T::$results, static fn (array $r): bool => $r[1] !== null));
printf("%d checks, %d assertions, %d failed\n", count(T::$results), T::$assertions, $failed);
exit($failed ? 1 : 0);
