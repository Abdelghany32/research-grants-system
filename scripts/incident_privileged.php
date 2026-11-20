<?php
declare(strict_types=1);
// SIMULATED INCIDENT 2 - a stolen service credential (lab only, disposable grants_test).
// This plays the attacker: someone holding the grants_app DATABASE password connects from inside the Docker
// network, outside any HTTP request. They do NOT hold secrets/actor.key (that file lives only in the web process).
// Every step prints its SQLSTATE so the investigator (scripts/incident-privileged.sh) can match it with the logs.
// Compare with docs/evidence/incident-privileged-before-binding.txt (the same attack before findings O02/O03 were fixed).
if (PHP_SAPI !== 'cli' || getenv('PENTEST_LAB') !== '1' || getenv('DB_NAME') !== 'grants_test') {
    fwrite(STDERR, "Requires CLI, PENTEST_LAB=1 and the disposable grants_test database.\n");
    exit(2);
}
require __DIR__ . '/../src/bootstrap.php';

$c = (require __DIR__ . '/../config/config.php')['db'];
$pdo = new PDO(sprintf('pgsql:host=%s;port=%s;dbname=%s;sslmode=verify-full;sslrootcert=%s;application_name=stolen-credential',
    $c['host'], $c['port'], $c['name'], $c['sslrootcert']), $c['app_user'], $c['app_password'],
    [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES => false]);

$try = static function (string $label, string $sql, array $args = []) use ($pdo): ?array {
    try {
        $s = $pdo->prepare($sql);
        $s->execute($args);
        $returns = $s->columnCount() > 0;
        $rows = $returns ? $s->fetchAll() : [];
        printf("  %-66s -> allowed (%s)\n", $label, $returns ? count($rows) . ' row(s) returned' : $s->rowCount() . ' row(s) affected');
        return $rows;
    } catch (PDOException $e) {
        printf("  %-66s -> REFUSED %s\n", $label, $e->getCode());
        return null;
    }
};

printf("ATTACKER SESSION as %s (pid %d), application_name=stolen-credential\n", $pdo->query('SELECT current_user')->fetchColumn(), $pdo->query('SELECT pg_backend_pid()')->fetchColumn());
echo "\nPhase A - reconnaissance with the stolen credential\n";
$try('read the audit trail', 'SELECT * FROM audit_events');
$try('read password hashes', 'SELECT password_hash FROM users');
$users = $try('list every account (e-mail, name, role)', 'SELECT id, email, full_name, role FROM users ORDER BY id');
$try('read login-failure records', 'SELECT * FROM login_failures');
$try('read the actor-binding key', 'SELECT * FROM actor_key');

echo "\nPhase B - claim an officer identity (findings O02: now refused)\n";
$officer = (int) array_values(array_filter($users, static fn ($u) => $u['role'] === 'officer'))[0]['id'];
$pdo->beginTransaction();
$pdo->prepare("SELECT set_config('app.user_id', ?, true)")->execute([(string) $officer]);            // the old, self-asserted claim
$legacy = $try('read every submitted proposal with the old app.user_id claim', "SELECT id, title, status FROM proposals WHERE status <> 'draft'");
$forgedToken = (new App\Security\ActorToken(random_bytes(32)))->mint($officer);                       // signed with a key the attacker invented
$pdo->prepare("SELECT set_config('app.actor', ?, true)")->execute([$forgedToken]);
$try('read every submitted proposal with a self-signed actor token', "SELECT id, title, status FROM proposals WHERE status <> 'draft'");
$target = (int) $pdo->query("SELECT p.id FROM proposals p WHERE p.status = 'under_review' AND EXISTS (SELECT 1 FROM reviews r WHERE r.proposal_id = p.id AND r.status = 'submitted') AND NOT EXISTS (SELECT 1 FROM decisions d WHERE d.proposal_id = p.id) ORDER BY p.id LIMIT 1")->fetchColumn() ?: 1;

echo "\nPhase C - attempts to move money (findings F01 and O02)\n";
foreach (['insert a lone decision row' => ["INSERT INTO decisions (proposal_id, outcome, awarded_amount, currency, decided_by) VALUES (?, 'approved', 1.00, 'MAD', ?)", [$target, $officer]],
          'lower the call balance on its own' => ['UPDATE grant_calls SET remaining_budget = remaining_budget - 1 WHERE id = (SELECT call_id FROM proposals WHERE id = ?)', [$target]]] as $label => [$sql, $args]) {
    $pdo->exec('SAVEPOINT s');
    if ($try($label, $sql, $args) === null) { $pdo->exec('ROLLBACK TO SAVEPOINT s'); }
}

echo "\nPhase D - the one door that used to be open: record_decision() with the claimed identity\n";
$pdo->exec('SAVEPOINT s');
$r = $try('award 1.00 through the function with the forged token', "SELECT * FROM record_decision(?, 'approved', 1.00, 'unauthorised award by stolen credential')", [$target]);
if ($r === null) { $pdo->exec('ROLLBACK TO SAVEPOINT s'); }
$pdo->commit();

echo "\nPhase E - covering tracks, and forging a record (finding O03: now refused)\n";
foreach (['edit audit events' => "UPDATE audit_events SET outcome = 'failure' WHERE action = 'decision.record'",
          'delete audit events' => 'DELETE FROM audit_events WHERE action = \'decision.record\'',
          'truncate audit events' => 'TRUNCATE audit_events'] as $label => $sql) {
    $try($label, $sql);
}
$victim = (int) array_values(array_filter($users, static fn ($u) => $u['role'] === 'researcher'))[0]['id'];
$try('forge an audit event that frames a researcher (direct INSERT)',
    "INSERT INTO audit_events (actor_id, actor_role, action, resource_type, resource_id, outcome, details) VALUES (?, 'researcher', 'proposal.delete', 'proposal', ?, 'success', '{}')", [$victim, $target]);
$try('forge the same event through audit_append() with a forged token',
    "SELECT audit_append('proposal.delete', 'proposal', ?, 'success', '{}'::jsonb, NULL, NULL, ?, ?)", [$target, $victim, (new App\Security\ActorToken(random_bytes(32)))->mint($victim)]);
$try('forge it through audit_append() with no token at all',
    "SELECT audit_append('proposal.delete', 'proposal', ?, 'success', '{}'::jsonb, NULL, NULL, ?, NULL)", [$target, $victim]);
echo "\nsession closed\n";
