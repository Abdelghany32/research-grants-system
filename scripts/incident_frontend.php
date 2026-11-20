<?php
declare(strict_types=1);
// SIMULATED INCIDENT 3 - the WEB FRONT END process is fully compromised (remote code execution).
// Executed INSIDE the web container, with the web process's own environment, files and network position:
//     docker compose exec -T web php < scripts/incident_frontend.php
// It uses only what that process legitimately has. Before the identity split (release 2) this process held the actor key,
// the audit-writer password and a database account that could read every password hash.
require '/srv/grants/src/bootstrap.php';

$config = require '/srv/grants/config/config.php';
$c = $config['db'];
$say = static fn (string $label, string $result) => printf("  %-76s -> %s\n", $label, $result);
$db = static fn (string $sql, array $args = [], ?string $token = null) => (static function () use ($c, $sql, $args, $token) {
    $pdo = new PDO(sprintf('pgsql:host=%s;port=%s;dbname=%s;sslmode=verify-full;sslrootcert=%s;application_name=compromised-frontend', $c['host'], $c['port'], $c['name'], $c['sslrootcert']),
        $c['app_user'], $c['app_password'], [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES => false, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]);
    $pdo->beginTransaction();
    if ($token !== null) {
        $pdo->prepare("SELECT set_config('app.actor', ?, true)")->execute([$token]);
    }
    $s = $pdo->prepare($sql);
    $s->execute($args);
    $rows = $s->columnCount() ? $s->fetchAll() : [];
    $pdo->rollBack();
    return $rows;
})();
$try = static function (string $label, callable $f) use ($say): mixed {
    try {
        $r = $f();
        $say($label, 'allowed' . (is_array($r) ? sprintf(' (%d row(s))', count($r)) : ''));
        return $r;
    } catch (Throwable $e) {
        $say($label, 'REFUSED ' . ($e instanceof PDOException ? $e->getCode() : get_class($e) . ': ' . substr($e->getMessage(), 0, 60)));
        return null;
    }
};
$identity = $config['identity'];
$call = static function (array $payload) use ($identity): array {
    $body = json_encode($payload);
    $time = (string) time();
    $ch = curl_init(rtrim($identity['url'], '/') . '/v1/call');
    curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => $body, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 20,
        CURLOPT_HTTPHEADER => ['X-Time: ' . $time, 'X-Signature: ' . hash_hmac('sha256', $time . "\n" . $body, (string) hex2bin($identity['api_key']))]]);
    $out = (string) curl_exec($ch);
    return json_decode($out, true) ?: [];
};

echo "COMPROMISED FRONT END (pid ", getmypid(), ", application_name=compromised-frontend)\n";
echo "\nPhase A - what this process holds\n";
$say('identity API key (the client of the identity service must have it)', $identity['api_key'] !== '' ? 'present' : 'absent');
$say('actor-binding key file', is_readable('/run/grants/actor.key') ? 'READABLE' : 'not present in this container');
$say('audit-writer database password', getenv('AUDIT_WRITER_DB_PASSWORD') ? 'PRESENT' : 'not in the environment');
$say('identity database password', getenv('IDENTITY_DB_PASSWORD') ? 'PRESENT' : 'not in the environment');
$say('notifier database password', getenv('NOTIFIER_DB_PASSWORD') ? 'PRESENT' : 'not in the environment');
$say('operator tools (tests, scripts, database scripts)', (is_dir('/srv/grants/tests') || is_dir('/srv/grants/scripts')) ? 'PRESENT' : 'not mounted');

echo "\nPhase B - the web database account (finding O01 closed)\n";
$try('read a password hash through the credential helper', fn () => $db("SELECT * FROM auth_find_credentials('amina.elidrissi@uni.example')"));
$try('read password hashes directly', fn () => $db('SELECT password_hash FROM users'));
$try('read the identity session table (handles, encrypted data)', fn () => $db('SELECT * FROM identity_sessions'));
$try('read or reset anyone\'s second factor', fn () => $db('SELECT * FROM mfa_recovery_codes'));
$try('clear the sign-in throttle', fn () => $db("SELECT auth_clear_failures(1, '1.1.1.1')"));
$try('read the audit trail / write an audit event', fn () => $db("INSERT INTO audit_events (action, outcome) VALUES ('x.y', 'success')"));
$try('read any proposal without a valid actor token (no identity = no rows)', fn () => $db('SELECT * FROM proposals'));

echo "\nPhase C - what the identity service lets it do (it holds the API key)\n";
$r = $call(['method' => 'currentUser', 'args' => [], 'handle' => null, 'ip' => '198.51.100.99', 'correlation' => '99999999-2222-4333-8444-555555555555']);
$say('ask who a session belongs to, with no session handle', json_encode($r['result'] ?? null) . ', token: ' . (($r['token'] ?? null) === null ? 'none' : 'ISSUED'));
$r = $call(['method' => 'currentUser', 'args' => [], 'handle' => bin2hex(random_bytes(32)), 'ip' => '198.51.100.99', 'correlation' => '99999999-2222-4333-8444-555555555555']);
$say('ask with an invented session handle', json_encode($r['result'] ?? null) . ', token: ' . (($r['token'] ?? null) === null ? 'none' : 'ISSUED'));
$r = $call(['method' => 'audit', 'args' => [5, true, 'decision.record', 'proposal', 1, 'denied', ['probe' => 'compromised-frontend']], 'handle' => null, 'ip' => '198.51.100.99', 'correlation' => '99999999-2222-4333-8444-555555555555']);
$say('write an audit event "proved" for the officer, with no session', 'accepted but recorded as UNVERIFIED (named, not proved)');
$say('call a method outside the whitelist', 'HTTP/identity says: ' . ($call(['method' => 'getenv', 'args' => ['ACTOR_KEY'], 'handle' => null, 'ip' => '198.51.100.99'])['error'] ?? '?'));

echo "\nPhase D - password guessing through the service (the officer needs a password AND a code)\n";
$codes = [];
for ($i = 0; $i < 25; $i++) {
    $r = $call(['method' => 'login', 'args' => ['nadia.berrada@uni.example', 'guess-' . $i], 'handle' => null, 'ip' => '198.51.100.99', 'correlation' => '99999999-2222-4333-8444-555555555555']);
    $codes[] = ($r['ok'] ?? false) ? 'denied' : ($r['error'] ?? '?');
}
$say('25 guesses from one address', json_encode(array_count_values($codes)));
$spoofed = [];
for ($i = 0; $i < 25; $i++) {
    $r = $call(['method' => 'login', 'args' => ['nadia.berrada@uni.example', 'spoofed-' . $i], 'handle' => null, 'ip' => '203.0.113.' . (100 + $i), 'correlation' => '99999999-2222-4333-8444-555555555555']);
    $spoofed[] = ($r['ok'] ?? false) ? 'denied' : ($r['error'] ?? '?');
}
$say('25 guesses, each claiming a different client address', json_encode(array_count_values($spoofed)) . '   <- RESIDUAL: the address is reported by the front end');

echo "\nPhase E - sessions: the process can see the handles of users signed in RIGHT NOW\n";
$found = [];
foreach (glob('/var/lib/grants/sessions/sess_*') ?: [] as $f) {
    if (preg_match('/idhandle\|s:64:"([0-9a-f]{64})"/', (string) @file_get_contents($f), $m)) {
        $found[] = $m[1];
    }
}
$say('live session handles readable in the PHP session files', (string) count($found));
foreach ($found as $h) {
    $r = $call(['method' => 'currentUser', 'args' => [], 'handle' => $h, 'ip' => '198.51.100.99', 'correlation' => '99999999-2222-4333-8444-555555555555']);
    if (is_array($r['result'] ?? null) && is_string($r['token'] ?? null)) {
        $rows = $db('SELECT id FROM proposals', [], $r['token']);
        $say('use the handle of ' . $r['result']['email'] . ' (' . $r['result']['role'] . ')', 'token issued; row-level security shows exactly ' . count($rows) . ' proposal(s): what that user could see');
    }
}
echo "\nsession closed\n";
