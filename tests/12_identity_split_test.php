<?php
declare(strict_types=1);
// Requirement: the web front end and the identity service are separate processes with separate secrets; a compromised
// front end (or a stolen web database password) gets no password hash, no actor key and no identity it was not given.

use App\App;
use App\Identity\IdentityClient;
use App\Security\ActorToken;

/** One signed call to the test identity service (port 8095). $sign = false/override to test the signature check. */
function identity_call(array $payload, ?string $time = null, ?string $signature = null, bool $raw = false, string $method = 'POST', string $path = '/v1/call'): array
{
    $body = $raw ? (string) $payload['raw'] : json_encode($payload, JSON_THROW_ON_ERROR);
    $time ??= (string) time();
    $key = (string) hex2bin((string) getenv('IDENTITY_API_KEY'));
    $signature ??= hash_hmac('sha256', $time . "\n" . $body, $key);
    $ch = curl_init('http://127.0.0.1:8095' . $path);
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_CUSTOMREQUEST => $method, CURLOPT_POSTFIELDS => $method === 'POST' ? $body : null,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'X-Time: ' . $time, 'X-Signature: ' . $signature], CURLOPT_TIMEOUT => 20]);
    $out = (string) curl_exec($ch);
    $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    unset($ch);
    return ['status' => $status, 'json' => json_decode($out, true)];
}

function id_payload(string $method, array $args = [], ?string $handle = null): array
{
    return ['method' => $method, 'args' => $args, 'handle' => $handle, 'ip' => '203.0.113.31', 'correlation' => '11111111-2222-4333-8444-555555555555'];
}

test('SPLIT the identity service refuses unsigned, mis-signed, stale and malformed calls', function (): void {
    $p = id_payload('currentUser');
    same(200, identity_call($p)['status'], 'a correctly signed call is accepted (positive control)');
    same(401, identity_call($p, null, str_repeat('0', 64))['status'], 'wrong signature');
    same(401, identity_call($p, (string) (time() - 120))['status'], 'a stale timestamp (the signature is checked against it)');
    $old = (string) (time() - 120);
    same(401, identity_call($p, $old, hash_hmac('sha256', $old . "\n" . json_encode($p), (string) hex2bin((string) getenv('IDENTITY_API_KEY'))))['status'], 'a correctly signed but stale request is refused');
    same(401, identity_call($p, 'abc')['status'], 'a malformed timestamp');
    same(400, identity_call(['raw' => '{not json'], null, null, true)['status'], 'malformed JSON (signed)');
    same(400, identity_call(id_payload('shell_exec', ['id']))['status'], 'a method outside the whitelist');
    same(400, identity_call(id_payload('__construct'))['status'], 'a constructor is not a method either');
    same(404, identity_call($p, null, null, false, 'GET')['status'], 'GET is not an API');
    same(404, identity_call($p, null, null, false, 'POST', '/v1/other')['status'], 'nor is any other path');
    same(401, identity_call(['raw' => str_repeat('a', 70000)], null, null, true)['status'], 'an oversized body is refused before it is parsed');
    $health = curl_init('http://127.0.0.1:8095/health');
    curl_setopt($health, CURLOPT_RETURNTRANSFER, true);
    same('ok', curl_exec($health), 'the unsigned health endpoint answers nothing but "ok"');
});

test('SPLIT sessions are opaque handles; the database holds only a hash and encrypted data', function (): void {
    T::forgiveFailures('203.0.113.31');
    $login = identity_call(id_payload('login', ['amina.elidrissi@uni.example', T::password('amina.elidrissi')]));
    $j = $login['json'];
    same(true, $j['ok'], 'login through the service');
    check(preg_match('/^[0-9a-f]{64}$/', (string) $j['handle']) === 1, 'the handle is 256 random bits');
    check($j['user']['email'] === 'amina.elidrissi@uni.example' && is_string($j['token']), 'the reply names the user and carries an actor token');
    $id = T::rawAs('identity_user', 'identity_password');
    $row = $id->query('SELECT encode(handle_hash, \'hex\') AS h, data_enc, user_id FROM identity_sessions ORDER BY created_at DESC LIMIT 1')->fetch();
    same(hash('sha256', (string) hex2bin($j['handle'])) === $row['h'] || $row['h'] === hash('sha256', $j['handle']), true, 'the table is keyed by a hash of the handle, never the handle');
    check($row['h'] !== $j['handle'] && !str_contains($row['data_enc'], 'user_id') && str_starts_with($row['data_enc'], 'v2:'), 'the session data is stored encrypted');
    same(T::user('amina.elidrissi')->id, (int) $row['user_id'], 'the owner is recorded for administration');
    // The token the service returned is a real actor token: PostgreSQL accepts it for amina, and only for amina.
    $pdo = T::rawRuntime();
    $pdo->beginTransaction();
    $pdo->prepare("SELECT set_config('app.actor', ?, true)")->execute([$j['token']]);
    same([T::user('amina.elidrissi')->id], $pdo->query('SELECT DISTINCT owner_id FROM proposals')->fetchAll(PDO::FETCH_COLUMN), 'the token gives amina her own rows');
    $pdo->rollBack();

    // Fixation: a handle that was never issued yields nothing, and signing in again rotates the handle.
    $none = identity_call(id_payload('currentUser', [], str_repeat('ab', 32)))['json'];
    same([null, null, null], [$none['result'], $none['token'], $none['handle']], 'an invented handle yields no user, no token and no session');
    $again = identity_call(id_payload('login', ['amina.elidrissi@uni.example', T::password('amina.elidrissi')], $j['handle']))['json'];
    check($again['handle'] !== $j['handle'], 'a new sign-in issues a new handle');
    same(null, identity_call(id_payload('currentUser', [], $j['handle']))['json']['result'], 'the previous handle stops working at once');
    same('amina.elidrissi@uni.example', identity_call(id_payload('currentUser', [], $again['handle']))['json']['user']['email'], 'the new one works');
    identity_call(id_payload('logout', [], $again['handle']));
    same(null, identity_call(id_payload('currentUser', [], $again['handle']))['json']['result'], 'logout ends the session at the identity service');
    same(0, (int) $id->query("SELECT count(*) FROM identity_sessions WHERE encode(handle_hash, 'hex') IN ('" . hash('sha256', (string) hex2bin($again['handle'])) . "', '" . hash('sha256', $again['handle']) . "')")->fetchColumn(), 'and the row is gone');
    T::forgiveFailures('203.0.113.31');
});

test('SPLIT a front end can only be given a token for the user of the session it holds', function (): void {
    $store = new class implements \App\Auth\SessionStore {
        private array $d = [];
        public function start(): void {}
        public function get(string $k, mixed $default = null): mixed { return $this->d[$k] ?? $default; }
        public function set(string $k, mixed $v): void { $this->d[$k] = $v; }
        public function pull(string $k, mixed $default = null): mixed { $v = $this->d[$k] ?? $default; unset($this->d[$k]); return $v; }
        public function regenerate(): void {}
        public function destroy(): void { $this->d = []; }
        public function idleSeconds(): int { return 1200; }
        public function absoluteSeconds(): int { return 28800; }
    };
    $client = new IdentityClient('http://127.0.0.1:8095', (string) getenv('IDENTITY_API_KEY'), $store, '11111111-2222-4333-8444-555555555555', '203.0.113.32');
    try {
        $client->tokenFor(T::user('nadia.berrada')->id);
        check(false, 'no token without a session');
    } catch (LogicException) {
        check(true, 'no session, no token');
    }
    $r = $client->call('login', ['salma.tazi@uni.example', T::password('salma.tazi')]);
    same('user', $r['result']['kind'], 'salma signs in through the client');
    check(is_string($client->tokenFor(T::user('salma.tazi')->id)), 'a token for the signed-in user');
    foreach (['nadia.berrada', 'amina.elidrissi'] as $other) {
        try {
            $client->tokenFor(T::user($other)->id);
            check(false, "a token for $other must not be available");
        } catch (LogicException) {
            check(true, "no token for $other: the process cannot act for a user it holds no session of");
        }
    }
    $client->call('logout');
    T::forgiveFailures('203.0.113.32');
});

test('SPLIT a front end cannot make the identity service vouch for someone: verified events need a live session of that user', function (): void {
    T::forgiveFailures('203.0.113.31');
    $amina = T::user('amina.elidrissi');
    $nadia = T::user('nadia.berrada');
    $h = identity_call(id_payload('login', ['amina.elidrissi@uni.example', T::password('amina.elidrissi')]))['json']['handle'];
    $send = fn (?string $handle, ?int $claimed, bool $verified, string $action) => identity_call(id_payload('audit', [$claimed, $verified, $action, 'proposal', 1, 'denied', ['probe' => 'split-test']], $handle))['json'];
    $last = static fn (string $action) => end(array_values(T::audit("action = ? AND details->>'probe' = 'split-test'", [$action])));
    check($send($h, $amina->id, true, 'proposal.view')['result'] === true, 'a verified event for the session owner is accepted');
    same(true, $last('proposal.view')['actor_verified'], 'and is recorded as proved');
    $send($h, $nadia->id, true, 'proposal.delete');            // claims to be the officer while holding amina's session
    $ev = $last('proposal.delete');
    same([$nadia->id, false], [(int) $ev['actor_id'], $ev['actor_verified']], 'claiming another user is recorded as only NAMED (unverified)');
    $send(null, $nadia->id, true, 'review.view');             // no session at all
    same(false, $last('review.view')['actor_verified'], 'no session: unverified');
    check($send($h, null, true, 'Bad Action')['result'] === false, 'a malformed action name is refused');
    identity_call(id_payload('logout', [], $h));
    T::forgiveFailures('203.0.113.31');
});

test('SPLIT every database account sees only what its job needs', function (): void {
    $web = T::rawRuntime();
    foreach (["SELECT * FROM auth_find_credentials('amina.elidrissi@uni.example')", "SELECT auth_login_gate(NULL, '1.1.1.1'::inet, 5, 15, 20, 10)", "SELECT auth_clear_failures(1, '1.1.1.1')",
              'SELECT * FROM identity_sessions', 'DELETE FROM identity_sessions', 'SELECT * FROM mfa_recovery_codes', 'UPDATE users SET last_login_at = now()'] as $sql) {
        sqlstate('42501', fn () => $web->query($sql), "web account refused: $sql");
    }
    $id = T::rawAs('identity_user', 'identity_password');
    check($id->query("SELECT count(*) FROM auth_find_credentials('amina.elidrissi@uni.example')")->fetchColumn() === 1, 'the identity account reads credentials');
    foreach (['SELECT * FROM proposals', 'SELECT * FROM reviews', 'SELECT * FROM decisions', 'SELECT * FROM grant_calls', 'SELECT * FROM audit_events', 'SELECT * FROM actor_key',
              'SELECT * FROM notifications', "SELECT record_decision(1, 'approved', 1, 'x')", "SELECT notify_enqueue_reminders('https://localhost:8443')",
              "SELECT audit_append('auth.login', 'user', 1, 'denied', '{}'::jsonb, NULL, NULL, NULL, NULL)", 'SELECT password_hash FROM users', 'UPDATE users SET role = \'officer\''] as $sql) {
        sqlstate('42501', fn () => $id->query($sql), "identity account refused: $sql");
    }
    $w = T::rawAs('audit_writer_user', 'audit_writer_password');
    foreach (["SELECT * FROM auth_find_credentials('amina.elidrissi@uni.example')", 'SELECT * FROM identity_sessions'] as $sql) {
        sqlstate('42501', fn () => $w->query($sql), "audit-writer account refused: $sql");
    }
});

test('SPLIT the web front end process cannot reach the identity secrets at all', function (): void {
    // A front end is an App in "remote" mode: the same code that runs in the web container.
    $remote = new App(array_replace_recursive(T::config(), ['identity' => ['mode' => 'remote', 'url' => 'http://127.0.0.1:8095']]), '127.0.0.1');
    check($remote->remote(), 'remote mode');
    foreach (['actorToken', 'identityDb', 'auditDb'] as $what) {
        try {
            $remote->$what();
            check(false, "$what must not exist in the front end");
        } catch (LogicException $e) {
            check(str_contains($e->getMessage(), 'not available to the web front end'), "$what is not available to the front end");
        }
    }
    try {
        $remote->actorTokens()->tokenFor(T::user('nadia.berrada')->id);
        check(false, 'the front end cannot mint a token');
    } catch (LogicException) {
        check(true, 'the front end cannot mint a token for anyone');
    }
    check(!($remote->auth() instanceof \App\Auth\Authenticator) && $remote->auth() instanceof \App\Identity\RemoteAuthenticator, 'authentication is delegated');
    check($remote->audit() instanceof \App\Identity\RemoteAuditLog, 'and so is standalone audit writing');
});
