<?php
declare(strict_types=1);
// Requirement: authentication, sessions, CSRF, output escaping.

test('AUTH passwords are stored as Argon2id hashes, never plaintext', function (): void {
    // Only the identity account can read hashes (finding O01): the web account is refused outright.
    $web = T::rawRuntime()->prepare('SELECT password_hash FROM auth_find_credentials(?)');
    sqlstate('42501', fn () => $web->execute(['amina.elidrissi@uni.example']), 'the web account cannot fetch a password hash (O01)');
    $stmt = T::rawAs('identity_user', 'identity_password')->prepare('SELECT password_hash FROM auth_find_credentials(?)');
    $stmt->execute(['amina.elidrissi@uni.example']);
    $hash = $stmt->fetchColumn();
    check(str_starts_with($hash, '$argon2id$'), 'hash uses argon2id');
    check(!str_contains($hash, T::password('amina.elidrissi')), 'hash does not contain the password');
    check(password_verify(T::password('amina.elidrissi'), $hash), 'correct password verifies');
    check(!password_verify('wrong-password', $hash), 'wrong password does not verify');
});

test('AUTH runtime account cannot read the password_hash column', function (): void {
    sqlstate('42501', fn () => T::rawRuntime()->query('SELECT password_hash FROM users'), 'SELECT password_hash is refused');
    sqlstate('42501', fn () => T::rawRuntime()->query('SELECT * FROM users'), 'SELECT * FROM users is refused');
});

test('AUTH wrong password gets a generic message and a denied audit event', function (): void {
    $b = (new Browser())->login('amina.elidrissi', 'definitely-wrong');
    same(401, $b->status, 'status');
    check(str_contains($b->body, 'incorrect, or the account is temporarily locked'), 'generic message shown');
    $unknown = (new Browser())->login('nobody.here', 'x');
    same(401, $unknown->status, 'unknown account status');
    check(str_contains($unknown->body, 'incorrect, or the account is temporarily locked'), 'same message for unknown account');
    check(count(T::audit("action = 'auth.login' AND outcome = 'denied' AND details->>'reason' = 'bad_password'")) >= 1, 'bad_password event recorded');
    check(count(T::audit("action = 'auth.login' AND outcome = 'denied' AND details->>'reason' = 'unknown_account'")) >= 1, 'unknown_account event recorded');
    T::forgiveFailures();
});

test('AUTH login regenerates the session ID and sets a HttpOnly SameSite cookie', function (): void {
    $b = new Browser();
    $b->get('/login');
    $before = $b->cookie();
    check(str_contains($b->headers, 'HttpOnly') && str_contains($b->headers, 'SameSite=Lax'), 'cookie flags present');
    $b->post('/login', ['email' => 'amina.elidrissi@uni.example', 'password' => T::password('amina.elidrissi')]);
    same(303, $b->status, 'login redirects');
    check($before !== '' && $b->cookie() !== '' && $before !== $b->cookie(), 'session ID changed at login');
    same(200, $b->get('/proposals')->status, 'authenticated page loads');
});

test('AUTH session cookie is Secure and __Host- prefixed over HTTPS (Apache)', function (): void {
    $ch = curl_init('https://web/login');                 // the real Apache front end, over the compose network
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true, CURLOPT_SSL_VERIFYPEER => false, CURLOPT_SSL_VERIFYHOST => 0]);
    $headers = (string) curl_exec($ch);
    check((bool) preg_match('/Set-Cookie: __Host-grants=\S+; path=\/; secure; HttpOnly; SameSite=Lax/i', $headers), 'secure host-only cookie');
    check(stripos($headers, 'Strict-Transport-Security') !== false, 'HSTS header present');
    check(stripos($headers, 'X-Powered-By') === false, 'PHP version not advertised');
    curl_setopt_array($ch, [CURLOPT_NOBODY => true]);
    check(str_starts_with((string) curl_exec($ch), 'HTTP/1.1 200'), 'HEAD is answered like GET');
});

test('AUTH logout ends the session', function (): void {
    $b = (new Browser())->login('amina.elidrissi');
    $b->get('/proposals');
    same(303, $b->post('/logout', [])->status, 'logout redirects');
    $after = $b->get('/proposals');
    same(303, $after->status, 'protected page redirects after logout');
    check(str_ends_with($after->location, '/login'), 'redirect goes to login');
});

test('AUTH session expires after inactivity', function (): void {
    $b = (new Browser('http://127.0.0.1:8098'))->login('amina.elidrissi');   // server with a 1-second idle limit
    same(200, $b->get('/proposals')->status, 'active session works');
    sleep(3);
    same(303, $b->get('/proposals')->status, 'idle session is rejected');
    check(count(T::audit("action = 'auth.session_expired' AND details->>'reason' = 'idle'")) >= 1, 'expiry recorded');
});

test('AUTH five failures lock the (account, address) pair, even for the correct password', function (): void {
    T::forgiveFailures();
    for ($i = 0; $i < 5; $i++) {
        (new Browser())->login('omar.chraibi', 'wrong-' . $i);
    }
    same(401, (new Browser())->login('omar.chraibi')->status, 'correct password refused while the pair is locked');
    check(count(T::audit("action = 'auth.lockout'")) === 1, 'one lockout event');
    check(count(T::audit("action = 'auth.login' AND details->>'reason' = 'account_locked'")) === 1, 'locked attempt recorded');
    T::forgiveFailures();
    same(303, (new Browser())->login('omar.chraibi')->status, 'login works again once the failures are forgiven');
});

test('AUTH a stranger cannot lock the real owner out (finding F02 remediated)', function (): void {
    T::forgiveFailures();
    $stranger = '198.51.100.9';
    T::forgiveFailures($stranger);
    $victim = 'omar.chraibi@uni.example';
    for ($i = 0; $i < 5; $i++) {
        same(null, T::appFrom($stranger)->auth()->login($victim, 'guess-' . $i), 'stranger guess refused');
    }
    // The stranger's address is now locked for that account ...
    $gate = fn (string $ip) => T::rawAs('identity_user', 'identity_password')->query(sprintf(
        "SELECT auth_login_gate((SELECT id FROM users WHERE email = '%s'), '%s'::inet, 5, 15, 20, 10)", $victim, $ip))->fetchColumn();
    same('pair_locked', $gate($stranger), 'the stranger is locked out for that account');
    // ... but the owner, from the usual address, is not.
    same(null, $gate('127.0.0.1'), 'the gate is open for the owner\'s own address');
    same(303, (new Browser())->login('omar.chraibi')->status, 'the owner signs in normally from their address');
    T::forgiveFailures($stranger);
});

test('AUTH a source address that keeps failing is throttled before any hashing (finding F04 remediated)', function (): void {
    $ip = '198.51.100.40';
    T::forgiveFailures($ip);
    $app = T::appFrom($ip);
    for ($i = 0; $i < 20; $i++) {
        $app->auth()->login("spray$i@uni.example", 'Password1');             // 20 distinct unknown accounts
    }
    $t0 = hrtime(true);
    try {
        T::appFrom($ip)->auth()->login('amina.elidrissi@uni.example', T::password('amina.elidrissi'));
        check(false, 'the 21st attempt must be refused, even with the correct password');
    } catch (App\Auth\LoginThrottled $e) {
        $ms = (hrtime(true) - $t0) / 1e6;
        check($ms < 100, sprintf('refused without password hashing (%.0f ms)', $ms));
        same(600, $e->retryAfterSeconds, 'Retry-After is the window length');
    }
    check(count(T::audit("action = 'auth.throttle' AND source_ip = '$ip'")) === 1, 'the throttle is audited once, not once per request');
    $gate = T::rawAs('identity_user', 'identity_password')->query("SELECT auth_login_gate(NULL, '127.0.0.1'::inet, 5, 15, 20, 10)")->fetchColumn();
    same(null, $gate, 'other addresses are unaffected');
    T::forgiveFailures($ip);
    same(null, T::rawAs('identity_user', 'identity_password')->query("SELECT auth_login_gate(NULL, '$ip'::inet, 5, 15, 20, 10)")->fetchColumn(), 'the address recovers once the failures are cleared');
});

test('AUTH unknown, wrong-password and locked answers cost the same hashing work (finding F03 remediated)', function (): void {
    $median = function (callable $attempt): float {
        $t = [];
        for ($i = 0; $i < 3; $i++) {
            $t0 = hrtime(true);
            $attempt($i);
            $t[] = (hrtime(true) - $t0) / 1e6;
        }
        sort($t);
        return $t[1];
    };
    foreach (['198.51.100.21', '198.51.100.22', '198.51.100.23'] as $ip) {
        T::forgiveFailures($ip);
    }
    $unknown = $median(fn ($i) => T::appFrom('198.51.100.21')->auth()->login("ghost$i@uni.example", 'x'));
    $wrong = $median(fn ($i) => T::appFrom('198.51.100.22')->auth()->login('salma.tazi@uni.example', 'x' . $i));
    for ($i = 0; $i < 5; $i++) {
        T::appFrom('198.51.100.23')->auth()->login('omar.chraibi@uni.example', 'lock-' . $i);
    }
    $locked = $median(fn ($i) => T::appFrom('198.51.100.23')->auth()->login('omar.chraibi@uni.example', 'x' . $i));
    check($unknown > 100 && $wrong > 100 && $locked > 100, sprintf('all three pay for a full hash (%.0f / %.0f / %.0f ms)', $unknown, $wrong, $locked));
    check($locked > 0.6 * $wrong && $unknown > 0.6 * $wrong, 'no path is much faster than the others');
    check($locked < 1.6 * $wrong, sprintf('the locked path is not slower either (locked %.0f ms, wrong password %.0f ms)', $locked, $wrong));
    foreach (['198.51.100.21', '198.51.100.22', '198.51.100.23'] as $ip) {
        T::forgiveFailures($ip);
    }
});

test('AUTH the HTTP login answers 429 with Retry-After when the source is throttled', function (): void {
    T::forgiveFailures();
    $b = new Browser();
    for ($i = 0; $i < 20; $i++) {
        $b->login('spray' . $i, 'Password1');
    }
    $b->login('amina.elidrissi');
    same(429, $b->status, 'throttled');
    check(stripos($b->headers, 'Retry-After: 600') !== false, 'Retry-After header present');
    check(str_contains($b->body, 'Too many failed attempts'), 'the message names no account');
    T::forgiveFailures();
    same(303, (new Browser())->login('amina.elidrissi')->status, 'normal login works again after the window');
});

test('AUTH security headers include Permissions-Policy (finding F05 remediated)', function (): void {
    $h = (new Browser())->get('/login')->headers;
    foreach (['Permissions-Policy: ', 'camera=()', 'microphone=()', 'geolocation=()', 'Cross-Origin-Opener-Policy: same-origin', 'X-Frame-Options: DENY', 'Referrer-Policy: same-origin'] as $needle) {
        check(stripos($h, $needle) !== false, "response header contains $needle");
    }
});

test('AUTH state-changing request without a CSRF token is rejected', function (): void {
    $b = (new Browser())->login('amina.elidrissi');
    $before = count(T::sqlAs(T::user('amina.elidrissi'), 'SELECT id FROM proposals')['rows']);
    $r = $b->post('/proposals', ['call_id' => 1, 'title' => 'Forged request', 'abstract' => '', 'requested_amount' => '10'], withCsrf: false);
    same(400, $r->status, 'missing token');
    $r = $b->post('/proposals', ['call_id' => 1, 'title' => 'Forged request', 'requested_amount' => '10', '_csrf' => str_repeat('0', 64)], withCsrf: false);
    same(400, $r->status, 'wrong token');
    same($before, count(T::sqlAs(T::user('amina.elidrissi'), 'SELECT id FROM proposals')['rows']), 'no proposal was created');
    check(count(T::audit("action = 'request.csrf_rejected'")) >= 2, 'rejections recorded');
});

test('AUTH user-supplied text is escaped on output', function (): void {
    $amina = T::user('amina.elidrissi');
    $id = T::app()->workflow()->createDraft($amina, 1, ['title' => '<script>alert("x")</script> & co', 'abstract' => '<img src=x onerror=alert(1)>', 'requested_amount' => '100']);
    $b = (new Browser())->login('amina.elidrissi');
    foreach (['/proposals', '/proposals/' . $id] as $path) {
        $html = $b->get($path)->body;
        check(!str_contains($html, '<script>alert('), "$path has no raw script tag");
        check(str_contains($html, '&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt; &amp; co'), "$path shows the escaped title");
    }
    check(!str_contains($b->get('/proposals/' . $id)->body, '<img src=x'), 'abstract is escaped');
    check(str_contains($b->headers, "Content-Security-Policy: default-src 'self'"), 'CSP header forbids inline script');
    T::app()->workflow()->deleteDraft($amina, $id);
});
