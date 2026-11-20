<?php
declare(strict_types=1);
// Requirement: multi-factor authentication (TOTP) for officers and auditors.

use App\Auth\Totp;

test('MFA the TOTP implementation matches the RFC 6238 test vectors', function (): void {
    $secret = Totp::base32Encode('12345678901234567890');
    foreach ([[59, '287082'], [1111111109, '081804'], [1111111111, '050471'], [1234567890, '005924'], [2000000000, '279037'], [20000000000, '353130']] as [$t, $code]) {
        same($code, Totp::code($secret, intdiv($t, 30)), "T=$t");
    }
    same('12345678901234567890', Totp::base32Decode($secret), 'base32 round trip');
    $step = Totp::step(1_700_000_000);
    $c = Totp::code($secret, $step);
    same($step, Totp::matchStep($secret, $c, 1, 1_700_000_000), 'the current code matches');
    same($step, Totp::matchStep($secret, substr($c, 0, 3) . ' ' . substr($c, 3), 1, 1_700_000_000), 'spaces are ignored');
    same($step, Totp::matchStep($secret, $c, 1, 1_700_000_000 + 30), 'a code one step old is accepted (clock drift)');
    same(null, Totp::matchStep($secret, $c, 1, 1_700_000_000 + 90), 'but not three steps old');
    foreach (['', '12345', '1234567', 'abcdef', '12 34'] as $bad) {
        same(null, Totp::matchStep($secret, $bad, 1, 1_700_000_000), 'malformed code ' . json_encode($bad));
    }
    check(count(array_unique(Totp::recoveryCodes(8))) === 8 && (bool) preg_match('/^[a-z2-9]{4}-[a-z2-9]{4}-[a-z2-9]{4}$/', Totp::recoveryCodes(1)[0]), 'recovery codes: eight distinct, readable');
});

test('MFA an officer or auditor is not signed in by the password alone', function (): void {
    foreach (['nadia.berrada', 'omar.chraibi'] as $who) {
        $b = (new Browser())->login($who, null, completeMfa: false);
        same(303, $b->status, "$who: the password is accepted ...");
        check(str_ends_with($b->location, '/login/mfa'), "$who: ... but the next stop is the second factor");
        $protected = $who === 'nadia.berrada' ? '/officer' : '/audit';
        $r = $b->get($protected);
        same(303, $r->status, "$who: the protected page still redirects");
        check(str_ends_with($r->location, '/login'), "$who: to the login, not through");
    }
    $b = (new Browser())->login('amina.elidrissi', null, completeMfa: false);
    same(303, $b->status, 'a researcher is signed in directly');
    check(str_ends_with($b->location, '/proposals'), 'and lands on the inbox');
});

test('MFA a wrong code is refused, a right one signs in, and both are audited', function (): void {
    T::forgiveFailures();
    $b = (new Browser())->login('omar.chraibi', null, completeMfa: false);
    $b->get('/login/mfa');
    check(str_contains($b->body, 'Second factor'), 'the code form is shown');
    $b->post('/login/mfa', ['code' => '000000']);
    same(401, $b->status, 'wrong code');
    check(str_contains($b->body, 'That code is not valid'), 'with a plain message');
    $b->post('/login/mfa', ['code' => T::totpCode('omar.chraibi')]);
    same(303, $b->status, 'right code');
    check(str_ends_with($b->location, '/audit'), 'lands on the auditor home');
    same(200, $b->get('/audit')->status, 'and is signed in');
    $fail = T::audit("action = 'auth.login' AND details->>'reason' = 'bad_mfa'");
    check(count($fail) >= 1 && end($fail)['actor_verified'] === false, 'the wrong code is audited (unverified: nobody is signed in)');
    $ok = T::audit("action = 'auth.login' AND outcome = 'success' AND details->>'method' = 'totp'");
    check(count($ok) >= 1 && end($ok)['actor_verified'] === true, 'the sign-in is audited with its method');
    T::forgiveFailures();
});

test('MFA a one-time code works once when replay protection is on', function (): void {
    T::forgiveFailures();
    $base = 'http://127.0.0.1:8096';                      // the test server with replay protection on
    $code = T::totpCode('nadia.berrada');
    $a = (new Browser($base))->login('nadia.berrada', null, completeMfa: false);
    $a->get('/login/mfa');
    $a->post('/login/mfa', ['code' => $code]);
    same(303, $a->status, 'first use of the code');
    $b = (new Browser($base))->login('nadia.berrada', null, completeMfa: false);
    $b->get('/login/mfa');
    $b->post('/login/mfa', ['code' => $code]);
    same(401, $b->status, 'the same code a second time is refused');
    check(count(T::audit("action = 'auth.login' AND details->>'reason' = 'mfa_replay'")) >= 1, 'and audited as a replay');
    $c = (new Browser($base))->login('nadia.berrada', null, completeMfa: false);
    $c->get('/login/mfa');
    $c->post('/login/mfa', ['code' => T::totpCode('nadia.berrada', -1)]);
    same(401, $c->status, 'an older step is refused too: the database only moves forward');
    T::forgiveFailures();
});

test('MFA too many wrong codes abandon the sign-in and count toward the lockout', function (): void {
    T::forgiveFailures();
    $b = (new Browser())->login('omar.chraibi', null, completeMfa: false);
    $b->get('/login/mfa');
    for ($i = 0; $i < 5; $i++) {
        $b->post('/login/mfa', ['code' => '11111' . $i]);
    }
    same(401, $b->status, 'the fifth wrong code');
    check(str_contains($b->body, 'Too many wrong codes'), 'ends the pending sign-in');
    $r = $b->get('/login/mfa');
    check(str_ends_with($r->location, '/login'), 'the code page is gone: start again from the password');
    $gate = T::rawAs('identity_user', 'identity_password')->query("SELECT auth_login_gate((SELECT id FROM users WHERE email = 'omar.chraibi@uni.example'), '127.0.0.1'::inet, 5, 15, 20, 10)")->fetchColumn();
    same('pair_locked', $gate, 'five wrong codes also lock this (account, address) pair, like five wrong passwords');
    T::forgiveFailures();
});

test('MFA first sign-in forces enrolment: setup key, encrypted secret, recovery codes shown once', function (): void {
    T::forgiveFailures();
    $pw = 'Fixture-Officer-9!';
    $b = (new Browser())->login('newofficer.fixture', $pw, completeMfa: false);
    check(str_ends_with($b->location, '/login/mfa'), 'an officer without a second factor is sent to set one up');
    $b->get('/login/mfa');
    check(str_contains($b->body, 'Set up two-step sign-in'), 'the setup page');
    check((bool) preg_match('#<code id="mfa-secret">([A-Z2-7 ]+)</code>#', $b->body, $m), 'the setup key is shown');
    $secret = str_replace(' ', '', $m[1]);
    check(str_contains($b->body, 'otpauth://totp/'), 'with the otpauth address for a phone');
    $b->post('/login/mfa', ['code' => '000000']);
    same(401, $b->status, 'a wrong code does not enrol');
    $b->post('/login/mfa', ['code' => Totp::code($secret, Totp::step())]);
    same(200, $b->status, 'the right code enrols and signs in');
    check(str_contains($b->body, 'Save your recovery codes'), 'recovery codes are shown');
    preg_match_all('#<li><code>([a-z2-9-]{14})</code></li>#', $b->body, $codes);
    same(8, count($codes[1]), 'eight codes');
    $officer = T::user('newofficer.fixture');
    $state = T::identitySqlAs($officer, 'SELECT enrolled, secret_enc FROM mfa_state(?)', [$officer->id])['rows'][0];
    same(true, $state['enrolled'], 'enrolled in the database');
    check(preg_match('/^v2:k\d+:/', $state['secret_enc']) === 1 && !str_contains($state['secret_enc'], $secret), 'the secret is stored encrypted, never in clear');
    sqlstate('23514', fn () => T::identitySqlAs($officer, "SELECT mfa_enroll(?, 'v2:k1:x', ARRAY['h'])", [$officer->id]), 'a second enrolment is refused');
    check(count(T::audit("action = 'auth.mfa_enrolled' AND actor_id = ?", [$officer->id])) === 1, 'enrolment is audited');

    // Next time the officer is asked for a code; a recovery code works once.
    $c = (new Browser())->login('newofficer.fixture', $pw, completeMfa: false);
    $c->get('/login/mfa');
    check(str_contains($c->body, 'Second factor'), 'now the normal code form');
    $c->get('/login/mfa?recovery=1');
    $c->post('/login/mfa', ['mode' => 'recovery', 'recovery_code' => strtoupper($codes[1][0])]);
    same(303, $c->status, 'a recovery code signs in (case does not matter)');
    $d = (new Browser())->login('newofficer.fixture', $pw, completeMfa: false);
    $d->get('/login/mfa?recovery=1');
    $d->post('/login/mfa', ['mode' => 'recovery', 'recovery_code' => $codes[1][0]]);
    same(401, $d->status, 'the same recovery code a second time is refused');
    check(count(T::audit("action = 'auth.mfa_recovery_used' AND actor_id = ?", [$officer->id])) === 1, 'recovery use is audited');
    T::forgiveFailures();
});

test('MFA a stolen database password cannot enrol, read, replay or reset anyone\'s second factor', function (): void {
    $officer = T::user('nadia.berrada');
    $pdo = T::rawRuntime();
    foreach (["SELECT * FROM mfa_state({$officer->id})", "SELECT mfa_accept_step({$officer->id}, 99999999)", "SELECT * FROM mfa_recovery_hashes({$officer->id})",
              "SELECT mfa_enroll({$officer->id}, 'v2:k1:x', ARRAY['h'])", "SELECT mfa_consume_recovery({$officer->id}, 1)"] as $sql) {
        sqlstate('42501', fn () => $pdo->query($sql), "no token, no access: $sql");
    }
    $pdo->beginTransaction();
    $pdo->exec("SELECT set_config('app.user_id', '{$officer->id}', true)");
    sqlstate('42501', fn () => $pdo->query("SELECT * FROM mfa_state({$officer->id})"), 'the old self-asserted claim does not help');
    $pdo->rollBack();
    foreach (['SELECT totp_secret_enc FROM users', 'SELECT * FROM mfa_recovery_codes', 'UPDATE users SET totp_enrolled_at = NULL', 'UPDATE users SET totp_last_step = 0', 'DELETE FROM mfa_recovery_codes'] as $sql) {
        sqlstate('42501', fn () => $pdo->exec($sql), "no direct access: $sql");
    }
    // A valid token for ANOTHER user cannot touch this officer's factor either.
    sqlstate('42501', fn () => T::identitySqlAs(T::user('omar.chraibi'), 'SELECT * FROM mfa_state(?)', [$officer->id]), 'one user cannot read another user\'s second-factor state');
});

test('MFA the second-factor form needs a CSRF token', function (): void {
    $b = (new Browser())->login('omar.chraibi', null, completeMfa: false);
    $b->get('/login/mfa');
    same(400, $b->post('/login/mfa', ['code' => T::totpCode('omar.chraibi')], withCsrf: false)->status, 'no token, no check');
});
