<?php
declare(strict_types=1);
// Requirement: security keys (WebAuthn / FIDO2) as a phishing-resistant second factor.

use App\Auth\Cbor;
use App\Auth\WebAuthn;

/** A software authenticator: what a hardware key does, with a fresh P-256 key, so the server's checks can be exercised. */
final class SoftKey
{
    public string $id;
    private \OpenSSLAsymmetricKey $key;
    public int $counter = 0;

    public function __construct(private readonly string $rpId, private readonly string $origin, private readonly int $flags = 0x05)
    {
        $this->id = random_bytes(32);
        $this->key = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
    }

    private static function bstr(string $s): string
    {
        return (strlen($s) < 24 ? chr(0x40 | strlen($s)) : (strlen($s) < 256 ? "\x58" . chr(strlen($s)) : "\x59" . pack('n', strlen($s)))) . $s;
    }

    private static function tstr(string $s): string
    {
        return chr(0x60 | strlen($s)) . $s;
    }

    private function cose(): string
    {
        $d = openssl_pkey_get_details($this->key)['ec'];
        return "\xa5\x01\x02\x03\x26\x20\x01\x21" . self::bstr(str_pad($d['x'], 32, "\0", STR_PAD_LEFT)) . "\x22" . self::bstr(str_pad($d['y'], 32, "\0", STR_PAD_LEFT));
    }

    private function clientData(string $type, string $challenge, ?string $origin = null): string
    {
        return json_encode(['type' => $type, 'challenge' => $challenge, 'origin' => $origin ?? $this->origin, 'crossOrigin' => false]);
    }

    /** @return array credential as the browser script sends it */
    public function create(string $challenge, ?string $origin = null, ?string $rpId = null): array
    {
        $auth = hash('sha256', $rpId ?? $this->rpId, true) . chr($this->flags | 0x40) . pack('N', $this->counter) . str_repeat("\0", 16)
              . pack('n', strlen($this->id)) . $this->id . $this->cose();
        $att = "\xa3" . self::tstr('fmt') . self::tstr('none') . self::tstr('attStmt') . "\xa0" . self::tstr('authData') . self::bstr($auth);
        return ['id' => WebAuthn::b64uEncode($this->id), 'response' => [
            'clientDataJSON' => WebAuthn::b64uEncode($this->clientData('webauthn.create', $challenge, $origin)),
            'attestationObject' => WebAuthn::b64uEncode($att)]];
    }

    public function get(string $challenge, ?string $origin = null, ?int $counter = null, ?int $flags = null, bool $corrupt = false): array
    {
        $this->counter = $counter ?? $this->counter + 1;
        $auth = hash('sha256', $this->rpId, true) . chr($flags ?? $this->flags) . pack('N', $this->counter);
        $cd = $this->clientData('webauthn.get', $challenge, $origin);
        openssl_sign($auth . hash('sha256', $cd, true), $sig, $this->key, OPENSSL_ALGO_SHA256);
        if ($corrupt) { $sig[strlen($sig) - 1] = $sig[strlen($sig) - 1] ^ "\x01"; }
        return ['id' => WebAuthn::b64uEncode($this->id), 'response' => [
            'clientDataJSON' => WebAuthn::b64uEncode($cd), 'authenticatorData' => WebAuthn::b64uEncode($auth), 'signature' => WebAuthn::b64uEncode($sig)]];
    }
}

function wa_cfg(): array { return T::config()['auth']['webauthn']; }

function wa_json(Browser $b, string $path, array $fields = []): array
{
    $b->post($path, $fields);
    return json_decode($b->body, true) ?? [];
}

/** Sign in as the officer with password + TOTP and register $key through the pages. */
function wa_register(Browser $b, SoftKey $key, string $name = 'Test key'): array
{
    $b->get('/account/security');
    $o = wa_json($b, '/account/security/webauthn/options');
    $b->get('/account/security');
    return wa_json($b, '/account/security/webauthn/register', ['name' => $name, 'credential' => json_encode($key->create($o['options']['challenge']))]);
}

test('WEBAUTHN the CBOR decoder reads what it should and refuses what it must', function (): void {
    same(['a' => 1, 'b' => [true, null, -7]], Cbor::decodeAll("\xa2\x61a\x01\x61b\x83\xf5\xf6\x26"), 'a map with text keys, an array, booleans, null and a negative integer');
    same("\x01\x02", Cbor::decodeAll("\x42\x01\x02"), 'a byte string');
    foreach (['indefinite length' => "\x9f\x01\xff", 'truncated string' => "\x45\x01", 'a float' => "\xfb\x3f\xf0\x00\x00\x00\x00\x00\x00", 'a tag' => "\xc1\x01",
              'trailing bytes' => "\x01\x02", 'empty' => ''] as $why => $bin) {
        $threw = false;
        try { Cbor::decodeAll($bin); } catch (InvalidArgumentException) { $threw = true; }
        check($threw, "refused: $why");
    }
    $deep = str_repeat("\x81", 20) . "\x01";
    $threw = false;
    try { Cbor::decodeAll($deep); } catch (InvalidArgumentException) { $threw = true; }
    check($threw, 'refused: nesting deeper than 8');
});

test('WEBAUTHN registration and sign-in ceremonies are verified, and each defect is refused', function (): void {
    $c = wa_cfg();
    $key = new SoftKey($c['rp_id'], $c['origin']);
    $ch = WebAuthn::newChallenge();
    $reg = WebAuthn::verifyRegistration($key->create($ch), $ch, $c['origin'], $c['rp_id'], true);
    same($key->id, $reg['credential_id'], 'registration returns the credential id');
    same(-7, $reg['alg'], 'ES256');
    check($reg['user_verified'], 'user verification was performed');

    $fails = static function (callable $f): bool { try { $f(); return false; } catch (InvalidArgumentException) { return true; } };
    check($fails(fn () => WebAuthn::verifyRegistration($key->create($ch), WebAuthn::newChallenge(), $c['origin'], $c['rp_id'], true)), 'registration: another challenge');
    check($fails(fn () => WebAuthn::verifyRegistration($key->create($ch, 'https://evil.example'), $ch, $c['origin'], $c['rp_id'], true)), 'registration: another origin');
    check($fails(fn () => WebAuthn::verifyRegistration($key->create($ch, null, 'evil.example'), $ch, $c['origin'], $c['rp_id'], true)), 'registration: another relying party id');
    check($fails(fn () => WebAuthn::verifyRegistration((new SoftKey($c['rp_id'], $c['origin'], 0x01))->create($ch), $ch, $c['origin'], $c['rp_id'], true)), 'registration: no user verification when required');

    $pem = $reg['pem'];
    $ch = WebAuthn::newChallenge();
    $ok = WebAuthn::verifyAssertion($key->get($ch), $ch, $c['origin'], $c['rp_id'], true, $pem);
    same(1, $ok['sign_count'], 'a valid assertion verifies and reports the counter');
    check($fails(fn () => WebAuthn::verifyAssertion($key->get($ch, corrupt: true), $ch, $c['origin'], $c['rp_id'], true, $pem)), 'assertion: damaged signature');
    check($fails(fn () => WebAuthn::verifyAssertion($key->get($ch), WebAuthn::newChallenge(), $c['origin'], $c['rp_id'], true, $pem)), 'assertion: another challenge');
    check($fails(fn () => WebAuthn::verifyAssertion($key->get($ch, 'https://evil.example'), $ch, $c['origin'], $c['rp_id'], true, $pem)), 'assertion: signed for a look-alike origin (phishing)');
    check($fails(fn () => WebAuthn::verifyAssertion($key->get($ch, flags: 0x04), $ch, $c['origin'], $c['rp_id'], true, $pem)), 'assertion: user not present');
    check($fails(fn () => WebAuthn::verifyAssertion($key->get($ch, flags: 0x01), $ch, $c['origin'], $c['rp_id'], true, $pem)), 'assertion: no user verification when required');
    $other = new SoftKey($c['rp_id'], $c['origin']);
    check($fails(fn () => WebAuthn::verifyAssertion($other->get($ch), $ch, $c['origin'], $c['rp_id'], true, $pem)), 'assertion: signed by a different key');
});

test('WEBAUTHN an officer registers a key and then signs in with it', function (): void {
    T::forgiveFailures();
    $c = wa_cfg();
    $key = new SoftKey($c['rp_id'], $c['origin']);
    $b = (new Browser())->login('nadia.berrada');
    $r = wa_register($b, $key, 'Office YubiKey');
    check(($r['ok'] ?? false) === true, 'the key is registered');
    check(str_contains($b->get('/account/security')->body, 'Office YubiKey'), 'it is listed by name');
    check(!str_contains($b->body, WebAuthn::b64uEncode($key->id)), 'the page never shows key material');

    T::forgiveFailures();
    $s = (new Browser())->login('nadia.berrada', null, completeMfa: false);
    $s->get('/login/mfa');
    check(str_contains($s->body, 'Use security key'), 'the second-factor page offers the key');
    $o = wa_json($s, '/login/webauthn/options');
    check(($o['ok'] ?? false) && ($o['options']['rpId'] ?? '') === $c['rp_id'] && count($o['options']['allowCredentials']) === 1, 'the challenge names only this user\'s key');
    $s->get('/login/mfa');
    $v = wa_json($s, '/login/webauthn/verify', ['credential' => json_encode($key->get($o['options']['challenge']))]);
    check(($v['ok'] ?? false) === true && str_ends_with($v['redirect'] ?? '', '/officer'), 'the signed challenge opens the session');
    same(200, $s->get('/officer')->status, 'and the officer is signed in');
    $ev = T::audit("action = 'auth.login' AND outcome = 'success' AND details->>'method' = 'security_key'");
    check(count($ev) >= 1 && end($ev)['actor_verified'] === true, 'the sign-in is audited with its method');
    check(count(T::audit("action = 'auth.webauthn_register' AND outcome = 'success'")) >= 1, 'the registration is audited');
});

test('WEBAUTHN replayed, wrong and cloned responses are refused and counted', function (): void {
    T::forgiveFailures();
    $c = wa_cfg();
    $key = new SoftKey($c['rp_id'], $c['origin']);
    $b = (new Browser())->login('omar.chraibi');
    check((wa_register($b, $key)['ok'] ?? false) === true, 'auditor registers a key');
    $attempt = function (callable $respond) use ($c): array {
        T::forgiveFailures();
        $s = (new Browser())->login('omar.chraibi', null, completeMfa: false);
        $s->get('/login/mfa');
        $o = wa_json($s, '/login/webauthn/options');
        $s->get('/login/mfa');
        return [$s, wa_json($s, '/login/webauthn/verify', ['credential' => json_encode($respond($o['options']['challenge']))])];
    };
    [$s, $v] = $attempt(fn ($ch) => $key->get($ch, 'https://evil.example'));
    same(401, $s->status, 'a response signed for another origin is refused');
    [$s, $v] = $attempt(fn ($ch) => $key->get(WebAuthn::newChallenge()));
    same(401, $s->status, 'a response to another challenge is refused');
    [$s, $v] = $attempt(fn ($ch) => $key->get($ch, corrupt: true));
    same(401, $s->status, 'a damaged signature is refused');
    same(303, $s->get('/audit')->status, 'and the visitor is still not signed in');

    // The same challenge cannot be answered twice.
    T::forgiveFailures();
    $s = (new Browser())->login('omar.chraibi', null, completeMfa: false);
    $s->get('/login/mfa');
    $o = wa_json($s, '/login/webauthn/options');
    $answer = $key->get($o['options']['challenge']);
    $s->get('/login/mfa');
    check((wa_json($s, '/login/webauthn/verify', ['credential' => json_encode($answer)])['ok'] ?? false) === true, 'first answer accepted');
    $t = (new Browser())->login('omar.chraibi', null, completeMfa: false);
    $t->get('/login/mfa');
    wa_json($t, '/login/webauthn/options');
    $t->get('/login/mfa');
    same(401, $t->post('/login/webauthn/verify', ['credential' => json_encode($answer)])->status, 'the same answer, replayed in another session, is refused');

    // A counter that does not move forward means a cloned key.
    [$s, $v] = $attempt(fn ($ch) => $key->get($ch, counter: 1));
    same(401, $s->status, 'a counter that went backwards is refused');
    check(count(T::audit("action = 'auth.webauthn_clone_suspected'")) >= 1, 'a suspected clone is audited');
    T::forgiveFailures();
});

test('WEBAUTHN a key belongs to one person, can be removed, and is closed to the web account', function (): void {
    T::forgiveFailures();
    $c = wa_cfg();
    $key = new SoftKey($c['rp_id'], $c['origin']);
    $b = (new Browser())->login('nadia.berrada');
    wa_register($b, $key, 'To remove');
    $nadia = T::user('nadia.berrada');
    $omar = T::user('omar.chraibi');

    $list = T::identitySqlAs($nadia, 'SELECT id, name FROM webauthn_list(?)', [$nadia->id]);
    check(count($list) >= 1, 'the identity account lists the user\'s own keys');
    sqlstate('42501', fn () => T::identitySqlAs($omar, 'SELECT * FROM webauthn_list(?)', [$nadia->id]), 'another user cannot list them (token is for someone else)');
    sqlstate('42501', fn () => T::identitySqlAs($omar, 'SELECT webauthn_delete(?, ?)', [$nadia->id, $list[0]['id']]), 'another user cannot delete them');
    sqlstate('42501', fn () => T::rawRuntime()->query('SELECT * FROM webauthn_list(1)'), 'the web account cannot call the key functions');
    sqlstate('42501', fn () => T::rawRuntime()->query('SELECT public_key_pem FROM webauthn_credentials'), 'nor read the table');

    $b->get('/account/security');
    preg_match('#To remove.*?/account/security/webauthn/(\d+)/delete#s', $b->body, $m);
    $b->post('/account/security/webauthn/' . $m[1] . '/delete', []);
    same(303, $b->status, 'removing a key redirects back');
    check(!str_contains($b->get('/account/security')->body, 'To remove'), 'and the key is gone');
    check(count(T::audit("action = 'auth.webauthn_removed'")) >= 1, 'the removal is audited');

    $r = (new Browser())->login('amina.elidrissi');
    same(403, $r->get('/account/security')->status, 'a researcher has no security-key page');
    same(303, (new Browser())->get('/account/security')->status, 'a visitor is sent to sign in');
    $v = (new Browser())->post('/login/webauthn/options', []);
    same(400, $v->status, 'the challenge endpoint gives nothing without a pending sign-in');
});
