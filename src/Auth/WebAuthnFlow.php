<?php
declare(strict_types=1);

namespace App\Auth;

use InvalidArgumentException;
use PDO;

/**
 * The security-key (WebAuthn) steps of the Authenticator: a second factor at sign-in, and registering or removing keys
 * for a signed-in user. Challenges live in the server-side session, are single use, and expire after two minutes.
 * Every failure counts like a wrong code (pair lock, address throttle, per-sign-in cap).
 */
trait WebAuthnFlow
{
    private function wa(): array
    {
        return $this->config['webauthn'];
    }

    /** @return list<array{id:int, credential_id:string, public_key_pem:string, alg:int, sign_count:int, user_verified:bool, name:string, created_at:string, last_used_at:?string}> */
    private function waRows(User $user): array
    {
        return $this->db->asActor($user->id, static function (PDO $tx) use ($user): array {
            $s = $tx->prepare('SELECT * FROM webauthn_list(?)');
            $s->execute([$user->id]);
            $rows = $s->fetchAll();
            foreach ($rows as &$r) {
                $r['credential_id'] = is_resource($r['credential_id']) ? stream_get_contents($r['credential_id']) : $r['credential_id'];
            }
            return $rows;
        });
    }

    /** Names and dates of the user's keys (no key material), for the pages. */
    public function webauthnKeys(User $user): array
    {
        return array_map(static fn (array $r): array => ['id' => (int) $r['id'], 'name' => $r['name'], 'created_at' => $r['created_at'],
                                                          'last_used_at' => $r['last_used_at']], $this->waRows($user));
    }

    public function pendingHasKeys(): bool
    {
        $user = $this->pendingMfaUser();
        return $user !== null && $this->waRows($user) !== [];
    }

    private function waChallenge(string $purpose, array $extra = []): string
    {
        $c = WebAuthn::newChallenge();
        $this->session->set('wa_challenge', ['c' => $c, 'purpose' => $purpose, 'at' => time()] + $extra);
        return $c;
    }

    /** The pending challenge for this purpose, consumed: it can never be answered twice. */
    private function waTake(string $purpose): ?array
    {
        $p = $this->session->pull('wa_challenge');
        return is_array($p) && ($p['purpose'] ?? null) === $purpose && time() - (int) $p['at'] <= (int) $this->wa()['ttl'] ? $p : null;
    }

    // ------------------------------------------------------------------- sign-in

    /** Options for navigator.credentials.get(), for the user who passed the password step; null if none or no keys. */
    public function webauthnBeginLogin(): ?array
    {
        $user = $this->pendingMfaUser();
        if ($user === null || !$this->mfaGate($user)) {
            return null;
        }
        $rows = $this->waRows($user);
        if ($rows === []) {
            return null;
        }
        return [
            'challenge' => $this->waChallenge('login'), 'rpId' => $this->wa()['rp_id'], 'timeout' => 120000,
            'userVerification' => $this->wa()['require_uv'] ? 'required' : 'preferred',
            'allowCredentials' => array_map(static fn (array $r): array => ['type' => 'public-key', 'id' => WebAuthn::b64uEncode($r['credential_id'])], $rows),
        ];
    }

    public function webauthnFinishLogin(array $credential): ?User
    {
        $user = $this->pendingMfaUser();
        if ($user === null || !$this->mfaGate($user)) {
            return null;
        }
        $challenge = $this->waTake('login');
        if ($challenge === null) {
            return $this->mfaFail($user, 'bad_mfa');
        }
        try {
            $id = WebAuthn::b64uDecode((string) ($credential['id'] ?? ''));
            $row = null;
            foreach ($this->waRows($user) as $r) {
                if (hash_equals($r['credential_id'], $id)) {
                    $row = $r;
                }
            }
            if ($row === null) {
                throw new InvalidArgumentException('Unknown credential for this user.');
            }
            $res = WebAuthn::verifyAssertion($credential, $challenge['c'], $this->wa()['origin'], $this->wa()['rp_id'], $this->wa()['require_uv'], $row['public_key_pem']);
            $moved = $this->db->asActor($user->id, static function (PDO $tx) use ($user, $row, $res): bool {
                $s = $tx->prepare('SELECT webauthn_use(?, ?, ?)');
                $s->execute([$user->id, $row['id'], $res['sign_count']]);
                return (bool) $s->fetchColumn();
            });
            if (!$moved) {
                $this->audit->standalone($user, 'auth.webauthn_clone_suspected', 'user', $user->id, 'denied', ['key' => $row['name']], verified: false);
                throw new InvalidArgumentException('The signature counter did not move forward.');
            }
        } catch (InvalidArgumentException) {
            return $this->mfaFail($user, 'bad_mfa');
        }
        return $this->finishLogin($user, 'security_key');
    }

    // ------------------------------------------------------------------- management (signed-in user)

    /** Options for navigator.credentials.create(). */
    public function webauthnBeginRegister(): ?array
    {
        $user = $this->currentUser();
        if ($user === null) {
            return null;
        }
        return [
            'challenge' => $this->waChallenge('register'),
            'rp' => ['name' => 'Research Grants', 'id' => $this->wa()['rp_id']],
            'user' => ['id' => WebAuthn::b64uEncode(WebAuthn::userHandle($user->id)), 'name' => $user->email, 'displayName' => $user->fullName],
            'pubKeyCredParams' => [['type' => 'public-key', 'alg' => WebAuthn::ALG_ES256], ['type' => 'public-key', 'alg' => WebAuthn::ALG_RS256]],
            'timeout' => 120000, 'attestation' => 'none',
            'authenticatorSelection' => ['residentKey' => 'discouraged', 'userVerification' => $this->wa()['require_uv'] ? 'required' : 'preferred'],
            'excludeCredentials' => array_map(static fn (array $r): array => ['type' => 'public-key', 'id' => WebAuthn::b64uEncode($r['credential_id'])], $this->waRows($user)),
        ];
    }

    public function webauthnFinishRegister(array $credential, string $name): bool
    {
        $user = $this->currentUser();
        $challenge = $this->waTake('register');
        $name = trim($name);
        if ($user === null || $challenge === null || $name === '' || mb_strlen($name) > 60) {
            return false;
        }
        try {
            $r = WebAuthn::verifyRegistration($credential, $challenge['c'], $this->wa()['origin'], $this->wa()['rp_id'], $this->wa()['require_uv']);
            $this->db->asActor($user->id, static function (PDO $tx) use ($user, $r, $name): void {
                $s = $tx->prepare('SELECT webauthn_register(?, ?, ?, ?, ?, ?, ?, NULL)');
                $s->bindValue(1, $user->id, PDO::PARAM_INT);
                $s->bindValue(2, $r['credential_id'], PDO::PARAM_LOB);
                $s->bindValue(3, $r['pem']);
                $s->bindValue(4, $r['alg'], PDO::PARAM_INT);
                $s->bindValue(5, $r['sign_count'], PDO::PARAM_INT);
                $s->bindValue(6, $r['user_verified'], PDO::PARAM_BOOL);
                $s->bindValue(7, $name);
                $s->execute();
            });
        } catch (InvalidArgumentException | \PDOException) {
            $this->audit->standalone($user, 'auth.webauthn_register', 'user', $user->id, 'denied', [], verified: true);
            return false;
        }
        $this->audit->standalone($user, 'auth.webauthn_register', 'user', $user->id, 'success', ['name' => $name], verified: true);
        return true;
    }

    public function webauthnDelete(int $keyId): bool
    {
        $user = $this->currentUser();
        if ($user === null) {
            return false;
        }
        try {
            $ok = (bool) $this->db->asActor($user->id, static function (PDO $tx) use ($user, $keyId): bool {
                $s = $tx->prepare('SELECT webauthn_delete(?, ?)');
                $s->execute([$user->id, $keyId]);
                return (bool) $s->fetchColumn();
            });
        } catch (\PDOException) {
            return false;                              // the last second factor cannot be removed
        }
        if ($ok) {
            $this->audit->standalone($user, 'auth.webauthn_removed', 'user', $user->id, 'success', ['key_id' => $keyId], verified: true);
        }
        return $ok;
    }
}
