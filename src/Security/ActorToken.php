<?php
declare(strict_types=1);

namespace App\Security;

use RuntimeException;

/**
 * Proof of identity that the DATABASE can check (findings O02 and O03).
 *
 * The web process signs "v1|<user id>|<expiry>|<nonce>" with HMAC-SHA256 using a key that is stored in
 * secrets/actor.key (readable by the web process only) and, for verification, in a table that only the schema
 * owner can read (database/06_identity_and_audit.sql). The runtime database password alone cannot produce a valid
 * token, so holding it no longer lets anyone act as a user or write an audit event that names one.
 *
 * Tokens live 120 seconds and are set per transaction; the nonce is the request's correlation id.
 */
final class ActorToken implements ActorTokenSource
{
    public function __construct(#[\SensitiveParameter] private readonly string $key)
    {
    }

    public static function fromKeyFile(string $path): self
    {
        $hex = is_readable($path) ? trim((string) file_get_contents($path)) : '';
        if (!preg_match('/^[0-9a-f]{64}$/', $hex)) {
            throw new RuntimeException('Actor key is missing or malformed.');
        }
        return new self((string) hex2bin($hex));
    }

    public function tokenFor(int $userId, ?string $nonce = null): string
    {
        return $this->mint($userId, $nonce);
    }

    public function mint(int $userId, ?string $nonce = null, int $ttlSeconds = 120): string
    {
        $nonce = $nonce !== null ? preg_replace('/[^0-9a-f]/', '', strtolower($nonce)) : bin2hex(random_bytes(8));
        $nonce = substr((string) $nonce, 0, 32);
        if (strlen($nonce) < 8) {
            $nonce = bin2hex(random_bytes(8));
        }
        $expires = time() + $ttlSeconds;
        $mac = hash_hmac('sha256', sprintf('v1|%d|%d|%s', $userId, $expires, $nonce), $this->key);
        return sprintf('v1.%d.%d.%s.%s', $userId, $expires, $nonce, $mac);
    }
}
