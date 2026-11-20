<?php
declare(strict_types=1);

namespace App\Security;

use RuntimeException;

/**
 * Encrypts one confidential column (reviews.comments_enc) before it reaches
 * PostgreSQL, using XChaCha20-Poly1305 (authenticated encryption, libsodium).
 *
 * KEY MANAGEMENT
 *  - The 256-bit keys live in a keyring file outside the database and outside
 *    the repository, so a database dump, a backup or a DBA session alone cannot
 *    reveal the comments.
 *  - Keyring format, one key per line:  <key id>:<base64 of 32 random bytes>
 *    The FIRST line is the active key (used to encrypt); every line can decrypt.
 *    A legacy file holding a single bare base64 line is read as key id "k1".
 *  - Every ciphertext names the key that produced it ("v2:<key id>:<payload>"),
 *    so a key can be rotated without a flag day: add a new first line, re-encrypt
 *    the rows (scripts/rotate-field-key.sh), then retire the old line once no
 *    row refers to it.
 *  - The "context" (e.g. "reviews.comments:42") and the header (version + key id)
 *    are authenticated but not stored twice: a ciphertext copied onto another row,
 *    or relabelled with another key id, fails to decrypt.
 *  - "v1:" values (the original format, no key id, key = "k1") are still readable.
 */
final class FieldCipher
{
    private const LEGACY_KEY_ID = 'k1';

    /** @param array<string,string> $keys key id => 32 raw bytes, active key first */
    private function __construct(private readonly array $keys)
    {
    }

    public static function fromKeyFile(string $path): self
    {
        $lines = is_readable($path) ? preg_split('/\R/', (string) file_get_contents($path)) : false;
        $keys = [];
        foreach ($lines ?: [] as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            if (str_contains($line, ':')) {
                [$id, $b64] = explode(':', $line, 2);
            } else {
                [$id, $b64] = [self::LEGACY_KEY_ID, $line];     // legacy single-key file
            }
            $raw = base64_decode(trim($b64), true);
            if (!preg_match('/^[a-z0-9]{1,16}$/', $id) || $raw === false
                || strlen($raw) !== SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES || isset($keys[$id])) {
                throw new RuntimeException('Field encryption keyring is malformed.');
            }
            $keys[$id] = $raw;
        }
        if ($keys === []) {
            throw new RuntimeException('Field encryption key is missing or malformed.');
        }
        return new self($keys);
    }

    public function activeKeyId(): string
    {
        return (string) array_key_first($this->keys);
    }

    /** @return list<string> */
    public function keyIds(): array
    {
        return array_keys($this->keys);
    }

    /** The key id a stored value was encrypted with ("k1" for the legacy v1 format), or null if unrecognised. */
    public static function keyIdOf(string $stored): ?string
    {
        if (str_starts_with($stored, 'v1:')) {
            return self::LEGACY_KEY_ID;
        }
        return preg_match('/^v2:([a-z0-9]{1,16}):/', $stored, $m) ? $m[1] : null;
    }

    public function encrypt(string $plaintext, string $context): string
    {
        $id = $this->activeKeyId();
        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $ct = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plaintext, self::aad('v2', $id, $context), $nonce, $this->keys[$id]);
        return "v2:$id:" . base64_encode($nonce . $ct);
    }

    public function decrypt(string $stored, string $context): string
    {
        $parts = explode(':', $stored, 3);
        if ($parts[0] === 'v1') {
            // Original format: no key id in the value, key "k1", the context alone as associated data.
            [$id, $payload, $aad] = [self::LEGACY_KEY_ID, implode(':', array_slice($parts, 1)), $context];
        } elseif ($parts[0] === 'v2' && count($parts) === 3) {
            [, $id, $payload] = $parts;
            $aad = self::aad('v2', $id, $context);
        } else {
            throw new RuntimeException('Unrecognised ciphertext format.');
        }
        if (!isset($this->keys[$id])) {
            throw new RuntimeException("Ciphertext was made with key '$id', which is not in the keyring.");
        }
        $raw = base64_decode($payload, true);
        $n = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
        if ($raw === false || strlen($raw) <= $n) {
            throw new RuntimeException('Unrecognised ciphertext format.');
        }
        $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(substr($raw, $n), $aad, substr($raw, 0, $n), $this->keys[$id]);
        if ($plain === false) {
            throw new RuntimeException('Ciphertext failed authentication (wrong key, wrong row, or tampering).');
        }
        return $plain;
    }

    private static function aad(string $version, string $keyId, string $context): string
    {
        return "$version:$keyId|$context";
    }
}
