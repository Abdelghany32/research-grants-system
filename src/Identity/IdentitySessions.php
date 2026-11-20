<?php
declare(strict_types=1);

namespace App\Identity;

use App\Auth\ArraySessionStore;
use App\Database\Database;
use App\Security\FieldCipher;

/**
 * The identity service's own session store: one row per session, keyed by the SHA-256 of an opaque 256-bit handle
 * (the database never holds a usable handle) with the session data encrypted under the field keyring and bound to
 * its row. Only the identity account can touch the table.
 */
final class IdentitySessions
{
    private const PENDING_LIFETIME = '10 minutes';
    private const SESSION_LIFETIME = '9 hours';      // the 8-hour absolute limit plus a margin; the real limit is enforced by Authenticator

    public function __construct(private readonly Database $db, private readonly FieldCipher $cipher)
    {
    }

    public static function isHandle(mixed $h): bool
    {
        return is_string($h) && (bool) preg_match('/^[0-9a-f]{64}$/', $h);
    }

    /** @return array the stored session data, or [] for an unknown or expired handle */
    public function load(?string $handle): array
    {
        if (!self::isHandle($handle)) {
            return [];
        }
        $hash = hash('sha256', (string) $handle, true);
        $s = $this->db->pdo()->prepare('SELECT data_enc FROM identity_sessions WHERE handle_hash = ? AND expires_at > now()');
        $s->bindValue(1, $hash, \PDO::PARAM_LOB);
        $s->execute();
        $enc = $s->fetchColumn();
        if (!is_string($enc)) {
            return [];
        }
        try {
            $data = json_decode($this->cipher->decrypt($enc, 'identity_sessions:' . bin2hex($hash)), true, 8, JSON_THROW_ON_ERROR);
        } catch (\Throwable) {
            return [];
        }
        return is_array($data) ? $data : [];
    }

    /** Save the session after a call; returns the handle the caller must use next (null = no session). */
    public function persist(?string $handle, ArraySessionStore $store): ?string
    {
        $pdo = $this->db->pdo();
        if (random_int(1, 25) === 1) {
            $pdo->exec('DELETE FROM identity_sessions WHERE expires_at < now()');
        }
        $old = self::isHandle($handle) ? hash('sha256', (string) $handle, true) : null;
        $data = $store->data();
        if ($store->destroyed || $data === []) {
            if ($old !== null) {
                $this->delete($old);
            }
            return null;
        }
        if (!$store->dirty && $old !== null) {
            return $handle;                      // read-only call (should not happen: currentUser touches seen_at)
        }
        $newHandle = ($store->rotated || $old === null) ? bin2hex(random_bytes(32)) : (string) $handle;
        $hash = hash('sha256', $newHandle, true);
        $userId = isset($data['user_id']) && is_int($data['user_id']) ? $data['user_id'] : null;
        $enc = $this->cipher->encrypt(json_encode($data, JSON_THROW_ON_ERROR), 'identity_sessions:' . bin2hex($hash));
        $life = $userId === null ? self::PENDING_LIFETIME : self::SESSION_LIFETIME;
        if ($old !== null && $old !== $hash) {
            $this->delete($old);                 // the previous handle stops working the moment a new one is issued
        }
        $s = $pdo->prepare("INSERT INTO identity_sessions (handle_hash, data_enc, user_id, expires_at)
                            VALUES (?, ?, ?, now() + interval '$life')
                            ON CONFLICT (handle_hash) DO UPDATE SET data_enc = EXCLUDED.data_enc, user_id = EXCLUDED.user_id,
                                last_seen_at = now(), expires_at = EXCLUDED.expires_at");
        $s->bindValue(1, $hash, \PDO::PARAM_LOB);
        $s->bindValue(2, $enc);
        $s->bindValue(3, $userId, $userId === null ? \PDO::PARAM_NULL : \PDO::PARAM_INT);
        $s->execute();
        return $newHandle;
    }

    private function delete(string $hash): void
    {
        $s = $this->db->pdo()->prepare('DELETE FROM identity_sessions WHERE handle_hash = ?');
        $s->bindValue(1, $hash, \PDO::PARAM_LOB);
        $s->execute();
    }
}
