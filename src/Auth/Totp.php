<?php
declare(strict_types=1);

namespace App\Auth;

/**
 * Time-based one-time passwords, RFC 6238 (HMAC-SHA1, 30-second steps, 6 digits), the format every authenticator
 * app understands. No library: HOTP (RFC 4226) is an HMAC and a truncation.
 */
final class Totp
{
    public const PERIOD = 30;
    public const DIGITS = 6;
    private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /** 160 random bits as base32 (the form authenticator apps expect). */
    public static function generateSecret(): string
    {
        return self::base32Encode(random_bytes(20));
    }

    public static function step(?int $time = null): int
    {
        return intdiv($time ?? time(), self::PERIOD);
    }

    public static function code(#[\SensitiveParameter] string $secretBase32, int $step): string
    {
        $key = self::base32Decode($secretBase32);
        $mac = hash_hmac('sha1', pack('J', $step), $key, true);
        $offset = ord($mac[19]) & 0x0f;
        $bin = ((ord($mac[$offset]) & 0x7f) << 24) | (ord($mac[$offset + 1]) << 16) | (ord($mac[$offset + 2]) << 8) | ord($mac[$offset + 3]);
        return str_pad((string) ($bin % 10 ** self::DIGITS), self::DIGITS, '0', STR_PAD_LEFT);
    }

    /**
     * The step a submitted code belongs to, within +-$window steps of now (clock drift), or null.
     * Constant-time comparison; the caller must still record the step so a code cannot be used twice.
     */
    public static function matchStep(#[\SensitiveParameter] string $secretBase32, string $submitted, int $window = 1, ?int $time = null): ?int
    {
        $submitted = preg_replace('/\s+/', '', $submitted) ?? '';
        if (!preg_match('/^\d{6}$/', $submitted)) {
            return null;
        }
        $now = self::step($time);
        $found = null;
        for ($s = $now - $window; $s <= $now + $window; $s++) {
            if (hash_equals(self::code($secretBase32, $s), $submitted) && $found === null) {
                $found = $s;                         // keep looping: the time taken does not depend on where it matched
            }
        }
        return $found;
    }

    public static function uri(string $secretBase32, string $account, string $issuer): string
    {
        return sprintf('otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d',
            rawurlencode($issuer), rawurlencode($account), $secretBase32, rawurlencode($issuer), self::DIGITS, self::PERIOD);
    }

    /** Eight single-use recovery codes, e.g. "k7p2-9xqm-4tdw"; shown once, stored only as Argon2id hashes. */
    public static function recoveryCodes(int $count = 8): array
    {
        $alphabet = 'abcdefghjkmnpqrstuvwxyz23456789';     // no look-alikes (0/o, 1/l/i)
        $codes = [];
        for ($i = 0; $i < $count; $i++) {
            $parts = [];
            for ($p = 0; $p < 3; $p++) {
                $part = '';
                for ($c = 0; $c < 4; $c++) {
                    $part .= $alphabet[random_int(0, strlen($alphabet) - 1)];
                }
                $parts[] = $part;
            }
            $codes[] = implode('-', $parts);
        }
        return $codes;
    }

    public static function base32Encode(string $bytes): string
    {
        $bits = '';
        foreach (str_split($bytes) as $ch) {
            $bits .= str_pad(decbin(ord($ch)), 8, '0', STR_PAD_LEFT);
        }
        $out = '';
        foreach (str_split($bits, 5) as $chunk) {
            $out .= self::ALPHABET[bindec(str_pad($chunk, 5, '0'))];
        }
        return $out;
    }

    public static function base32Decode(string $text): string
    {
        $text = strtoupper(preg_replace('/[\s=-]+/', '', $text) ?? '');
        $bits = '';
        foreach (str_split($text) as $ch) {
            $v = strpos(self::ALPHABET, $ch);
            if ($v === false) {
                throw new \InvalidArgumentException('Not a base32 string.');
            }
            $bits .= str_pad(decbin($v), 5, '0', STR_PAD_LEFT);
        }
        $out = '';
        foreach (str_split($bits, 8) as $byte) {
            if (strlen($byte) === 8) {
                $out .= chr(bindec($byte));
            }
        }
        return $out;
    }
}
