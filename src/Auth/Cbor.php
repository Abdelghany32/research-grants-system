<?php
declare(strict_types=1);

namespace App\Auth;

use InvalidArgumentException;

/**
 * A strict decoder for the small part of CBOR (RFC 8949) that WebAuthn uses: unsigned and negative integers, byte and
 * text strings, arrays, maps with integer or text keys, booleans and null. Indefinite lengths, tags and floats are refused,
 * as are nesting deeper than 8 and lengths that run past the input.
 */
final class Cbor
{
    /** @return mixed the single item that makes up the whole input */
    public static function decodeAll(string $bin): mixed
    {
        $offset = 0;
        $value = self::decode($bin, $offset, 0);
        if ($offset !== strlen($bin)) {
            throw new InvalidArgumentException('Trailing bytes after the CBOR item.');
        }
        return $value;
    }

    /** Decode one item starting at $offset; $offset is moved past it. */
    public static function decode(string $bin, int &$offset, int $depth = 0): mixed
    {
        if ($depth > 8 || $offset >= strlen($bin)) {
            throw new InvalidArgumentException('CBOR is too deep or truncated.');
        }
        $initial = ord($bin[$offset++]);
        $major = $initial >> 5;
        $info = $initial & 0x1f;
        if ($major === 7) {
            return match ($info) {
                20 => false, 21 => true, 22 => null,
                default => throw new InvalidArgumentException('Unsupported CBOR simple value or float.'),
            };
        }
        $len = self::argument($bin, $offset, $info);
        switch ($major) {
            case 0:
                return $len;
            case 1:
                return -1 - $len;
            case 2:
            case 3:
                if ($len > strlen($bin) - $offset) {
                    throw new InvalidArgumentException('CBOR string runs past the input.');
                }
                $s = substr($bin, $offset, $len);
                $offset += $len;
                return $s;
            case 4:
                if ($len > 1024) {
                    throw new InvalidArgumentException('CBOR array too long.');
                }
                $a = [];
                for ($i = 0; $i < $len; $i++) {
                    $a[] = self::decode($bin, $offset, $depth + 1);
                }
                return $a;
            case 5:
                if ($len > 256) {
                    throw new InvalidArgumentException('CBOR map too large.');
                }
                $m = [];
                for ($i = 0; $i < $len; $i++) {
                    $k = self::decode($bin, $offset, $depth + 1);
                    if (!is_int($k) && !is_string($k)) {
                        throw new InvalidArgumentException('CBOR map key must be an integer or a text string.');
                    }
                    $m[$k] = self::decode($bin, $offset, $depth + 1);
                }
                return $m;
            default:
                throw new InvalidArgumentException('Unsupported CBOR major type (tags are not used by WebAuthn).');
        }
    }

    private static function argument(string $bin, int &$offset, int $info): int
    {
        if ($info < 24) {
            return $info;
        }
        $size = match ($info) { 24 => 1, 25 => 2, 26 => 4, 27 => 8, default => throw new InvalidArgumentException('Indefinite or reserved CBOR length.') };
        if ($size > strlen($bin) - $offset) {
            throw new InvalidArgumentException('Truncated CBOR argument.');
        }
        $raw = substr($bin, $offset, $size);
        $offset += $size;
        $n = match ($size) { 1 => ord($raw), 2 => unpack('n', $raw)[1], 4 => unpack('N', $raw)[1], 8 => unpack('J', $raw)[1] };
        if ($n < 0) {
            throw new InvalidArgumentException('CBOR integer too large.');
        }
        return $n;
    }
}
