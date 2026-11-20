<?php
declare(strict_types=1);

namespace App\Auth;

use InvalidArgumentException;

/**
 * Server side of WebAuthn Level 2 (FIDO2): option building and the verification of registration (attestation "none")
 * and authentication ceremonies, with ES256 and RS256 keys. Stateless: the caller keeps the challenge.
 *
 * What is checked, for both ceremonies: the type, the single-use challenge, the origin, that the browser did not report a
 * cross-origin request, the SHA-256 of the relying-party id, the user-presence flag (and user verification when the
 * policy asks for it); and, for authentication, the signature over authenticatorData || SHA-256(clientDataJSON).
 */
final class WebAuthn
{
    public const ALG_ES256 = -7;
    public const ALG_RS256 = -257;

    public static function b64uEncode(string $bin): string
    {
        return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
    }

    public static function b64uDecode(string $s): string
    {
        if ($s === '' || !preg_match('/^[A-Za-z0-9_-]+$/', $s)) {
            throw new InvalidArgumentException('Not base64url.');
        }
        $bin = base64_decode(strtr($s, '-_', '+/') . str_repeat('=', (4 - strlen($s) % 4) % 4), true);
        if ($bin === false) {
            throw new InvalidArgumentException('Not base64url.');
        }
        return $bin;
    }

    public static function newChallenge(): string
    {
        return self::b64uEncode(random_bytes(32));
    }

    /** An opaque, stable user handle that reveals nothing about the person. */
    public static function userHandle(int $userId): string
    {
        return hash('sha256', 'grants-webauthn-user:' . $userId, true);
    }

    /**
     * Verify a registration response.
     *
     * @param array{id:string, response:array{clientDataJSON:string, attestationObject:string}} $credential (base64url strings)
     * @return array{credential_id:string, pem:string, alg:int, sign_count:int, user_verified:bool}
     * @throws InvalidArgumentException on any failure (the message is for the log, never for the user)
     */
    public static function verifyRegistration(array $credential, string $challenge, string $origin, string $rpId, bool $requireUv): array
    {
        $clientData = self::clientData($credential['response']['clientDataJSON'] ?? '', 'webauthn.create', $challenge, $origin);
        $att = Cbor::decodeAll(self::b64uDecode($credential['response']['attestationObject'] ?? ''));
        if (!is_array($att) || ($att['fmt'] ?? null) !== 'none' || !isset($att['authData']) || !is_string($att['authData'])) {
            throw new InvalidArgumentException('Only attestation "none" is accepted.');
        }
        $auth = self::parseAuthData($att['authData'], $rpId, $requireUv, true);
        if (!isset($auth['credential'])) {
            throw new InvalidArgumentException('No attested credential data.');
        }
        $id = self::b64uDecode((string) ($credential['id'] ?? ''));
        if (!hash_equals($auth['credential']['id'], $id) || strlen($id) < 16 || strlen($id) > 1023) {
            throw new InvalidArgumentException('Credential id mismatch.');
        }
        [$pem, $alg] = self::coseToPem($auth['credential']['key']);
        return ['credential_id' => $id, 'pem' => $pem, 'alg' => $alg, 'sign_count' => $auth['counter'], 'user_verified' => $auth['uv']];
    }

    /**
     * Verify an authentication response against a stored public key.
     *
     * @return array{sign_count:int, user_verified:bool}
     */
    public static function verifyAssertion(array $credential, string $challenge, string $origin, string $rpId, bool $requireUv, string $pem): array
    {
        $r = $credential['response'] ?? [];
        $clientDataRaw = self::b64uDecode((string) ($r['clientDataJSON'] ?? ''));
        self::clientData((string) ($r['clientDataJSON'] ?? ''), 'webauthn.get', $challenge, $origin);
        $authData = self::b64uDecode((string) ($r['authenticatorData'] ?? ''));
        $signature = self::b64uDecode((string) ($r['signature'] ?? ''));
        $auth = self::parseAuthData($authData, $rpId, $requireUv, false);
        $ok = openssl_verify($authData . hash('sha256', $clientDataRaw, true), $signature, $pem, OPENSSL_ALGO_SHA256);
        if ($ok !== 1) {
            throw new InvalidArgumentException('Signature does not verify.');
        }
        return ['sign_count' => $auth['counter'], 'user_verified' => $auth['uv']];
    }

    /** @return array decoded clientDataJSON after the common checks */
    private static function clientData(string $b64, string $type, string $challenge, string $origin): array
    {
        $json = json_decode(self::b64uDecode($b64), true, 4);
        if (!is_array($json) || ($json['type'] ?? null) !== $type) {
            throw new InvalidArgumentException('Wrong ceremony type.');
        }
        if (!is_string($json['challenge'] ?? null) || !hash_equals($challenge, $json['challenge'])) {
            throw new InvalidArgumentException('Challenge mismatch (or reused).');
        }
        if (($json['origin'] ?? null) !== $origin) {
            throw new InvalidArgumentException('Origin mismatch.');
        }
        if (($json['crossOrigin'] ?? false) === true) {
            throw new InvalidArgumentException('Cross-origin ceremony.');
        }
        return $json;
    }

    /** @return array{counter:int, uv:bool, credential?:array{id:string, key:array}} */
    private static function parseAuthData(string $d, string $rpId, bool $requireUv, bool $expectAttested): array
    {
        if (strlen($d) < 37) {
            throw new InvalidArgumentException('authenticatorData too short.');
        }
        if (!hash_equals(hash('sha256', $rpId, true), substr($d, 0, 32))) {
            throw new InvalidArgumentException('Relying party id hash mismatch.');
        }
        $flags = ord($d[32]);
        if (!($flags & 0x01)) {
            throw new InvalidArgumentException('User presence flag not set.');
        }
        $uv = (bool) ($flags & 0x04);
        if ($requireUv && !$uv) {
            throw new InvalidArgumentException('User verification required but not performed.');
        }
        $out = ['counter' => unpack('N', substr($d, 33, 4))[1], 'uv' => $uv];
        if ($expectAttested) {
            if (!($flags & 0x40) || strlen($d) < 55) {
                throw new InvalidArgumentException('Attested credential data missing.');
            }
            $len = unpack('n', substr($d, 53, 2))[1];
            if ($len < 16 || $len > 1023 || strlen($d) < 55 + $len) {
                throw new InvalidArgumentException('Bad credential id length.');
            }
            $id = substr($d, 55, $len);
            $offset = 55 + $len;
            $key = Cbor::decode($d, $offset, 0);
            if (!is_array($key)) {
                throw new InvalidArgumentException('Bad credential public key.');
            }
            $out['credential'] = ['id' => $id, 'key' => $key];
        }
        return $out;
    }

    /** @return array{0:string, 1:int} PEM public key and COSE algorithm */
    public static function coseToPem(array $key): array
    {
        $kty = $key[1] ?? null;
        $alg = $key[3] ?? null;
        if ($kty === 2 && $alg === self::ALG_ES256 && ($key[-1] ?? null) === 1 && is_string($key[-2] ?? null) && is_string($key[-3] ?? null)
            && strlen($key[-2]) === 32 && strlen($key[-3]) === 32) {
            $der = hex2bin('3059301306072a8648ce3d020106082a8648ce3d030107034200') . "\x04" . $key[-2] . $key[-3];
        } elseif ($kty === 3 && $alg === self::ALG_RS256 && is_string($key[-1] ?? null) && is_string($key[-2] ?? null) && strlen($key[-1]) >= 256) {
            $rsa = self::der(0x30, self::derInt($key[-1]) . self::derInt($key[-2]));
            $algId = self::der(0x30, hex2bin('06092a864886f70d010101') . "\x05\x00");
            $der = self::der(0x30, $algId . self::der(0x03, "\x00" . $rsa));
        } else {
            throw new InvalidArgumentException('Unsupported credential key type (ES256 and RS256 only).');
        }
        $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
        if (openssl_pkey_get_public($pem) === false) {
            throw new InvalidArgumentException('The public key is not valid.');
        }
        return [$pem, $alg];
    }

    private static function der(int $tag, string $content): string
    {
        $n = strlen($content);
        $len = $n < 128 ? chr($n) : (($n < 256) ? "\x81" . chr($n) : "\x82" . pack('n', $n));
        return chr($tag) . $len . $content;
    }

    private static function derInt(string $bin): string
    {
        $bin = ltrim($bin, "\x00");
        return self::der(0x02, (ord($bin[0] ?? "\x00") & 0x80 ? "\x00" : '') . $bin);
    }
}
