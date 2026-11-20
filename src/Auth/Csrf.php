<?php
declare(strict_types=1);

namespace App\Auth;

/**
 * Synchronizer token: a random value stored in the session and repeated in
 * every state-changing form. Another site can make the browser send the
 * cookie, but it cannot read this token.
 */
final class Csrf
{
    public static function token(Session $session): string
    {
        $token = $session->get('csrf');
        if (!is_string($token)) {
            $token = bin2hex(random_bytes(32));
            $session->set('csrf', $token);
        }
        return $token;
    }

    public static function isValid(Session $session, mixed $submitted): bool
    {
        $token = $session->get('csrf');
        return is_string($token) && is_string($submitted) && hash_equals($token, $submitted);
    }
}
