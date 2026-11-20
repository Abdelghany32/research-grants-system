<?php
declare(strict_types=1);

namespace App\Auth;

/** Server-side session: the browser only ever holds a random identifier. */
final class Session implements SessionStore
{
    private bool $started = false;

    public function __construct(private readonly array $config)
    {
    }

    public function start(): void
    {
        if ($this->started) {
            return;
        }
        $https = ($_SERVER['HTTPS'] ?? '') === 'on';
        // "__Host-" makes the browser refuse the cookie unless it is Secure,
        // host-only and Path=/ - it cannot be set from a sibling sub-domain.
        session_name($https ? '__Host-grants' : 'grants_session');
        session_set_cookie_params([
            'lifetime' => 0,          // dies with the browser session
            'path'     => '/',
            'secure'   => $https,
            'httponly' => true,       // not readable from JavaScript
            'samesite' => 'Lax',
        ]);
        ini_set('session.use_strict_mode', '1');   // reject identifiers the server did not issue
        ini_set('session.use_only_cookies', '1');
        session_start();
        $this->started = true;
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return $_SESSION[$key] ?? $default;
    }

    public function set(string $key, mixed $value): void
    {
        $_SESSION[$key] = $value;
    }

    public function pull(string $key, mixed $default = null): mixed
    {
        $value = $_SESSION[$key] ?? $default;
        unset($_SESSION[$key]);
        return $value;
    }

    /** New identifier at login: defeats session fixation. */
    public function regenerate(): void
    {
        session_regenerate_id(true);
    }

    public function destroy(): void
    {
        $_SESSION = [];
        if ($this->started && session_status() === PHP_SESSION_ACTIVE) {
            $p = session_get_cookie_params();
            setcookie(session_name(), '', ['expires' => 1, 'path' => $p['path'], 'secure' => $p['secure'],
                                           'httponly' => true, 'samesite' => 'Lax']);
            session_destroy();
        }
        $this->started = false;
    }

    public function idleSeconds(): int
    {
        return $this->config['idle_seconds'];
    }

    public function absoluteSeconds(): int
    {
        return $this->config['absolute_seconds'];
    }
}
