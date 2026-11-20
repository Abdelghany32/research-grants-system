<?php
declare(strict_types=1);

namespace App\Auth;

/**
 * Where an authentication session keeps its state. The web front end uses PHP's own session (Session); the identity
 * service keeps sessions in its own database table, keyed by an opaque handle (ArraySessionStore, loaded per call).
 */
interface SessionStore
{
    public function start(): void;

    public function get(string $key, mixed $default = null): mixed;

    public function set(string $key, mixed $value): void;

    public function pull(string $key, mixed $default = null): mixed;

    /** New identifier at login: defeats session fixation. */
    public function regenerate(): void;

    public function destroy(): void;

    public function idleSeconds(): int;

    public function absoluteSeconds(): int;
}
