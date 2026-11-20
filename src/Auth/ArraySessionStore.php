<?php
declare(strict_types=1);

namespace App\Auth;

/** One session held in memory for the duration of one identity-service call, then persisted by the caller. */
final class ArraySessionStore implements SessionStore
{
    public bool $dirty = false;
    public bool $rotated = false;
    public bool $destroyed = false;

    public function __construct(private array $data, private readonly array $config)
    {
    }

    public function start(): void
    {
    }

    public function data(): array
    {
        return $this->data;
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->data[$key] ?? $default;
    }

    public function set(string $key, mixed $value): void
    {
        $this->data[$key] = $value;
        $this->dirty = true;
    }

    public function pull(string $key, mixed $default = null): mixed
    {
        $value = $this->data[$key] ?? $default;
        if (array_key_exists($key, $this->data)) {
            unset($this->data[$key]);
            $this->dirty = true;
        }
        return $value;
    }

    public function regenerate(): void
    {
        $this->rotated = true;
        $this->dirty = true;
    }

    public function destroy(): void
    {
        $this->data = [];
        $this->destroyed = true;
        $this->dirty = true;
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
