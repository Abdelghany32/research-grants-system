<?php
declare(strict_types=1);

namespace App\Http;

final class Response
{
    private function __construct(
        public readonly int $status,
        public readonly string $body,
        public readonly ?string $location = null,
        public readonly ?string $contentType = null,
        public readonly ?string $download = null,
    ) {
    }

    public static function html(string $body, int $status = 200): self
    {
        return new self($status, $body);
    }

    /** A JSON reply for the security-key scripts. */
    public static function json(array $data, int $status = 200): self
    {
        return new self($status, json_encode($data, JSON_THROW_ON_ERROR), null, 'application/json; charset=utf-8');
    }

    /** A file download (CSV). The file name is fixed by the server, never taken from the request. */
    public static function csv(string $body, string $filename): self
    {
        return new self(200, $body, null, 'text/csv; charset=utf-8', $filename);
    }

    /** 303 See Other after a POST: a browser refresh cannot repeat the action. */
    public static function redirect(string $path): self
    {
        return new self(303, '', $path);
    }

    public function send(): void
    {
        http_response_code($this->status);
        if ($this->location !== null) {
            header('Location: ' . $this->location);
            return;
        }
        header('Content-Type: ' . ($this->contentType ?? 'text/html; charset=utf-8'));
        if ($this->download !== null) {
            header('Content-Disposition: attachment; filename="' . $this->download . '"');
        }
        echo $this->body;
    }
}
