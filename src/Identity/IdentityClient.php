<?php
declare(strict_types=1);

namespace App\Identity;

use App\Auth\LoginThrottled;
use App\Auth\SessionStore;
use App\Security\ActorTokenSource;
use RuntimeException;

/**
 * The web front end's view of the identity service: signed HTTP calls, the opaque session handle (kept in the PHP
 * session, never in a cookie of its own), and the actor token the service returns for the signed-in user.
 *
 * The front end can obtain a token ONLY for the user of the session it holds the handle of. Asking for a token for any
 * other user is a programming error here and impossible against the service.
 */
final class IdentityClient implements ActorTokenSource
{
    private ?string $handle = null;
    private bool $handleLoaded = false;
    private ?array $user = null;
    private ?string $token = null;

    public function __construct(
        private readonly string $url,
        #[\SensitiveParameter] private readonly string $apiKeyHex,
        private readonly SessionStore $session,
        private readonly string $correlationId,
        private readonly ?string $ip,
        private readonly int $timeout = 8,
    ) {
    }

    public function hasHandle(): bool
    {
        return $this->handle() !== null;
    }

    /** The user the last reply identified (the signed-in user of this session), or null. */
    public function user(): ?array
    {
        return $this->user;
    }

    public function tokenFor(int $userId, ?string $nonce = null): string
    {
        if ($this->token === null || ($this->user['id'] ?? null) !== $userId) {
            throw new \LogicException('This process holds no identity for that user: only the signed-in user of the current session can be acted for.');
        }
        return $this->token;
    }

    /**
     * @return array the service's reply ({ok, result, handle, user, token})
     * @throws LoginThrottled when this address is throttled
     * @throws RuntimeException when the service cannot be reached or refuses the call (the request then fails closed)
     */
    public function call(string $method, array $args = []): array
    {
        $body = json_encode(['method' => $method, 'args' => $args, 'handle' => $this->handle(), 'ip' => $this->ip ?? '0.0.0.0',
                             'correlation' => $this->correlationId], JSON_THROW_ON_ERROR);
        $time = (string) time();
        $ch = curl_init(rtrim($this->url, '/') . '/v1/call');
        curl_setopt_array($ch, [
            CURLOPT_POST => true, CURLOPT_POSTFIELDS => $body, CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => 3, CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'X-Time: ' . $time,
                                   'X-Signature: ' . hash_hmac('sha256', $time . "\n" . $body, (string) hex2bin($this->apiKeyHex))],
        ]);
        $raw = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        unset($ch);
        $reply = is_string($raw) ? json_decode($raw, true) : null;
        if (!is_array($reply) || ($status !== 200 && $status !== 0 && !isset($reply['error']))) {
            throw new RuntimeException('The identity service did not answer (HTTP ' . $status . ').');
        }
        if (array_key_exists('handle', $reply)) {
            $this->setHandle(is_string($reply['handle']) ? $reply['handle'] : null);
        }
        if (($reply['ok'] ?? false) !== true) {
            if (($reply['error'] ?? '') === 'throttled') {
                throw new LoginThrottled((int) ($reply['retry_after'] ?? 600));
            }
            throw new RuntimeException('The identity service refused the call: ' . (string) ($reply['error'] ?? 'unknown'));
        }
        $this->user = is_array($reply['user'] ?? null) ? $reply['user'] : null;
        $this->token = is_string($reply['token'] ?? null) ? $reply['token'] : null;
        return $reply;
    }

    private function handle(): ?string
    {
        if (!$this->handleLoaded) {
            $h = $this->session->get('idhandle');
            $this->handle = IdentitySessions::isHandle($h) ? $h : null;
            $this->handleLoaded = true;
        }
        return $this->handle;
    }

    private function setHandle(?string $h): void
    {
        $this->handle = $h;
        $this->handleLoaded = true;
        if ($h === null) {
            $this->session->pull('idhandle');
            $this->user = null;
            $this->token = null;
        } else {
            $this->session->set('idhandle', $h);
        }
    }
}
