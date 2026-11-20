<?php
declare(strict_types=1);

namespace App\Identity;

use App\Auth\AuthService;
use App\Auth\MfaChallenge;
use App\Auth\SessionStore;
use App\Auth\User;

/** AuthService for the web front end: every step is a call to the identity service. */
final class RemoteAuthenticator implements AuthService
{
    private bool $currentLoaded = false;
    private ?User $current = null;

    public function __construct(private readonly IdentityClient $client, private readonly SessionStore $session)
    {
    }

    public function login(string $email, #[\SensitiveParameter] string $password): User|MfaChallenge|null
    {
        $r = $this->client->call('login', [$email, $password]);
        $res = $r['result'] ?? ['kind' => 'none'];
        if (($res['kind'] ?? 'none') === 'none') {
            return null;
        }
        // The front end rotates ITS OWN session identifier and CSRF token at every sign-in step (fixation defence).
        $this->session->regenerate();
        $this->session->set('csrf', bin2hex(random_bytes(32)));
        $user = User::fromRow($res['user']);
        if ($res['kind'] === 'mfa') {
            return new MfaChallenge($user, (bool) $res['enrolled']);
        }
        return $this->current = $user;
    }

    public function currentUser(): ?User
    {
        if ($this->currentLoaded) {
            return $this->current;
        }
        $this->currentLoaded = true;
        if (!$this->client->hasHandle()) {
            return null;
        }
        $r = $this->client->call('currentUser');
        if (is_array($r['result'] ?? null)) {
            return $this->current = User::fromRow($r['result']);
        }
        if (!$this->client->hasHandle()) {
            $this->session->destroy();                 // expired or unknown at the identity service: the browser session ends too
        }                                              // (a handle that is still valid but not signed in is a pending second factor)
        return $this->current = null;
    }

    public function logout(): void
    {
        if ($this->client->hasHandle()) {
            $this->client->call('logout');
        }
        $this->session->destroy();
        $this->current = null;
        $this->currentLoaded = true;
    }

    public function pendingMfaUser(): ?User
    {
        if (!$this->client->hasHandle()) {
            return null;
        }
        $r = $this->client->call('pendingMfaUser');
        return is_array($r['result'] ?? null) ? User::fromRow($r['result']) : null;
    }

    public function mfaEnrolled(User $user): bool
    {
        return (bool) ($this->client->call('mfaEnrolled')['result'] ?? false);
    }

    public function mfaEnrollmentSecret(): string
    {
        return (string) ($this->client->call('mfaEnrollmentSecret')['result'] ?? '');
    }

    public function mfaUri(User $user): string
    {
        return (string) ($this->client->call('mfaUri')['result'] ?? '');
    }

    public function completeMfa(string $input, bool $recovery = false): ?User
    {
        $r = $this->client->call('completeMfa', [$input, $recovery]);
        if (!is_array($r['result'] ?? null)) {
            return null;
        }
        $this->session->regenerate();
        $this->session->set('csrf', bin2hex(random_bytes(32)));
        return $this->current = User::fromRow($r['result']);
    }

    public function enrollMfa(string $code): ?array
    {
        $r = $this->client->call('enrollMfa', [$code]);
        $res = $r['result'] ?? null;
        if (!is_array($res)) {
            return null;
        }
        $this->session->regenerate();
        $this->session->set('csrf', bin2hex(random_bytes(32)));
        return ['user' => $this->current = User::fromRow($res['user']), 'recovery' => $res['recovery']];
    }

    public function webauthnKeys(User $user): array
    {
        return (array) ($this->client->call('webauthnKeys')['result'] ?? []);
    }

    public function pendingHasKeys(): bool
    {
        return $this->client->hasHandle() && (bool) ($this->client->call('pendingHasKeys')['result'] ?? false);
    }

    public function webauthnBeginLogin(): ?array
    {
        $r = $this->client->call('webauthnBeginLogin')['result'] ?? null;
        return is_array($r) ? $r : null;
    }

    public function webauthnFinishLogin(array $credential): ?User
    {
        $r = $this->client->call('webauthnFinishLogin', [$credential]);
        if (!is_array($r['result'] ?? null)) {
            return null;
        }
        $this->session->regenerate();
        $this->session->set('csrf', bin2hex(random_bytes(32)));
        return $this->current = User::fromRow($r['result']);
    }

    public function webauthnBeginRegister(): ?array
    {
        $r = $this->client->call('webauthnBeginRegister')['result'] ?? null;
        return is_array($r) ? $r : null;
    }

    public function webauthnFinishRegister(array $credential, string $name): bool
    {
        return (bool) ($this->client->call('webauthnFinishRegister', [$credential, $name])['result'] ?? false);
    }

    public function webauthnDelete(int $keyId): bool
    {
        return (bool) ($this->client->call('webauthnDelete', [$keyId])['result'] ?? false);
    }
}
