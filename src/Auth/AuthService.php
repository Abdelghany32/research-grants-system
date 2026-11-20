<?php
declare(strict_types=1);

namespace App\Auth;

/**
 * What the web front end needs from authentication. Authenticator implements it in-process (the identity service,
 * the tests and the operator tools); RemoteAuthenticator implements it by calling the identity service, so the
 * front end process never sees a password hash, the actor key or the audit-writer credential.
 */
interface AuthService
{
    /** @throws LoginThrottled */
    public function login(string $email, #[\SensitiveParameter] string $password): User|MfaChallenge|null;

    public function currentUser(): ?User;

    public function logout(): void;

    public function pendingMfaUser(): ?User;

    public function mfaEnrolled(User $user): bool;

    public function mfaEnrollmentSecret(): string;

    public function mfaUri(User $user): string;

    /** @throws LoginThrottled */
    public function completeMfa(string $input, bool $recovery = false): ?User;

    /** @return array{user:User, recovery:list<string>}|null @throws LoginThrottled */
    public function enrollMfa(string $code): ?array;

    public function pendingHasKeys(): bool;

    /** Security keys (WebAuthn). Names only - never key material - leave the identity service. */
    public function webauthnKeys(User $user): array;

    /** @throws LoginThrottled */
    public function webauthnBeginLogin(): ?array;

    /** @throws LoginThrottled */
    public function webauthnFinishLogin(array $credential): ?User;

    public function webauthnBeginRegister(): ?array;

    public function webauthnFinishRegister(array $credential, string $name): bool;

    public function webauthnDelete(int $keyId): bool;
}
