<?php
declare(strict_types=1);

namespace App\Auth;

use App\Audit\AuditWriter;
use App\Database\Database;
use App\Security\FieldCipher;
use PDO;

final class Authenticator implements AuthService
{
    use WebAuthnFlow;

    // Verified when the e-mail is unknown, so "no such account" costs the same
    // time as "wrong password" and accounts cannot be enumerated by timing.
    private const DUMMY_HASH = '$argon2id$v=19$m=65536,t=4,p=1$UVBhSVIveGljZ2o3V0hNSQ$aq6nS5YTvt8Cnrsvm8ZB0TIEOPgvc4QDxzPlqFCW590';

    private ?User $current = null;

    public function __construct(
        private readonly Database $db,
        private readonly AuditWriter $audit,
        private readonly SessionStore $session,
        private readonly array $config,
        private readonly string $ip = '0.0.0.0',
        private readonly ?FieldCipher $cipher = null,
    ) {
    }

    public static function hashPassword(#[\SensitiveParameter] string $password): string
    {
        // Argon2id: salted, deliberately slow and memory-hard. One-way - the
        // application can verify a password but can never recover it.
        return password_hash($password, PASSWORD_ARGON2ID);
    }

    /**
     * Returns the user on success, null on any failure (the caller shows one
     * generic message). Throws LoginThrottled when this source address has
     * failed too often.
     *
     * Every failure that reaches the password stage costs one Argon2id
     * verification - real hash or dummy - so unknown, disabled, locked and
     * wrong-password answers take the same time (finding F03). Only a
     * throttled SOURCE is refused early, and that depends on the caller's own
     * address, not on the account asked about.
     */
    public function login(string $email, #[\SensitiveParameter] string $password): User|MfaChallenge|null
    {
        $pdo = $this->db->pdo();
        $email = strtolower(trim($email));

        // 1. Per-source throttle (finding F04): cheap refusal, no hashing.
        if ($this->gate(null) === 'ip_throttled') {
            throw new LoginThrottled($this->config['ip_window_minutes'] * 60);
        }

        // The runtime account cannot SELECT password_hash; this SECURITY DEFINER
        // function returns the single row for one e-mail address.
        $stmt = $pdo->prepare('SELECT * FROM auth_find_credentials(?)');
        $stmt->execute([$email]);
        $cred = $stmt->fetch();

        if ($cred === false) {
            password_verify($password, self::DUMMY_HASH);
            $this->fail(null, null, 'unknown_account');
            return null;
        }
        $user = $this->loadUser((int) $cred['id'], activeOnly: false);

        if (!$cred['is_active']) {
            password_verify($password, self::DUMMY_HASH);
            $this->fail($user, $user->id, 'account_disabled');
            return null;
        }
        // Administrative lock (set by an operator during an incident; the application only reads it).
        if ($cred['locked_until'] !== null && strtotime($cred['locked_until']) > time()) {
            password_verify($password, self::DUMMY_HASH);
            $this->fail($user, $user->id, 'account_locked', ['scope' => 'administrative']);
            return null;
        }
        // Per-(account, address) lock (finding F02): the account's real owner,
        // signing in from elsewhere, is not affected by a stranger's guesses.
        if ($this->gate($user->id) === 'pair_locked') {
            password_verify($password, self::DUMMY_HASH);
            $this->fail($user, $user->id, 'account_locked', ['scope' => 'account_and_address']);
            return null;
        }

        if (!password_verify($password, $cred['password_hash'])) {
            $this->fail($user, $user->id, 'bad_password');
            return null;
        }

        // Second factor: officers and auditors (and anyone who enrolled) are not signed in until the code is right.
        $state = $this->mfaState($user);
        if ($state['enrolled'] || in_array($user->role, $this->config['mfa']['required_roles'], true)) {
            $this->session->regenerate();
            $this->session->set('mfa_pending', ['user_id' => $user->id, 'at' => time(), 'attempts' => 0]);
            $this->session->set('csrf', bin2hex(random_bytes(32)));
            return new MfaChallenge($user, $state['enrolled']);
        }
        return $this->finishLogin($user, 'password');
    }

    /** The password (and, when required, the second factor) are both right: open the session. */
    private function finishLogin(User $user, string $method): User
    {
        $pdo = $this->db->pdo();
        $pdo->prepare('SELECT auth_clear_failures(?, ?::inet)')->execute([$user->id, $this->ip]);
        $pdo->prepare('UPDATE users SET last_login_at = now() WHERE id = ?')->execute([$user->id]);

        $this->session->regenerate();
        $this->session->pull('mfa_pending');
        $this->session->pull('mfa_new_secret');
        $this->session->set('user_id', $user->id);
        $this->session->set('login_at', time());
        $this->session->set('seen_at', time());
        $this->session->set('csrf', bin2hex(random_bytes(32)));   // fresh token for the authenticated session
        $this->audit->standalone($user, 'auth.login', 'user', $user->id, 'success', ['method' => $method]);
        return $this->current = $user;
    }

    // ------------------------------------------------------------------- second factor

    /** @return array{enrolled:bool, secret_enc:?string, last_step:int} */
    private function mfaState(User $user): array
    {
        $row = $this->db->asActor($user->id, static function (PDO $tx) use ($user): array {
            $s = $tx->prepare('SELECT enrolled, secret_enc, last_step FROM mfa_state(?)');
            $s->execute([$user->id]);
            return $s->fetch();
        });
        return ['enrolled' => (bool) $row['enrolled'], 'secret_enc' => $row['secret_enc'], 'last_step' => (int) $row['last_step']];
    }

    /** The user who passed the password step and now owes a code, or null (none, expired, or too many wrong codes). */
    public function pendingMfaUser(): ?User
    {
        $p = $this->session->get('mfa_pending');
        if (!is_array($p) || time() - (int) $p['at'] > $this->config['mfa']['pending_seconds']) {
            $this->session->pull('mfa_pending');
            return null;
        }
        return $this->loadUser((int) $p['user_id'], activeOnly: true);
    }

    public function mfaEnrolled(User $user): bool
    {
        return $this->mfaState($user)['enrolled'];
    }

    /** The secret shown during enrolment: generated once per pending sign-in, kept only in the server-side session. */
    public function mfaEnrollmentSecret(): string
    {
        $secret = $this->session->get('mfa_new_secret');
        if (!is_string($secret)) {
            $secret = Totp::generateSecret();
            $this->session->set('mfa_new_secret', $secret);
        }
        return $secret;
    }

    public function mfaUri(User $user): string
    {
        return Totp::uri($this->mfaEnrollmentSecret(), $user->email, $this->config['mfa']['issuer']);
    }

    /** A wrong code counts like a wrong password: the same pair lock and address throttle apply, plus a per-sign-in cap. */
    private function mfaFail(User $user, string $reason): null
    {
        $p = $this->session->get('mfa_pending');
        if (is_array($p)) {
            $p['attempts'] = (int) $p['attempts'] + 1;
            $this->session->set('mfa_pending', $p);
            if ($p['attempts'] >= $this->config['mfa']['max_attempts']) {
                $this->session->pull('mfa_pending');       // start again from the password
            }
        }
        $this->fail($user, $user->id, $reason);
        return null;
    }

    /** @throws LoginThrottled */
    private function mfaGate(User $user): bool
    {
        if ($this->gate(null) === 'ip_throttled') {
            throw new LoginThrottled($this->config['ip_window_minutes'] * 60);
        }
        if ($this->gate($user->id) === 'pair_locked') {
            $this->fail($user, $user->id, 'account_locked', ['scope' => 'account_and_address']);
            return false;
        }
        return true;
    }

    /** Verify a TOTP code or a recovery code for an enrolled user. */
    public function completeMfa(string $input, bool $recovery = false): ?User
    {
        $user = $this->pendingMfaUser();
        if ($user === null) {
            return null;
        }
        if (!$this->mfaGate($user)) {
            return null;
        }
        $state = $this->mfaState($user);
        if (!$state['enrolled'] || $state['secret_enc'] === null || $this->cipher === null) {
            return $this->mfaFail($user, 'bad_mfa');
        }
        if ($recovery) {
            $codes = $this->db->asActor($user->id, static function (PDO $tx) use ($user): array {
                $s = $tx->prepare('SELECT id, code_hash FROM mfa_recovery_hashes(?)');
                $s->execute([$user->id]);
                return $s->fetchAll();
            });
            $given = strtolower(preg_replace('/\s+/', '', $input) ?? '');
            foreach ($codes as $c) {
                if (password_verify($given, $c['code_hash'])) {
                    $used = $this->db->asActor($user->id, static function (PDO $tx) use ($user, $c): bool {
                        $s = $tx->prepare('SELECT mfa_consume_recovery(?, ?)');
                        $s->execute([$user->id, $c['id']]);
                        return (bool) $s->fetchColumn();
                    });
                    if ($used) {
                        $this->audit->standalone($user, 'auth.mfa_recovery_used', 'user', $user->id, 'success',
                            ['remaining' => count($codes) - 1]);
                        return $this->finishLogin($user, 'recovery_code');
                    }
                }
            }
            return $this->mfaFail($user, 'bad_mfa');
        }
        $secret = $this->cipher->decrypt($state['secret_enc'], 'users.totp:' . $user->id);
        $step = Totp::matchStep($secret, $input, $this->config['mfa']['window']);
        if ($step === null) {
            return $this->mfaFail($user, 'bad_mfa');
        }
        if ($this->config['mfa']['replay_protection'] && !$this->acceptStep($user, $step)) {
            return $this->mfaFail($user, 'mfa_replay');
        }
        return $this->finishLogin($user, 'totp');
    }

    /**
     * First sign-in of an officer or auditor: prove that the authenticator app works by entering a code, then the
     * secret is stored encrypted and eight recovery codes are issued (shown once).
     *
     * @return array{user:User, recovery:list<string>}|null
     */
    public function enrollMfa(string $code): ?array
    {
        $user = $this->pendingMfaUser();
        $secret = $this->session->get('mfa_new_secret');
        if ($user === null || !is_string($secret) || $this->cipher === null) {
            return null;
        }
        if (!$this->mfaGate($user)) {
            return null;
        }
        $step = Totp::matchStep($secret, $code, $this->config['mfa']['window']);
        if ($step === null) {
            $this->mfaFail($user, 'bad_mfa');
            return null;
        }
        $recovery = Totp::recoveryCodes();
        $hashes = array_map(static fn (string $c): string => password_hash($c, PASSWORD_ARGON2ID), $recovery);
        $literal = '{' . implode(',', array_map(static fn (string $h): string => '"' . str_replace(['\\', '"'], ['\\\\', '\\"'], $h) . '"', $hashes)) . '}';
        $encrypted = $this->cipher->encrypt($secret, 'users.totp:' . $user->id);
        $this->db->asActor($user->id, static function (PDO $tx) use ($user, $encrypted, $literal): void {
            $tx->prepare('SELECT mfa_enroll(?, ?, ?::text[])')->execute([$user->id, $encrypted, $literal]);
        });
        $this->acceptStep($user, $step);
        $this->audit->standalone($user, 'auth.mfa_enrolled', 'user', $user->id, 'success', ['recovery_codes' => count($recovery)]);
        return ['user' => $this->finishLogin($user, 'enrollment'), 'recovery' => $recovery];
    }

    private function acceptStep(User $user, int $step): bool
    {
        return (bool) $this->db->asActor($user->id, static function (PDO $tx) use ($user, $step): bool {
            $s = $tx->prepare('SELECT mfa_accept_step(?, ?)');
            $s->execute([$user->id, $step]);
            return (bool) $s->fetchColumn();
        });
    }

    /** NULL = allowed; otherwise 'ip_throttled' or 'pair_locked'. */
    private function gate(?int $userId): ?string
    {
        $c = $this->config;
        $stmt = $this->db->pdo()->prepare('SELECT auth_login_gate(?, ?::inet, ?, ?, ?, ?)');
        $stmt->execute([$userId, $this->ip, $c['pair_max_failures'], $c['pair_window_minutes'], $c['ip_max_failures'], $c['ip_window_minutes']]);
        $reason = $stmt->fetchColumn();
        return is_string($reason) ? $reason : null;
    }

    /**
     * Count the failure, write its audit event, and write the threshold events
     * (lockout, throttle, suspicious volume) exactly once - when the counter
     * crosses the limit - so an attacker cannot flood the audit trail.
     */
    private function fail(?User $user, ?int $userId, string $reason, array $extra = []): void
    {
        $c = $this->config;
        $stmt = $this->db->pdo()->prepare('SELECT * FROM auth_record_failure(?, ?::inet, ?, ?)');
        $stmt->execute([$userId, $this->ip, $c['pair_window_minutes'], $c['ip_window_minutes']]);
        $n = $stmt->fetch();

        // The actor is only NAMED here (the sign-in failed), so these events are written unverified.
        $this->audit->standalone($user, 'auth.login', 'user', $userId, 'denied', ['reason' => $reason] + $extra, verified: false);
        if ($reason === 'bad_password' && (int) $n['pair_failures'] === $c['pair_max_failures']) {
            $this->audit->standalone($user, 'auth.lockout', 'user', $userId, 'success',
                ['minutes' => $c['pair_window_minutes'], 'scope' => 'account_and_address'], verified: false);
        }
        if ((int) $n['ip_failures'] === $c['ip_max_failures']) {
            $this->audit->standalone(null, 'auth.throttle', null, null, 'success',
                ['minutes' => $c['ip_window_minutes'], 'failures' => (int) $n['ip_failures']], verified: false);
        }
        if ($userId !== null && (int) $n['account_failures'] === $c['alert_account_failures']) {
            $this->audit->standalone($user, 'auth.suspicious_volume', 'user', $userId, 'denied',
                ['failures_last_hour' => (int) $n['account_failures'], 'note' => 'many addresses may be guessing this account'], verified: false);
        }
    }

    /** The user signed in by this call, with no side effects (the identity service reads it after a login step). */
    public function authenticatedUser(): ?User
    {
        return $this->current;
    }

    /** The signed-in user for this request, or null. Enforces both session timeouts. */
    public function currentUser(): ?User
    {
        if ($this->current !== null) {
            return $this->current;
        }
        $id = $this->session->get('user_id');
        if (!is_int($id)) {
            return null;
        }
        $now = time();
        $idle = $now - (int) $this->session->get('seen_at', 0);
        $age = $now - (int) $this->session->get('login_at', 0);
        // The user row is re-read on every request: a disabled account or a
        // changed role takes effect immediately, not at next login.
        $user = $this->loadUser($id, activeOnly: true);
        if ($user === null || $idle > $this->session->idleSeconds() || $age > $this->session->absoluteSeconds()) {
            if ($user !== null) {
                $this->audit->standalone($user, 'auth.session_expired', 'user', $user->id, 'success',
                    ['reason' => $idle > $this->session->idleSeconds() ? 'idle' : 'absolute'], verified: false);
            }
            $this->session->destroy();
            return null;
        }
        $this->session->set('seen_at', $now);
        return $this->current = $user;
    }

    public function logout(): void
    {
        $user = $this->currentUser();
        if ($user !== null) {
            $this->audit->standalone($user, 'auth.logout', 'user', $user->id, 'success');
        }
        $this->session->destroy();
        $this->current = null;
    }

    private function loadUser(int $id, bool $activeOnly): ?User
    {
        $stmt = $this->db->pdo()->prepare(
            'SELECT id, email, full_name, department, role FROM users WHERE id = ? AND (is_active OR NOT ?::boolean)'
        );
        $stmt->execute([$id, $activeOnly ? 'true' : 'false']);
        $row = $stmt->fetch();
        return $row ? User::fromRow($row) : null;
    }
}
