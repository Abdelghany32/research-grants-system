<?php
declare(strict_types=1);

namespace App\Identity;

use App\App;
use App\Audit\AuditLog;
use App\Auth\ArraySessionStore;
use App\Auth\Authenticator;
use App\Auth\LoginThrottled;
use App\Auth\MfaChallenge;
use App\Auth\User;
use Throwable;

/**
 * The identity service: the ONLY process that holds the actor key, the audit-writer credential and the database account
 * that can read password hashes. The web front end calls it over the internal network (HMAC-signed requests) to sign
 * users in, to learn who a session belongs to, and to receive a short-lived actor token for that user.
 *
 * It wraps the same Authenticator the tests exercise, with a database-backed session store. A front end can obtain a
 * token only for a user with a LIVE session whose opaque handle it holds - not for an arbitrary user id.
 */
final class IdentityService
{
    /** Methods the front end may call (anything else is refused). */
    private const METHODS = ['login', 'currentUser', 'logout', 'pendingMfaUser', 'mfaEnrolled', 'mfaEnrollmentSecret', 'mfaUri',
                             'completeMfa', 'enrollMfa', 'audit', 'webauthnKeys', 'webauthnBeginLogin', 'webauthnFinishLogin',
                             'webauthnBeginRegister', 'webauthnFinishRegister', 'webauthnDelete', 'pendingHasKeys'];

    public static function handle(App $app): void
    {
        $path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
        if ($path === '/health') {
            header('Content-Type: text/plain');
            echo 'ok';
            return;
        }
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST' || $path !== '/v1/call') {
            self::reply(404, ['ok' => false, 'error' => 'not_found']);
            return;
        }
        $body = (string) file_get_contents('php://input', false, null, 0, 65537);
        if (strlen($body) > 65536 || !self::signatureValid($app->config['identity']['api_key'], $body)) {
            self::reply(401, ['ok' => false, 'error' => 'unauthorized']);
            return;
        }
        try {
            $req = json_decode($body, true, 16, JSON_THROW_ON_ERROR);
        } catch (Throwable) {
            self::reply(400, ['ok' => false, 'error' => 'bad_request']);
            return;
        }
        $method = $req['method'] ?? null;
        $args = $req['args'] ?? [];
        if (!is_string($method) || !in_array($method, self::METHODS, true) || !is_array($args)) {
            self::reply(400, ['ok' => false, 'error' => 'bad_method']);
            return;
        }
        $handle = $req['handle'] ?? null;
        $ip = is_string($req['ip'] ?? null) ? (filter_var($req['ip'], FILTER_VALIDATE_IP) ?: '0.0.0.0') : '0.0.0.0';
        $correlation = is_string($req['correlation'] ?? null) && preg_match('/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/', $req['correlation'])
            ? $req['correlation'] : $app->correlationId;

        try {
            $sessions = new IdentitySessions($app->identityDb(), $app->cipher());
            $store = new ArraySessionStore($sessions->load(is_string($handle) ? $handle : null), $app->config['session']);
            $audit = new AuditLog($app->auditDb(), $correlation, $ip, $app->actorToken());
            $auth = new Authenticator($app->identityDb(), $audit, $store, $app->config['auth'], $ip, $app->cipher());

            try {
                $result = self::dispatch($app, $auth, $audit, $method, $args);
            } catch (LoginThrottled $e) {
                $sessions->persist(is_string($handle) ? $handle : null, $store);
                self::reply(200, ['ok' => false, 'error' => 'throttled', 'retry_after' => $e->retryAfterSeconds, 'handle' => is_string($handle) ? $handle : null]);
                return;
            }
            $newHandle = $sessions->persist(is_string($handle) ? $handle : null, $store);
            $user = $store->destroyed ? null : $auth->authenticatedUser();
            self::reply(200, [
                'ok' => true, 'result' => $result, 'handle' => $newHandle,
                'user' => $user === null ? null : self::userArray($user),
                'token' => $user === null ? null : $app->actorToken()->mint($user->id, $correlation),
            ]);
        } catch (Throwable $e) {
            $app->logError($e);
            self::reply(500, ['ok' => false, 'error' => 'internal']);
        }
    }

    private static function dispatch(App $app, Authenticator $auth, AuditLog $audit, string $method, array $a): mixed
    {
        return match ($method) {
            'login' => self::loginResult($auth->login((string) ($a[0] ?? ''), (string) ($a[1] ?? ''))),
            'currentUser' => ($u = $auth->currentUser()) === null ? null : self::userArray($u),
            'logout' => $auth->logout(),
            'pendingMfaUser' => ($u = $auth->pendingMfaUser()) === null ? null : self::userArray($u),
            // These two concern only the sign-in pending in THIS session, never an arbitrary user id.
            'mfaEnrolled' => ($u = $auth->pendingMfaUser()) !== null && $auth->mfaEnrolled($u),
            'mfaEnrollmentSecret' => $auth->mfaEnrollmentSecret(),
            'mfaUri' => ($u = $auth->pendingMfaUser()) === null ? '' : $auth->mfaUri($u),
            'completeMfa' => ($u = $auth->completeMfa((string) ($a[0] ?? ''), (bool) ($a[1] ?? false))) === null ? null : self::userArray($u),
            'enrollMfa' => self::enrollResult($auth->enrollMfa((string) ($a[0] ?? ''))),
            'audit' => self::audit($app, $auth, $audit, $a),
            // Security keys: only for the sign-in pending in, or the user signed in to, THIS session.
            'webauthnKeys' => ($u = $auth->currentUser()) === null ? [] : $auth->webauthnKeys($u),
            'pendingHasKeys' => ($u = $auth->pendingMfaUser()) !== null && $auth->webauthnKeys($u) !== [],
            'webauthnBeginLogin' => $auth->webauthnBeginLogin(),
            'webauthnFinishLogin' => ($u = $auth->webauthnFinishLogin(is_array($a[0] ?? null) ? $a[0] : [])) === null ? null : self::userArray($u),
            'webauthnBeginRegister' => $auth->webauthnBeginRegister(),
            'webauthnFinishRegister' => $auth->webauthnFinishRegister(is_array($a[0] ?? null) ? $a[0] : [], (string) ($a[1] ?? '')),
            'webauthnDelete' => $auth->webauthnDelete((int) ($a[0] ?? 0)),
        };
    }

    private static function audit(App $app, Authenticator $auth, AuditLog $audit, array $a): bool
    {
        [$claimed, $verified, $action, $type, $id, $outcome, $details] = array_pad($a, 7, null);
        if (!is_string($action) || !preg_match('/^[a-z_]+\.[a-z_]+$/', $action) || !in_array($outcome, ['success', 'denied', 'failure'], true)) {
            return false;
        }
        $actor = null;
        $proved = false;
        if (is_int($claimed)) {
            $session = $auth->currentUser();
            if ($verified === true && $session !== null && $session->id === $claimed) {
                $actor = $session;                        // the live session of that very user proves the identity
                $proved = true;
            } else {
                $actor = self::userById($app, $claimed);  // only NAMED: written unverified
            }
        }
        $audit->standalone($actor, $action, is_string($type) ? $type : null, is_int($id) ? $id : null, $outcome,
            is_array($details) ? $details : [], verified: $proved);
        return true;
    }

    private static function enrollResult(?array $d): ?array
    {
        return $d === null ? null : ['user' => self::userArray($d['user']), 'recovery' => $d['recovery']];
    }

    private static function loginResult(User|MfaChallenge|null $r): array
    {
        return match (true) {
            $r === null => ['kind' => 'none'],
            $r instanceof MfaChallenge => ['kind' => 'mfa', 'user' => self::userArray($r->user), 'enrolled' => $r->enrolled],
            default => ['kind' => 'user', 'user' => self::userArray($r)],
        };
    }

    public static function userArray(User $u): array
    {
        return ['id' => $u->id, 'email' => $u->email, 'full_name' => $u->fullName, 'department' => $u->department, 'role' => $u->role];
    }

    private static function userById(App $app, int $id): ?User
    {
        $s = $app->identityDb()->pdo()->prepare('SELECT id, email, full_name, department, role FROM users WHERE id = ?');
        $s->execute([$id]);
        $row = $s->fetch();
        return $row ? User::fromRow($row) : null;
    }

    private static function signatureValid(string $keyHex, string $body): bool
    {
        $time = $_SERVER['HTTP_X_TIME'] ?? '';
        $sig = $_SERVER['HTTP_X_SIGNATURE'] ?? '';
        if (!preg_match('/^[0-9a-f]{64}$/', $keyHex) || !ctype_digit($time) || abs(time() - (int) $time) > 30 || !preg_match('/^[0-9a-f]{64}$/', $sig)) {
            return false;
        }
        return hash_equals(hash_hmac('sha256', $time . "\n" . $body, (string) hex2bin($keyHex)), $sig);
    }

    private static function reply(int $status, array $body): void
    {
        http_response_code($status);
        header('Content-Type: application/json');
        header('Cache-Control: no-store');
        echo json_encode($body, JSON_THROW_ON_ERROR);
    }
}
