<?php
declare(strict_types=1);

namespace App;

use App\Audit\AuditLog;
use App\Audit\AuditWriter;
use App\Audit\AuditReader;
use App\Auth\AuthService;
use App\Auth\Authenticator;
use App\Auth\Session;
use App\Database\Database;
use App\Grants\GrantQueries;
use App\Grants\GrantWorkflow;
use App\Identity\IdentityClient;
use App\Identity\RemoteAuditLog;
use App\Identity\RemoteAuthenticator;
use App\Mail\FileMailer;
use App\Mail\Mailer;
use App\Mail\Notifier;
use App\Mail\SmtpMailer;
use App\Security\ActorToken;
use App\Security\ActorTokenSource;
use App\Security\FieldCipher;

/**
 * Wires the shared components together. One instance per HTTP request (or per
 * test). Three database connections exist on purpose:
 *   db        - grants_app, business transactions (actor token set per transaction)
 *   auditDb   - grants_audit_write, a different account that can only call audit_append(); its
 *               autocommit connection lets a "denied" event survive the rollback of the business work
 *   auditorDb - grants_auditor, read-only window on the audit timeline
 */
final class App
{
    public readonly string $correlationId;
    public readonly ?string $clientIp;
    private array $services = [];

    public function __construct(public readonly array $config, ?string $clientIp = null)
    {
        $this->correlationId = self::uuid4();
        $this->clientIp = filter_var($clientIp, FILTER_VALIDATE_IP) ?: null;
    }

    public static function fromEnvironment(): self
    {
        return new self(require __DIR__ . '/../config/config.php', $_SERVER['REMOTE_ADDR'] ?? null);
    }

    public function db(): Database
    {
        return $this->services['db'] ??= $this->connect('app_user', 'app_password', true);
    }

    /** The identity service's own account (it alone can read password hashes). Not available to the web front end. */
    public function identityDb(): Database
    {
        $this->requireLocal('identityDb');
        return $this->services['identityDb'] ??= $this->connect('identity_user', 'identity_password', true);
    }

    public function auditDb(): Database
    {
        $this->requireLocal('auditDb');
        return $this->services['auditDb'] ??= $this->connect('audit_writer_user', 'audit_writer_password');
    }

    public function notifierDb(): Database
    {
        return $this->services['notifierDb'] ??= $this->connect('notifier_user', 'notifier_password');
    }

    public function mailer(): Mailer
    {
        $m = $this->config['mail'];
        return $this->services['mailer'] ??= $m['transport'] === 'smtp'
            ? new SmtpMailer($m['smtp_host'], $m['smtp_port'], $m['smtp_security'], $m['from'], $m['smtp_user'], $m['smtp_password'])
            : new FileMailer($this->config['log_dir'] . '/outbox', $m['from']);
    }

    public function notifier(): Notifier
    {
        return $this->services['notifier'] ??= new Notifier($this->notifierDb(), $this->mailer(), $this->config['mail']['public_url']);
    }

    public function auditorDb(): Database
    {
        return $this->services['auditorDb'] ??= $this->connect('auditor_user', 'auditor_password');
    }

    public function audit(): AuditWriter
    {
        return $this->services['audit'] ??= $this->remote()
            ? new RemoteAuditLog($this->identityClient(), $this->correlationId, $this->clientIp)
            : new AuditLog($this->auditDb(), $this->correlationId, $this->clientIp, $this->actorToken());
    }

    public function auditReader(): AuditReader
    {
        return $this->services['auditReader'] ??= new AuditReader($this->auditorDb());
    }

    public function session(): Session
    {
        return $this->services['session'] ??= new Session($this->config['session']);
    }

    public function auth(): AuthService
    {
        return $this->services['auth'] ??= $this->remote()
            ? new RemoteAuthenticator($this->identityClient(), $this->session())
            : new Authenticator($this->identityDb(), $this->audit(), $this->session(), $this->config['auth'], $this->clientIp ?? '0.0.0.0', $this->cipher());
    }

    /** True in the web front end: identity work is delegated to the identity service. */
    public function remote(): bool
    {
        return ($this->config['identity']['mode'] ?? 'local') === 'remote';
    }

    public function identityClient(): IdentityClient
    {
        return $this->services['identityClient'] ??= new IdentityClient(
            $this->config['identity']['url'], $this->config['identity']['api_key'], $this->session(), $this->correlationId, $this->clientIp);
    }

    /** Where actor tokens come from: the key (identity service, tests, operator tools) or the identity service's reply (front end). */
    public function actorTokens(): ActorTokenSource
    {
        return $this->remote() ? $this->identityClient() : $this->actorToken();
    }

    /** The key holder. Not available to the web front end. */
    public function actorToken(): ActorToken
    {
        $this->requireLocal('actorToken');
        return $this->services['actorToken'] ??= ActorToken::fromKeyFile($this->config['actor_key_file']);
    }

    private function requireLocal(string $what): void
    {
        if ($this->remote()) {
            throw new \LogicException("$what is not available to the web front end (it is delegated to the identity service).");
        }
    }

    public function cipher(): FieldCipher
    {
        return $this->services['cipher'] ??= FieldCipher::fromKeyFile($this->config['field_key_file']);
    }

    public function workflow(): GrantWorkflow
    {
        return $this->services['workflow'] ??= new GrantWorkflow($this->db(), $this->audit(), $this->cipher(), $this->config['mail']['public_url']);
    }

    public function queries(): GrantQueries
    {
        return $this->services['queries'] ??= new GrantQueries($this->db(), $this->audit(), $this->cipher());
    }

    public function logError(\Throwable $e): void
    {
        // Full detail goes to a private log; the user only sees the correlation ID.
        $line = sprintf("[%s] %s %s: %s in %s:%d\n", gmdate('c'), $this->correlationId,
            $e::class, $e->getMessage(), $e->getFile(), $e->getLine());
        @file_put_contents($this->config['log_dir'] . '/app-error.log', $line, FILE_APPEND | LOCK_EX);
    }

    private function connect(string $userKey, string $passwordKey, bool $actsForUsers = false): Database
    {
        $c = $this->config['db'];
        $dsn = sprintf('pgsql:host=%s;port=%s;dbname=%s', $c['host'], $c['port'], $c['name']);
        if ($c['sslrootcert'] !== '') {
            // verify-full: encrypt AND check the server certificate matches the host name.
            $dsn .= ';sslmode=verify-full;sslrootcert=' . $c['sslrootcert'];
        }
        return new Database($dsn, $c[$userKey], $c[$passwordKey], $actsForUsers ? $this->actorTokens() : null);
    }

    private static function uuid4(): string
    {
        $b = random_bytes(16);
        $b[6] = chr((ord($b[6]) & 0x0f) | 0x40);
        $b[8] = chr((ord($b[8]) & 0x3f) | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($b), 4));
    }
}
