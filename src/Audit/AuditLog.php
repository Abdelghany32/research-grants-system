<?php
declare(strict_types=1);

namespace App\Audit;

use App\Auth\User;
use App\Database\Database;
use App\Security\ActorTokenSource;
use PDO;

/**
 * Appends security events through the database function audit_append() - never by writing the table.
 *
 *  - The runtime account has no privilege on audit_events (finding O03). An event that names an actor is accepted
 *    only with a valid actor token for that actor; the role is looked up by the database.
 *  - Events with no authenticated actor (login failures, throttling, CSRF rejections) are written by a separate
 *    account, the audit writer, which may do nothing else; the database flags them actor_verified = false.
 *
 * Details hold metadata (IDs, reasons, amounts) - never proposal text or comments.
 */
final class AuditLog implements AuditWriter
{
    private const CALL = 'SELECT audit_append(?, ?, ?, ?, ?::jsonb, ?::uuid, ?::inet, ?, ?)';

    public function __construct(
        private readonly Database $independent,       // the audit-writer account, autocommit
        private readonly string $correlationId,
        private readonly ?string $ip,
        private readonly ActorTokenSource $tokens,
    ) {
    }

    public function correlationId(): string
    {
        return $this->correlationId;
    }

    public function ip(): ?string
    {
        return $this->ip;
    }

    /**
     * Success event written INSIDE the business transaction: the change and
     * its audit record commit together or not at all.
     */
    public function withChange(PDO $tx, User $actor, string $action, string $type, ?int $id, array $details = []): void
    {
        $tx->prepare(self::CALL)->execute($this->args($actor, true, $action, $type, $id, 'success', $details));
    }

    /**
     * Event written on a separate autocommit connection, by the audit-writer account. Used for denials and
     * authentication outcomes, so the record survives when the business transaction is rolled back.
     *
     * $verified = true when $actor is the authenticated user of this request (a token proves it);
     * false when the actor is only NAMED (an account that failed to sign in).
     */
    public function standalone(?User $actor, string $action, ?string $type, ?int $id, string $outcome, array $details = [], bool $verified = true): void
    {
        $this->independent->pdo()->prepare(self::CALL)->execute($this->args($actor, $verified, $action, $type, $id, $outcome, $details));
    }

    private function args(?User $actor, bool $verified, string $action, ?string $type, ?int $id, string $outcome, array $details): array
    {
        $token = $actor !== null && $verified ? $this->tokens->tokenFor($actor->id, $this->correlationId) : null;
        return [$action, $type, $id, $outcome, json_encode((object) $details, JSON_THROW_ON_ERROR),
                $this->correlationId, $this->ip, $actor?->id, $token];
    }
}
