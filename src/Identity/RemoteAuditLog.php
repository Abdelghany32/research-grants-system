<?php
declare(strict_types=1);

namespace App\Identity;

use App\Audit\AuditWriter;
use App\Auth\User;
use PDO;

/**
 * AuditWriter for the web front end. Events inside a business transaction still go through audit_append() with the
 * actor token (the database proves the actor); everything else is handed to the identity service, which holds the
 * audit-writer credential - the front end has none.
 */
final class RemoteAuditLog implements AuditWriter
{
    public function __construct(
        private readonly IdentityClient $client,
        private readonly string $correlationId,
        private readonly ?string $ip,
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

    public function withChange(PDO $tx, User $actor, string $action, string $type, ?int $id, array $details = []): void
    {
        $tx->prepare('SELECT audit_append(?, ?, ?, ?, ?::jsonb, ?::uuid, ?::inet, ?, ?)')->execute([
            $action, $type, $id, 'success', json_encode((object) $details, JSON_THROW_ON_ERROR), $this->correlationId, $this->ip,
            $actor->id, $this->client->tokenFor($actor->id),
        ]);
    }

    public function standalone(?User $actor, string $action, ?string $type, ?int $id, string $outcome, array $details = [], bool $verified = true): void
    {
        $this->client->call('audit', [$actor?->id, $verified, $action, $type, $id, $outcome, $details]);
    }
}
