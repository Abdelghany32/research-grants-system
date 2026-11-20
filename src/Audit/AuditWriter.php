<?php
declare(strict_types=1);

namespace App\Audit;

use App\Auth\User;
use PDO;

/** How the application records audit events (in-process through audit_append, or through the identity service). */
interface AuditWriter
{
    public function correlationId(): string;

    public function ip(): ?string;

    /** Success event written INSIDE the business transaction. */
    public function withChange(PDO $tx, User $actor, string $action, string $type, ?int $id, array $details = []): void;

    /** Event written outside the business transaction (denials, authentication outcomes). */
    public function standalone(?User $actor, string $action, ?string $type, ?int $id, string $outcome, array $details = [], bool $verified = true): void;
}
