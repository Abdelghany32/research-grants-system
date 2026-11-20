<?php
declare(strict_types=1);

namespace App\Auth;

/**
 * Human-role permission matrix (application layer). Every route names the
 * permission it needs and every workflow operation checks it again.
 * PostgreSQL row-level security enforces the same boundaries independently.
 */
final class Policy
{
    public const PERMISSIONS = [
        'researcher' => ['call.read', 'proposal.read_own', 'proposal.write_own_draft', 'proposal.submit'],
        'reviewer'   => ['review.read_assigned', 'review.write_assigned'],
        'officer'    => ['call.read', 'call.manage', 'proposal.read_submitted', 'review.assign', 'decision.record', 'account.security'],
        'auditor'    => ['audit.read', 'account.security'],
    ];

    public const HOME = [
        'researcher' => '/proposals',
        'reviewer'   => '/reviews',
        'officer'    => '/officer',
        'auditor'    => '/audit',
    ];

    public static function can(User $user, string $permission): bool
    {
        return in_array($permission, self::PERMISSIONS[$user->role] ?? [], true);
    }
}
