<?php
declare(strict_types=1);

namespace App\Auth;

/** The authenticated person, as loaded from the users table for this request. */
final class User
{
    public function __construct(
        public readonly int $id,
        public readonly string $email,
        public readonly string $fullName,
        public readonly string $department,
        public readonly string $role,
    ) {
    }

    public static function fromRow(array $r): self
    {
        return new self((int) $r['id'], $r['email'], $r['full_name'], $r['department'], $r['role']);
    }
}
