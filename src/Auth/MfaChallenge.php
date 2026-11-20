<?php
declare(strict_types=1);

namespace App\Auth;

/** The password was right, but a second factor is still needed (or must first be enrolled). The user is NOT signed in yet. */
final class MfaChallenge
{
    public function __construct(public readonly User $user, public readonly bool $enrolled)
    {
    }
}
