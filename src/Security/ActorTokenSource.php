<?php
declare(strict_types=1);

namespace App\Security;

/** Something that can hand out a signed actor token for a user: the key holder itself, or the identity service's reply. */
interface ActorTokenSource
{
    public function tokenFor(int $userId, ?string $nonce = null): string;
}
