<?php
declare(strict_types=1);

namespace App\Grants;

/**
 * A request that the rules do not allow (wrong role, not the owner, wrong
 * state, not enough funds). Always rolled back and always audited as "denied".
 */
final class Denied extends \RuntimeException
{
    public function __construct(public readonly string $reason, string $messageForUser)
    {
        parent::__construct($messageForUser);
    }
}
