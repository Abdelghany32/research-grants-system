<?php
declare(strict_types=1);

namespace App\Auth;

use RuntimeException;

/**
 * Thrown when a source address has failed too often. It depends only on the
 * caller's own address - never on which account was named - so it leaks
 * nothing about accounts.
 */
final class LoginThrottled extends RuntimeException
{
    public function __construct(public readonly int $retryAfterSeconds)
    {
        parent::__construct('Too many failed sign-in attempts from this address.');
    }
}
