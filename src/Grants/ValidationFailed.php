<?php
declare(strict_types=1);

namespace App\Grants;

/** Input that a legitimate user can simply correct. Field name => message. */
final class ValidationFailed extends \RuntimeException
{
    /** @param array<string,string> $errors */
    public function __construct(public readonly array $errors)
    {
        parent::__construct('Please correct the highlighted fields.');
    }
}
