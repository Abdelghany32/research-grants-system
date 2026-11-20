<?php
declare(strict_types=1);

namespace App\Mail;

interface Mailer
{
    /** @throws \RuntimeException when the message could not be handed over */
    public function send(string $toEmail, string $toName, string $subject, string $body): void;
}
