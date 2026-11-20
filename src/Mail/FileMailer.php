<?php
declare(strict_types=1);

namespace App\Mail;

use RuntimeException;

/** Writes each message as an .eml file (the default transport of the lab: nothing leaves the machine). */
final class FileMailer implements Mailer
{
    public function __construct(private readonly string $directory, private readonly string $from)
    {
    }

    public function send(string $toEmail, string $toName, string $subject, string $body): void
    {
        $message = MailMessage::build($this->from, $toEmail, $toName, $subject, $body);
        if (!is_dir($this->directory) && !@mkdir($this->directory, 0750, true) && !is_dir($this->directory)) {
            throw new RuntimeException('The outbox directory cannot be created.');
        }
        $file = sprintf('%s/%s-%s.eml', $this->directory, gmdate('Ymd-His'), bin2hex(random_bytes(4)));
        if (@file_put_contents($file, $message, LOCK_EX) === false) {
            throw new RuntimeException('The message could not be written to the outbox.');
        }
        @chmod($file, 0640);
    }
}
