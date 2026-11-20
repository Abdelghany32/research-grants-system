<?php
declare(strict_types=1);

namespace App\Mail;

use InvalidArgumentException;

/**
 * Builds one RFC 5322 plain-text message. Every header value is checked: a carriage return or line feed in a
 * name, address or subject would let a value smuggle extra headers (header injection), so it is refused.
 */
final class MailMessage
{
    public static function build(string $from, string $toEmail, string $toName, string $subject, string $body, ?\DateTimeImmutable $now = null): string
    {
        foreach ([$from, $toEmail] as $address) {
            if (!filter_var($address, FILTER_VALIDATE_EMAIL) || preg_match('/[\r\n<>,;"]/', $address)) {
                throw new InvalidArgumentException('Invalid e-mail address.');
            }
        }
        foreach ([$toName, $subject] as $text) {
            if (preg_match('/[\r\n\x00]/', $text)) {
                throw new InvalidArgumentException('Header value contains a line break.');
            }
        }
        $now ??= new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
        $domain = substr(strrchr($from, '@'), 1);
        $headers = [
            'Date: ' . $now->format('D, d M Y H:i:s') . ' +0000',
            'From: Research Grants <' . $from . '>',
            'To: ' . self::encodeName($toName) . ' <' . $toEmail . '>',
            'Subject: ' . self::encodeText($subject),
            'Message-ID: <' . bin2hex(random_bytes(12)) . '@' . $domain . '>',
            'MIME-Version: 1.0',
            'Content-Type: text/plain; charset=UTF-8',
            'Content-Transfer-Encoding: quoted-printable',
            'Auto-Submitted: auto-generated',
        ];
        // Normalise to CRLF BEFORE encoding: quoted_printable_encode() keeps CRLF pairs as real line breaks.
        $body = str_replace("\n", "\r\n", str_replace(["\r\n", "\r"], "\n", $body));
        return implode("\r\n", $headers) . "\r\n\r\n" . quoted_printable_encode($body) . "\r\n";
    }

    private static function encodeText(string $s): string
    {
        return preg_match('/[^\x20-\x7e]/', $s) ? '=?UTF-8?B?' . base64_encode($s) . '?=' : $s;
    }

    private static function encodeName(string $name): string
    {
        $name = trim($name);
        if ($name === '') {
            return '';
        }
        return preg_match('/[^\x20-\x7e]/', $name) ? '=?UTF-8?B?' . base64_encode($name) . '?=' : '"' . str_replace(['\\', '"'], ['\\\\', '\\"'], $name) . '"';
    }
}
