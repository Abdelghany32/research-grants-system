<?php
declare(strict_types=1);

namespace App\Mail;

use RuntimeException;

/**
 * A small SMTP client (RFC 5321): EHLO, optional STARTTLS with certificate verification, AUTH LOGIN, one message.
 * Credentials are sent only over TLS; the plain transport is accepted only for a loopback test server.
 */
final class SmtpMailer implements Mailer
{
    public function __construct(
        private readonly string $host,
        private readonly int $port,
        private readonly string $security,          // 'starttls' | 'tls' (implicit) | 'none' (loopback only)
        private readonly string $from,
        private readonly string $username = '',
        #[\SensitiveParameter] private readonly string $password = '',
        private readonly string $helo = 'research-grants.local',
        private readonly int $timeout = 15,
    ) {
        if (!in_array($security, ['starttls', 'tls', 'none'], true)) {
            throw new RuntimeException('Unknown SMTP security mode.');
        }
        if ($security === 'none' && !in_array($host, ['127.0.0.1', '::1', 'localhost'], true)) {
            throw new RuntimeException('Unencrypted SMTP is allowed only to a loopback server.');
        }
        if ($username !== '' && $security === 'none') {
            throw new RuntimeException('Credentials are never sent without TLS.');
        }
    }

    public function send(string $toEmail, string $toName, string $subject, string $body): void
    {
        $message = MailMessage::build($this->from, $toEmail, $toName, $subject, $body);
        $ctx = stream_context_create(['ssl' => ['verify_peer' => true, 'verify_peer_name' => true, 'peer_name' => $this->host, 'SNI_enabled' => true]]);
        $scheme = $this->security === 'tls' ? 'tls' : 'tcp';
        $sock = @stream_socket_client(sprintf('%s://%s:%d', $scheme, $this->host, $this->port), $errno, $errstr, $this->timeout, STREAM_CLIENT_CONNECT, $ctx);
        if ($sock === false) {
            throw new RuntimeException('SMTP connection failed: ' . $errstr);
        }
        stream_set_timeout($sock, $this->timeout);
        try {
            $this->expect($sock, [220]);
            $this->command($sock, 'EHLO ' . $this->helo, [250]);
            if ($this->security === 'starttls') {
                $this->command($sock, 'STARTTLS', [220]);
                if (!@stream_socket_enable_crypto($sock, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
                    throw new RuntimeException('SMTP STARTTLS failed (certificate not accepted?).');
                }
                $this->command($sock, 'EHLO ' . $this->helo, [250]);
            }
            if ($this->username !== '') {
                $this->command($sock, 'AUTH LOGIN', [334]);
                $this->command($sock, base64_encode($this->username), [334], true);
                $this->command($sock, base64_encode($this->password), [235], true);
            }
            $this->command($sock, 'MAIL FROM:<' . $this->from . '>', [250]);
            $this->command($sock, 'RCPT TO:<' . $toEmail . '>', [250, 251]);
            $this->command($sock, 'DATA', [354]);
            // Dot-stuffing: a line that starts with "." would end the message early.
            $data = preg_replace('/^\./m', '..', $message);
            fwrite($sock, $data . ".\r\n");
            $this->expect($sock, [250]);
            $this->command($sock, 'QUIT', [221]);
        } finally {
            @fclose($sock);
        }
    }

    private function command($sock, string $line, array $ok, bool $secret = false): void
    {
        fwrite($sock, $line . "\r\n");
        $this->expect($sock, $ok, $secret ? '(credentials)' : $line);
    }

    /** @param resource $sock */
    private function expect($sock, array $ok, string $after = ''): void
    {
        $reply = '';
        while (($line = fgets($sock, 1024)) !== false) {
            $reply .= $line;
            if (strlen($line) < 4 || $line[3] === ' ') {      // the last line of a multi-line reply has a space after the code
                break;
            }
        }
        $code = (int) substr($reply, 0, 3);
        if (!in_array($code, $ok, true)) {
            throw new RuntimeException(sprintf('SMTP error %d after %s', $code, $after !== '' ? $after : 'connect'));
        }
    }
}
