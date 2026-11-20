<?php
declare(strict_types=1);
// A one-connection fake SMTP server for the mail test. usage: fake_smtp.php <log file>
// Prints the port it listens on, serves one session, writes everything it received to the log file.
$srv = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
echo substr(strrchr((string) stream_socket_get_name($srv, false), ':'), 1), "\n";
fflush(STDOUT);
$c = stream_socket_accept($srv, 15);
$log = '';
$say = static function (string $l) use ($c): void { fwrite($c, $l . "\r\n"); };
$say('220 fake ESMTP');
$inData = false;
while (($line = fgets($c)) !== false) {
    $log .= $line;
    if ($inData) {
        if (rtrim($line) === '.') { $inData = false; $say('250 queued'); }
        continue;
    }
    $cmd = strtoupper(substr($line, 0, 4));
    if ($cmd === 'DATA') { $inData = true; $say('354 go'); continue; }
    if ($cmd === 'QUIT') { $say('221 bye'); break; }
    $say(in_array($cmd, ['EHLO', 'MAIL', 'RCPT'], true) ? ($cmd === 'EHLO' ? '250 fake' : '250 ok') : '500 what');
}
file_put_contents($argv[1], $log);
