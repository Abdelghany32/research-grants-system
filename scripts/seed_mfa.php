<?php
declare(strict_types=1);
// Enrols the demo officers and auditor in two-step sign-in, through the same database function the sign-in screen uses.
// The shared secrets are the same in every database (live, test, restore) and are written to secrets/demo-totp.txt by
// scripts/seed.sh: one line per account, "e-mail TAB base32 secret TAB recovery codes (comma separated)".
// Fictional lab accounts only. In real life each person enrols their own phone at first sign-in.
require __DIR__ . '/../src/bootstrap.php';

use App\App;
use App\Auth\Totp;

$app = new App(require __DIR__ . '/../config/config.php');
$required = $app->config['auth']['mfa']['required_roles'];
$existing = [];
$file = '/run/grants/demo-totp.txt';
if (is_readable($file)) {
    foreach (file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $p = explode("\t", $line);
        if (count($p) >= 3) {
            $existing[$p[0]] = [$p[1], $p[2]];
        }
    }
}
$users = $app->identityDb()->pdo()->query('SELECT id, email FROM users WHERE is_active ORDER BY id')->fetchAll();
$roles = $app->identityDb()->pdo()->query('SELECT id, role FROM users')->fetchAll(PDO::FETCH_KEY_PAIR);
$out = $existing;
foreach ($users as $u) {
    if (!in_array($roles[$u['id']], $required, true)) {
        continue;
    }
    [$secret, $codesCsv] = $existing[$u['email']] ?? [Totp::generateSecret(), implode(',', Totp::recoveryCodes())];
    $out[$u['email']] = [$secret, $codesCsv];
    $enrolled = $app->identityDb()->asActor((int) $u['id'], static function (PDO $tx) use ($u): bool {
        $s = $tx->prepare('SELECT enrolled FROM mfa_state(?)');
        $s->execute([$u['id']]);
        return (bool) $s->fetchColumn();
    });
    if ($enrolled) {
        continue;
    }
    $hashes = array_map(static fn (string $c): string => password_hash($c, PASSWORD_ARGON2ID), explode(',', $codesCsv));
    $literal = '{' . implode(',', array_map(static fn (string $h): string => '"' . $h . '"', $hashes)) . '}';
    $enc = $app->cipher()->encrypt($secret, 'users.totp:' . $u['id']);
    $app->identityDb()->asActor((int) $u['id'], static function (PDO $tx) use ($u, $enc, $literal): void {
        $tx->prepare('SELECT mfa_enroll(?, ?, ?::text[])')->execute([$u['id'], $enc, $literal]);
    });
    fwrite(STDERR, "enrolled {$u['email']}\n");
}
foreach ($out as $email => [$secret, $codes]) {
    echo $email, "\t", $secret, "\t", $codes, "\n";
}
