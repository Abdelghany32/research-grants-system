<?php
declare(strict_types=1);
// Prints the demo users as CSV (email, name, department, role, password_hash).
// Input: database/seed_users.tsv and the locally generated demo credentials.
require __DIR__ . '/../src/bootstrap.php';

use App\Auth\Authenticator;

$passwords = [];
foreach (file('/run/grants/demo-credentials.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
    [$email, $password] = explode("\t", $line);
    $passwords[$email] = $password;
}
$rows = array_slice(file(__DIR__ . '/../database/seed_users.tsv', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES), 1);
$out = fopen('php://stdout', 'w');
foreach ($rows as $row) {
    [$email, $name, $department, $role] = explode("\t", $row);
    if (!isset($passwords[$email])) {
        fwrite(STDERR, "no generated password for $email\n");
        exit(1);
    }
    fputcsv($out, [$email, $name, $department, $role, Authenticator::hashPassword($passwords[$email])], ',', '"', '');
}
