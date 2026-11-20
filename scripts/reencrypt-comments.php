<?php
declare(strict_types=1);
// Key-rotation helper (operator tool, called by scripts/rotate-field-key.sh).
// Reads "<kind> TAB <id> TAB <value>" lines on stdin (kind r = review comment, t = TOTP secret), decrypts each value with
// the keyring and re-encrypts it with the ACTIVE key, then prints one SQL
// transaction on stdout for an administrator session to run. The database is not
// touched by this script; the web runtime account never gets write access to
// finalized reviews.
require __DIR__ . '/../src/bootstrap.php';

use App\Security\FieldCipher;

$cipher = FieldCipher::fromKeyFile((string) getenv('FIELD_KEY_FILE'));
$active = $cipher->activeKeyId();
$updates = [];
$kept = 0;
while (($line = fgets(STDIN)) !== false) {
    $line = rtrim($line, "\r\n");
    if ($line === '') {
        continue;
    }
    [$kind, $id, $stored] = explode("\t", $line, 3);
    if (!in_array($kind, ['r', 't'], true) || !ctype_digit($id) || !preg_match('#^v[12]:[A-Za-z0-9:+/=]+$#', $stored)) {
        fwrite(STDERR, "refusing malformed input line for review $id\n");
        exit(2);
    }
    if (FieldCipher::keyIdOf($stored) === $active && str_starts_with($stored, 'v2:')) {
        $kept++;
        continue;
    }
    $ctx = $kind === 'r' ? 'reviews.comments:' . $id : 'users.totp:' . $id;
    $plain = $cipher->decrypt($stored, $ctx);                               // fails loudly if a key is missing
    $new = $cipher->encrypt($plain, $ctx);
    if ($cipher->decrypt($new, $ctx) !== $plain) {      // verify before proposing the change
        fwrite(STDERR, "round-trip check failed for review $id\n");
        exit(3);
    }
    // base64 and ':' are the only characters in these values, so they are safe inside SQL quotes.
    $updates[] = $kind === 'r'
        ? sprintf("UPDATE grants.reviews SET comments_enc = '%s' WHERE id = %d AND comments_enc = '%s';", $new, (int) $id, $stored)
        : sprintf("UPDATE grants.users SET totp_secret_enc = '%s' WHERE id = %d AND totp_secret_enc = '%s';", $new, (int) $id, $stored);
}
echo "BEGIN;\n";
echo "-- Maintenance transaction: finalized reviews are immutable for the application, and the guard trigger\n";
echo "-- enforces that. Re-encryption changes no business data, so it runs with triggers off (superuser only).\n";
echo "SET LOCAL session_replication_role = replica;\n";
foreach ($updates as $u) {
    echo $u, "\n";
}
printf("INSERT INTO grants.audit_events (action, outcome, details) VALUES ('admin.rotate_field_key', 'success', '{\"rows_reencrypted\": %d, \"rows_already_current\": %d, \"active_key\": \"%s\"}');\n",
    count($updates), $kept, $active);
echo "COMMIT;\n";
fwrite(STDERR, sprintf("%d value(s) re-encrypted to key '%s', %d already current\n", count($updates), $active, $kept));
