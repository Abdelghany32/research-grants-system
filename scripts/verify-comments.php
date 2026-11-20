<?php
declare(strict_types=1);
// Operator check: every stored review comment decrypts with the current keyring,
// read through the real application path (runtime account acting as an officer).
require __DIR__ . '/../src/bootstrap.php';

use App\Security\FieldCipher;

$app = App\App::fromEnvironment();
$officer = $app->db()->pdo()->query("SELECT id FROM users WHERE role = 'officer' AND is_active ORDER BY id LIMIT 1")->fetchColumn();
$rows = $app->db()->asActor((int) $officer, static fn (PDO $tx): array => $tx->query('SELECT id, comments_enc FROM reviews WHERE comments_enc IS NOT NULL ORDER BY id')->fetchAll());
$cipher = $app->cipher();
$byKey = [];
foreach ($rows as $r) {
    $cipher->decrypt($r['comments_enc'], 'reviews.comments:' . $r['id']);       // throws if a key is missing or the value was tampered with
    $id = FieldCipher::keyIdOf($r['comments_enc']) ?? '?';
    $byKey[$id] = ($byKey[$id] ?? 0) + 1;
}
ksort($byKey);
printf("  %d comment(s) decrypt with the keyring (active key %s); by key: %s\n", count($rows), $cipher->activeKeyId(), json_encode($byKey));
