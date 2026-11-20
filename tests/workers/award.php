<?php
declare(strict_types=1);
// One officer "click" in its own process and its own database connection.
// usage: award.php <proposalId> <amount> <unix start time>
require __DIR__ . '/../../src/bootstrap.php';
require __DIR__ . '/../support.php';

[, $proposalId, $amount, $startAt] = $argv;
$app = T::newApp();
$officer = T::user('nadia.berrada');
$app->db()->pdo();                               // connect before the starting gun
if ((float) $startAt > 0) {
    time_sleep_until((float) $startAt);          // both workers fire at the same instant
}
try {
    $r = $app->workflow()->recordDecision($officer, (int) $proposalId, 'approved', $amount, 'Concurrent test award.');
    echo json_encode(['ok' => true, 'remaining' => $r['remaining']]);
} catch (App\Grants\Denied $e) {
    echo json_encode(['ok' => false, 'reason' => $e->reason]);
}
