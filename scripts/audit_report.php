<?php
declare(strict_types=1);
// Prints audit events as the grants_auditor account sees them (text table).
// usage: php scripts/audit_report.php [since-ISO-timestamp] [anomalies]
//   anomalies: only events the application itself could not have written (no request correlation id
//   or no source address - every event the web application writes carries both).
require __DIR__ . '/../src/bootstrap.php';

$app = new App\App(require __DIR__ . '/../config/config.php');
$pdo = $app->auditorDb()->pdo();
$stmt = $pdo->prepare("SELECT id, to_char(occurred_at, 'YYYY-MM-DD HH24:MI:SS.MS') AS utc_time, coalesce(actor_email, '(not signed in)') AS actor,
        coalesce(actor_role, '-') AS role, CASE WHEN actor_verified THEN 'yes' ELSE 'no' END AS proved, action, coalesce(resource_type || ' #' || resource_id, resource_type, '-') AS resource,
        outcome, left(correlation_id::text, 8) AS request, details::text AS details
   FROM audit_timeline WHERE occurred_at >= ?::timestamptz" . (($argv[2] ?? '') === 'anomalies' ? ' AND (correlation_id IS NULL OR source_ip IS NULL)' : '') . " ORDER BY id");
$stmt->execute([$argv[1] ?? '2000-01-01']);
printf("connected as %s to %s\n", $pdo->query('SELECT current_user')->fetchColumn(), $pdo->query('SELECT current_database()')->fetchColumn());
printf("%-5s %-23s %-28s %-10s %-6s %-22s %-13s %-8s %-8s %s\n", 'id', 'time (UTC)', 'actor', 'role', 'proved', 'action', 'resource', 'outcome', 'request', 'details');
foreach ($stmt as $r) {
    printf("%-5d %-23s %-28s %-10s %-6s %-22s %-13s %-8s %-8s %s\n", ...array_values($r));
}
