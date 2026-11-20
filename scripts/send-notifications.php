<?php
declare(strict_types=1);
// Delivers the e-mail outbox (and, with --reminders, first queues the 48-hour and overdue reminders).
//   php scripts/send-notifications.php [--reminders]
// Runs as the notifier service in compose.yaml (every minute), or by hand. The transport comes from the environment:
//   MAIL_TRANSPORT=file   (default) one .eml file per message in logs/outbox - nothing leaves the machine
//   MAIL_TRANSPORT=smtp   SMTP_HOST, SMTP_PORT, SMTP_SECURITY (starttls|tls), SMTP_USER, SMTP_PASSWORD, MAIL_FROM
require __DIR__ . '/../src/bootstrap.php';

$app = new App\App(require __DIR__ . '/../config/config.php');
$notifier = $app->notifier();
$queued = in_array('--reminders', $argv, true) ? $notifier->queueReminders() : 0;
$r = $notifier->deliverPending();
printf("%s reminders queued: %d, sent: %d, failed: %d (transport: %s)\n", gmdate('c'), $queued, $r['sent'], $r['failed'], $app->config['mail']['transport']);
exit($r['failed'] > 0 ? 1 : 0);
