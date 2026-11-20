<?php
declare(strict_types=1);

namespace App\Mail;

use App\Database\Database;
use PDO;
use Throwable;

/** Delivers the e-mail outbox with the notifier's own database account, which can see nothing else. */
final class Notifier
{
    public function __construct(
        private readonly Database $db,
        private readonly Mailer $mailer,
        private readonly string $publicUrl,
        private readonly int $maxAttempts = 5,
    ) {
    }

    /** Queue the 48-hour and overdue reminders (each once). @return int messages queued */
    public function queueReminders(): int
    {
        $s = $this->db->pdo()->prepare('SELECT notify_enqueue_reminders(?)');
        $s->execute([$this->publicUrl]);
        return (int) $s->fetchColumn();
    }

    /** @return array{sent:int, failed:int} */
    public function deliverPending(int $limit = 50): array
    {
        $pdo = $this->db->pdo();
        $sent = $failed = 0;
        $pdo->beginTransaction();
        try {
            $rows = $pdo->prepare('SELECT n.id, u.email, u.full_name, n.subject, n.body
                                     FROM notifications n JOIN users u ON u.id = n.to_user_id
                                    WHERE n.sent_at IS NULL AND n.attempts < ?
                                    ORDER BY n.id LIMIT ? FOR UPDATE OF n SKIP LOCKED');
            $rows->execute([$this->maxAttempts, $limit]);
            foreach ($rows->fetchAll() as $m) {
                try {
                    $this->mailer->send($m['email'], $m['full_name'], $m['subject'], $m['body']);
                    $pdo->prepare('UPDATE notifications SET sent_at = now(), attempts = attempts + 1, last_error = NULL WHERE id = ?')->execute([$m['id']]);
                    $sent++;
                } catch (Throwable $e) {
                    $err = substr(preg_replace('/[^\x20-\x7e]+/', ' ', get_class($e) . ': ' . $e->getMessage()) ?? '', 0, 400);
                    $pdo->prepare('UPDATE notifications SET attempts = attempts + 1, last_error = ? WHERE id = ?')->execute([$err, $m['id']]);
                    $failed++;
                }
            }
            $pdo->commit();
        } catch (Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            throw $e;
        }
        return ['sent' => $sent, 'failed' => $failed];
    }
}
