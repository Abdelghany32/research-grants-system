<?php
declare(strict_types=1);
// Requirement: e-mail notifications - queued atomically with the change, addressed and worded by the database,
// delivered by a separate account, and carrying no confidential content.

use App\Mail\FileMailer;
use App\Mail\MailMessage;
use App\Mail\Mailer;
use App\Mail\Notifier;
use App\Mail\SmtpMailer;

require_once __DIR__ . '/helpers_workflow.php';

/** All queued messages for a user, as the notifier account sees them. */
function outbox_for(string $localPart): array
{
    $pdo = T::rawAs('notifier_user', 'notifier_password');
    $s = $pdo->prepare('SELECT n.id, n.kind, n.ref_type, n.ref_id, n.subject, n.body, n.sent_at, n.attempts, n.last_error FROM notifications n JOIN users u ON u.id = n.to_user_id WHERE u.email = ? ORDER BY n.id');
    $s->execute([$localPart . '@uni.example']);
    return $s->fetchAll();
}

test('MAIL the workflow queues messages for the right people, in the same transaction', function (): void {
    $wf = T::app()->workflow();
    $nadia = T::user('nadia.berrada');
    $call = make_call('Notification call', '20000');
    $secretTitle = 'Confidential Quantum Title ' . bin2hex(random_bytes(3));
    $p = $wf->createDraft(T::user('amina.elidrissi'), $call, ['title' => $secretTitle, 'abstract' => str_repeat('Fictional abstract. ', 3), 'requested_amount' => '4321.00']);
    $wf->submitProposal(T::user('amina.elidrissi'), $p);
    $review = $wf->assignReviewer($nadia, $p, T::user('karim.ouazzani')->id, gmdate('Y-m-d', time() + 10 * 86400));
    $mine = array_values(array_filter(outbox_for('karim.ouazzani'), fn ($m) => (int) $m['ref_id'] === $review && $m['kind'] === 'review_assigned'));
    same(1, count($mine), 'the reviewer has one "assigned" message');
    same('A proposal has been assigned to you for review', $mine[0]['subject'], 'a fixed subject');
    check(str_contains($mine[0]['body'], '/reviews/' . $review) && str_contains($mine[0]['body'], 'Review due: ' . gmdate('Y-m-d', time() + 10 * 86400)), 'a link and the due date');
    foreach (['quantum', '4321', 'Fictional abstract'] as $leak) {
        check(stripos($mine[0]['subject'] . $mine[0]['body'], $leak) === false, "the message does not contain '$leak'");
    }

    $wf->saveReview(T::user('karim.ouazzani'), $review, ['score' => '9', 'comments' => 'A solid review for the notification test.'], true);
    $toOfficer = array_filter(outbox_for('nadia.berrada'), fn ($m) => $m['kind'] === 'review_submitted' && (int) $m['ref_id'] === $review);
    same(1, count($toOfficer), 'the officer who assigned it hears that the review is in');

    $wf->recordDecision($nadia, $p, 'approved', '4000', 'Good.');
    $toOwner = array_values(array_filter(outbox_for('amina.elidrissi'), fn ($m) => $m['kind'] === 'decision_recorded' && (int) $m['ref_id'] === $p));
    same(1, count($toOwner), 'the applicant hears that a decision exists');
    check(stripos($toOwner[0]['body'], 'approved') === false && !str_contains($toOwner[0]['body'], '4000'), 'but not what it is');
    check(count(array_filter(outbox_for('youssef.benali'), fn ($m) => (int) $m['ref_id'] === $p)) === 0, 'nobody else is told');

    // A refused action queues nothing (same transaction): a draft is not under review, so a second decision is denied.
    $before = count(outbox_for('amina.elidrissi'));
    denied('already_decided', fn () => $wf->recordDecision($nadia, $p, 'declined', '0', ''), 'a second decision is refused');
    same($before, count(outbox_for('amina.elidrissi')), 'and no message was queued for it');
});

test('MAIL the database addresses and words every message: callers cannot choose, forge or repeat one', function (): void {
    $nadia = T::user('nadia.berrada');
    $amina = T::user('amina.elidrissi');
    $call = make_call('Notification refusal call', '8000');
    $p = make_reviewed_proposal($call, 'amina.elidrissi', 'Refusal proposal', '1000');
    $review = (int) T::sqlAs($nadia, 'SELECT id FROM reviews WHERE proposal_id = ?', [$p])['rows'][0]['id'];
    $base = 'https://localhost:8443';
    $enq = fn (string $kind, int $ref, ?string $url = null) => "SELECT notify_enqueue('$kind', $ref, '" . ($url ?? $base) . "')";

    $pdo = T::rawRuntime();
    sqlstate('42501', fn () => $pdo->query($enq('decision_recorded', $p)), 'no token, no message');
    sqlstate('42501', fn () => T::sqlAs($amina, $enq('decision_recorded', $p)), 'a researcher cannot queue a decision message');
    sqlstate('42501', fn () => T::sqlAs($nadia, $enq('review_submitted', $review)), 'an officer cannot queue "review submitted" (only the reviewer who submitted it can)');
    sqlstate('42501', fn () => T::sqlAs($nadia, $enq('decision_recorded', $p)), 'an officer cannot announce a decision nobody recorded');
    sqlstate('23514', fn () => T::sqlAs($nadia, $enq('review_assigned', $review, 'javascript:alert(1)')), 'the link base must be a plain http(s) origin');
    sqlstate('23514', fn () => T::sqlAs($nadia, $enq('review_assigned', $review, "https://x.example\r\nBcc: evil@example.org")), 'and cannot smuggle a header');
    sqlstate('23514', fn () => T::sqlAs($nadia, $enq('free_text', $review)), 'there is no free-text kind');
    same(0, (int) T::sqlAs($nadia, $enq('review_assigned', $review))['rows'][0]['notify_enqueue'], 'queuing the same message twice queues it once');
    foreach (['INSERT INTO notifications (to_user_id, kind, ref_type, ref_id, subject, body) VALUES (1, \'review_assigned\', \'review\', 1, \'x\', \'y\')',
              'SELECT * FROM notifications', 'UPDATE notifications SET sent_at = now()', 'DELETE FROM notifications'] as $sql) {
        sqlstate('42501', fn () => $pdo->exec($sql), "the web account has no direct access: $sql");
    }
});

test('MAIL the notifier account can deliver mail and nothing else', function (): void {
    $n = T::rawAs('notifier_user', 'notifier_password');
    same('grants_notifier', $n->query('SELECT current_user')->fetchColumn(), 'its own account');
    check($n->query('SELECT count(*) FROM notifications')->fetchColumn() >= 0, 'reads the outbox');
    check($n->query('SELECT email, full_name FROM users LIMIT 1')->fetch() !== false, 'reads the recipient address and name');
    foreach (['SELECT password_hash FROM users', 'SELECT role FROM users', 'SELECT * FROM proposals', 'SELECT * FROM reviews', 'SELECT * FROM audit_events',
              'SELECT * FROM decisions', 'SELECT * FROM actor_key', 'UPDATE notifications SET subject = \'x\'', 'UPDATE users SET email = \'x@y.z\'',
              'DELETE FROM notifications', "SELECT record_decision(1, 'approved', 1, 'x')", "SELECT audit_append('auth.login', 'user', 1, 'denied', '{}'::jsonb, NULL, NULL, NULL, NULL)"] as $sql) {
        sqlstate('42501', fn () => $n->query($sql), "the notifier cannot: $sql");
    }
    // Reminders may be queued only by the notifier.
    sqlstate('42501', fn () => T::rawRuntime()->query("SELECT notify_enqueue_reminders('https://localhost:8443')"), 'the web account cannot queue reminders');
});

test('MAIL delivery marks messages sent once, retries failures, and writes safe .eml files', function (): void {
    $dir = sys_get_temp_dir() . '/outbox-' . bin2hex(random_bytes(4));
    $notifier = new Notifier(T::newApp()->notifierDb(), new FileMailer($dir, 'research-grants@uni.example'), 'https://localhost:8443');
    $pending = (int) T::rawAs('notifier_user', 'notifier_password')->query('SELECT count(*) FROM notifications WHERE sent_at IS NULL')->fetchColumn();
    check($pending >= 3, 'there are messages waiting');
    $r = $notifier->deliverPending(500);
    same($pending, $r['sent'], 'all were delivered');
    same(0, $r['failed'], 'none failed');
    $files = glob("$dir/*.eml");
    same($pending, count($files), 'one file per message');
    $eml = (string) file_get_contents($files[0]);
    check(str_contains($eml, "\r\nSubject: ") && str_contains($eml, 'Content-Type: text/plain; charset=UTF-8') && str_contains($eml, 'Auto-Submitted: auto-generated'), 'proper headers');
    check(!preg_match('/\r\nBcc:|\r\nCc:/i', $eml), 'no extra recipients');
    same(0, $notifier->deliverPending(500)['sent'], 'a second run sends nothing: sent messages are not sent again');

    // A failing transport: the message stays queued, the error is recorded, and it is retried up to the limit.
    $call = make_call('Mail failure call', '3000');
    make_reviewed_proposal($call, 'youssef.benali', 'Mail failure proposal', '500');
    $boom = new class implements Mailer {
        public function send(string $toEmail, string $toName, string $subject, string $body): void
        {
            throw new RuntimeException("connection refused\r\nsecret-token-123");
        }
    };
    $failing = new Notifier(T::newApp()->notifierDb(), $boom, 'https://localhost:8443', 2);
    $f1 = $failing->deliverPending(500);
    check($f1['failed'] >= 1 && $f1['sent'] === 0, 'failures are counted');
    $row = T::rawAs('notifier_user', 'notifier_password')->query('SELECT attempts, last_error, sent_at FROM notifications WHERE last_error IS NOT NULL ORDER BY id DESC LIMIT 1')->fetch();
    same(1, (int) $row['attempts'], 'one attempt recorded');
    check($row['sent_at'] === null && !str_contains($row['last_error'], "\n"), 'still queued, error stored on one line');
    $failing->deliverPending(500);
    same(0, $failing->deliverPending(500)['failed'], 'after the attempt limit (2) a message is left alone');
    array_map('unlink', glob("$dir/*"));
    @rmdir($dir);
});

test('MAIL header injection is refused and addresses are validated', function (): void {
    $ok = MailMessage::build('a@uni.example', 'b@uni.example', 'Dr. Ben', 'Hello', "Line one\n.Line starting with a dot");
    check(str_contains($ok, "\r\nTo: \"Dr. Ben\" <b@uni.example>\r\n"), 'a normal message');
    foreach ([['b@uni.example', "Evil\r\nBcc: x@y.z", 'Subject'], ['b@uni.example', 'Name', "Subject\nBcc: x@y.z"], ["b@uni.example\r\nBcc: x@y.z", 'Name', 'S'],
              ['not-an-address', 'Name', 'S'], ['a<b>@uni.example', 'Name', 'S']] as [$to, $name, $subject]) {
        try {
            MailMessage::build('a@uni.example', $to, $name, $subject, 'x');
            check(false, 'must be refused: ' . json_encode([$to, $name, $subject]));
        } catch (InvalidArgumentException) {
            check(true, 'refused');
        }
    }
    check(str_contains(MailMessage::build('a@uni.example', 'b@uni.example', 'Zoë', 'Réunion', 'x'), '=?UTF-8?B?'), 'non-ASCII headers are encoded');
});

test('MAIL the SMTP client speaks the protocol, dot-stuffs, and refuses unencrypted credentials', function (): void {
    $logFile = sys_get_temp_dir() . '/smtp-' . bin2hex(random_bytes(4)) . '.log';
    $proc = proc_open(['php', __DIR__ . '/workers/fake_smtp.php', $logFile], [['file', '/dev/null', 'r'], ['pipe', 'w'], ['file', '/dev/null', 'w']], $pipes);
    $port = (int) trim((string) fgets($pipes[1]));
    check($port > 0, 'the fake server is listening');
    (new SmtpMailer('127.0.0.1', $port, 'none', 'research-grants@uni.example'))->send('b@uni.example', 'Ben', 'Hello', "First line\n.dot line\nlast");
    proc_close($proc);
    $log = (string) file_get_contents($logFile);
    @unlink($logFile);
    foreach (['EHLO ', 'MAIL FROM:<research-grants@uni.example>', 'RCPT TO:<b@uni.example>', 'DATA', 'QUIT', 'Subject: Hello'] as $cmd) {
        check(str_contains($log, $cmd), "the client sent $cmd");
    }
    check(str_contains($log, "\n..dot line"), 'a body line starting with a dot is stuffed');
    foreach ([fn () => new SmtpMailer('mail.example.org', 25, 'none', 'a@uni.example'), fn () => new SmtpMailer('127.0.0.1', 25, 'none', 'a@uni.example', 'user', 'secret')] as $make) {
        try {
            $make();
            check(false, 'must be refused');
        } catch (RuntimeException $e) {
            check(true, 'refused: ' . $e->getMessage());
        }
    }
});

test('MAIL due-date reminders are queued once, to the reviewer and the officer, and carry no details', function (): void {
    $wf = T::app()->workflow();
    $nadia = T::user('nadia.berrada');
    $n = T::rawAs('notifier_user', 'notifier_password');
    // Due tomorrow: a "due soon" reminder.
    $call = make_call('Reminder call', '6000');
    $p = T::app()->workflow()->createDraft(T::user('amina.elidrissi'), $call, ['title' => 'Reminder proposal', 'abstract' => str_repeat('Fictional abstract. ', 3), 'requested_amount' => '900']);
    $wf->submitProposal(T::user('amina.elidrissi'), $p);
    $review = $wf->assignReviewer($nadia, $p, T::user('salma.tazi')->id, gmdate('Y-m-d', time() + 86400));
    $first = (int) $n->query("SELECT notify_enqueue_reminders('https://localhost:8443')")->fetchColumn();
    check($first >= 1, 'reminders were queued');
    same(0, (int) $n->query("SELECT notify_enqueue_reminders('https://localhost:8443')")->fetchColumn(), 'and a second run queues none');
    $soon = array_values(array_filter(outbox_for('salma.tazi'), fn ($m) => $m['kind'] === 'review_due_soon' && (int) $m['ref_id'] === $review));
    same(1, count($soon), 'the reviewer is told the review is due soon');
    check(!str_contains($soon[0]['body'], 'Reminder proposal'), 'without the proposal title');
    // The fixture review that is already past its deadline: overdue for the reviewer AND the officer who assigned it.
    $over = T::proposalId('Fixture: review past its deadline');
    $overReview = (int) T::sqlAs($nadia, 'SELECT id FROM reviews WHERE proposal_id = ?', [$over])['rows'][0]['id'];
    $status = T::sqlAs($nadia, 'SELECT status FROM reviews WHERE id = ?', [$overReview])['rows'][0]['status'];
    if ($status === 'assigned') {
        $kinds = array_column(array_merge(outbox_for('salma.tazi'), outbox_for('nadia.berrada')), 'kind', 'id');
        check(in_array('review_overdue', $kinds, true), 'an overdue review is reported');
    }
    sqlstate('23514', fn () => $n->query("SELECT notify_enqueue_reminders('ftp://x')"), 'the reminder link base is checked too');
});
