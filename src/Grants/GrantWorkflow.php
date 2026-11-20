<?php
declare(strict_types=1);

namespace App\Grants;

use App\Audit\AuditWriter;
use App\Auth\Policy;
use App\Auth\User;
use App\Database\Database;
use App\Security\FieldCipher;
use PDO;

/**
 * Every state-changing business operation, one public method each.
 *
 *   Draft -> Submitted -> Under review -> Approved | Declined
 *
 * Each operation: (1) validates input, (2) checks the human-role permission,
 * (3) runs in ONE transaction as the actor (so RLS applies), (4) re-checks
 * ownership/state inside that transaction, (5) appends its success event in
 * the same transaction. A Denied exception rolls everything back and is then
 * recorded on the independent audit connection.
 */
final class GrantWorkflow
{
    public function __construct(
        private readonly Database $db,
        private readonly AuditWriter $audit,
        private readonly FieldCipher $cipher,
        private readonly string $publicUrl = 'https://localhost:8443',
    ) {
    }

    // ------------------------------------------------------------ researcher

    /** @return int new proposal id */
    public function createDraft(User $actor, int $callId, array $input): int
    {
        $data = $this->validProposal($input);
        return $this->guarded($actor, 'proposal.write_own_draft', 'proposal.create', 'proposal', null,
            function (PDO $tx) use ($actor, $callId, $data): int {
                $call = $this->one($tx, "SELECT id, currency, total_budget,
                                                status = 'open' AND now() >= opens_at AND now() < closes_at AS is_open
                                           FROM grant_calls WHERE id = ?", [$callId]);
                if ($call === null || !$call['is_open']) {
                    throw new Denied('call_not_open', 'This call is not open for proposals.');
                }
                $this->requireWithinCallBudget($data['requested_amount'], $call['total_budget']);
                $stmt = $tx->prepare('INSERT INTO proposals (call_id, owner_id, title, abstract, requested_amount, currency)
                                      VALUES (?, ?, ?, ?, ?, ?) RETURNING id');
                $stmt->execute([$callId, $actor->id, $data['title'], $data['abstract'], $data['requested_amount'], $call['currency']]);
                $id = (int) $stmt->fetchColumn();
                $this->audit->withChange($tx, $actor, 'proposal.create', 'proposal', $id, ['call_id' => $callId]);
                return $id;
            });
    }

    public function updateDraft(User $actor, int $proposalId, array $input): void
    {
        $data = $this->validProposal($input);
        $this->guarded($actor, 'proposal.write_own_draft', 'proposal.update', 'proposal', $proposalId,
            function (PDO $tx) use ($actor, $proposalId, $data): void {
                $p = $this->one($tx, 'SELECT p.status, c.total_budget FROM proposals p JOIN grant_calls c ON c.id = p.call_id
                                       WHERE p.id = ? AND p.owner_id = ?', [$proposalId, $actor->id]);
                if ($p === null) {
                    throw new Denied('not_visible', 'Proposal not found.');
                }
                if ($p['status'] !== 'draft') {
                    throw new Denied('not_a_draft', 'Only drafts can be edited.');
                }
                $this->requireWithinCallBudget($data['requested_amount'], $p['total_budget']);
                $tx->prepare("UPDATE proposals SET title = ?, abstract = ?, requested_amount = ?
                               WHERE id = ? AND owner_id = ? AND status = 'draft'")
                   ->execute([$data['title'], $data['abstract'], $data['requested_amount'], $proposalId, $actor->id]);
                $this->audit->withChange($tx, $actor, 'proposal.update', 'proposal', $proposalId);
            });
    }

    public function submitProposal(User $actor, int $proposalId): void
    {
        $this->guarded($actor, 'proposal.submit', 'proposal.submit', 'proposal', $proposalId,
            function (PDO $tx) use ($actor, $proposalId): void {
                $p = $this->one($tx, "SELECT p.status, length(btrim(p.abstract)) AS abstract_length,
                                             c.status = 'open' AND now() < c.closes_at AS call_open
                                        FROM proposals p JOIN grant_calls c ON c.id = p.call_id
                                       WHERE p.id = ? AND p.owner_id = ?", [$proposalId, $actor->id]);
                if ($p === null) {
                    throw new Denied('not_visible', 'Proposal not found.');
                }
                if ($p['status'] !== 'draft') {
                    throw new Denied('not_a_draft', 'This proposal has already been submitted.');
                }
                if (!$p['call_open']) {
                    throw new Denied('deadline_passed', 'The submission deadline for this call has passed.');
                }
                if ($p['abstract_length'] < 20) {
                    throw new ValidationFailed(['abstract' => 'Write an abstract of at least 20 characters before submitting.']);
                }
                // "AND status = 'draft'" makes a double click harmless: the second UPDATE matches no row.
                $upd = $tx->prepare("UPDATE proposals SET status = 'submitted' WHERE id = ? AND owner_id = ? AND status = 'draft'");
                $upd->execute([$proposalId, $actor->id]);
                if ($upd->rowCount() !== 1) {
                    throw new Denied('not_a_draft', 'This proposal has already been submitted.');
                }
                $this->audit->withChange($tx, $actor, 'proposal.submit', 'proposal', $proposalId);
            });
    }

    public function deleteDraft(User $actor, int $proposalId): void
    {
        $this->guarded($actor, 'proposal.write_own_draft', 'proposal.delete', 'proposal', $proposalId,
            function (PDO $tx) use ($actor, $proposalId): void {
                $del = $tx->prepare("DELETE FROM proposals WHERE id = ? AND owner_id = ? AND status = 'draft'");
                $del->execute([$proposalId, $actor->id]);
                if ($del->rowCount() !== 1) {
                    throw new Denied('not_own_draft', 'Only your own drafts can be deleted.');
                }
                $this->audit->withChange($tx, $actor, 'proposal.delete', 'proposal', $proposalId);
            });
    }

    // --------------------------------------------------------------- officer

    /** @return int new review (assignment) id */
    public function assignReviewer(User $actor, int $proposalId, int $reviewerId, ?string $dueDate): int
    {
        if ($dueDate !== null && $dueDate !== '' && !$this->isFutureDate($dueDate)) {
            throw new ValidationFailed(['due_at' => 'Choose a review deadline in the future (YYYY-MM-DD).']);
        }
        return $this->guarded($actor, 'review.assign', 'review.assign', 'proposal', $proposalId,
            function (PDO $tx) use ($actor, $proposalId, $reviewerId, $dueDate): int {
                // Row lock: two officers assigning at once take turns on this proposal.
                $p = $this->one($tx, 'SELECT owner_id, status FROM proposals WHERE id = ? FOR NO KEY UPDATE', [$proposalId]);
                if ($p === null) {
                    throw new Denied('not_assignable', 'This proposal is not open for reviewer assignment.');
                }
                if ((int) $p['owner_id'] === $reviewerId) {
                    throw new Denied('self_review', 'A person cannot review their own proposal.');
                }
                if ($this->one($tx, "SELECT 1 FROM users WHERE id = ? AND role = 'reviewer' AND is_active", [$reviewerId]) === null) {
                    throw new Denied('not_a_reviewer', 'The selected person is not an active reviewer.');
                }
                if ($this->one($tx, 'SELECT 1 FROM reviews WHERE proposal_id = ? AND reviewer_id = ?', [$proposalId, $reviewerId]) !== null) {
                    throw new Denied('already_assigned', 'This reviewer is already assigned to the proposal.');
                }
                $ins = $tx->prepare("INSERT INTO reviews (proposal_id, reviewer_id, assigned_by, due_at)
                                     VALUES (?, ?, ?, ?::date + interval '1 day' - interval '1 second') RETURNING id");
                $ins->execute([$proposalId, $reviewerId, $actor->id, $dueDate ?: null]);
                $reviewId = (int) $ins->fetchColumn();
                if ($p['status'] === 'submitted') {
                    $tx->prepare("UPDATE proposals SET status = 'under_review' WHERE id = ? AND status = 'submitted'")
                       ->execute([$proposalId]);
                }
                $this->audit->withChange($tx, $actor, 'review.assign', 'proposal', $proposalId,
                    ['review_id' => $reviewId, 'reviewer_id' => $reviewerId]);
                $this->notify($tx, 'review_assigned', $reviewId);
                return $reviewId;
            });
    }

    /**
     * Record the final funding decision.
     *
     * Concurrency: record_decision() serializes all decisions for one grant
     * call by locking that call's row. A second officer (or a second click)
     * waits there, then re-reads the proposal and the balance and sees the
     * first result. READ COMMITTED is enough because every check happens
     * after the lock.
     *
     * @return array{decision_id:int, remaining:string}
     */
    public function recordDecision(User $actor, int $proposalId, string $outcome, string $amountInput, string $rationale): array
    {
        $errors = [];
        if (!in_array($outcome, ['approved', 'declined'], true)) {
            $errors['outcome'] = 'Choose Approve or Decline.';
        }
        $amount = $outcome === 'declined' ? '0.00' : Money::parse($amountInput);
        if ($amount === null || ($outcome === 'approved' && Money::cents($amount) <= 0)) {
            $errors['awarded_amount'] = 'Enter the award as a positive amount, for example 7000.00.';
        }
        $rationale = trim($rationale);
        if (mb_strlen($rationale) > 2000) {
            $errors['rationale'] = 'Keep the rationale under 2,000 characters.';
        }
        if ($errors) {
            throw new ValidationFailed($errors);
        }

        return $this->guarded($actor, 'decision.record', 'decision.record', 'proposal', $proposalId,
            function (PDO $tx) use ($proposalId, $outcome, $amount, $rationale): array {
                // The whole award - lock, eligibility, money limits, decision row,
                // balance, proposal status and audit event - is ONE database
                // function (finding F01). The runtime account has no privilege to
                // do any of these steps separately, so none can be done partially.
                try {
                    $stmt = $tx->prepare('SELECT decision_id, remaining FROM record_decision(?, ?, ?::numeric, ?, ?::uuid, ?::inet)');
                    $stmt->execute([$proposalId, $outcome, $amount, $rationale, $this->audit->correlationId(), $this->audit->ip()]);
                } catch (\PDOException $e) {
                    // GR001 = a business rule refused the award; the transaction is rolled back by the caller.
                    if (($e->errorInfo[0] ?? '') === 'GR001' && preg_match('/ERROR:\s+(\w+)\|([^\n]*)/', (string) ($e->errorInfo[2] ?? ''), $m)) {
                        throw new Denied($m[1], $m[2]);
                    }
                    throw $e;
                }
                $row = $stmt->fetch();
                $this->notify($tx, 'decision_recorded', $proposalId);
                return ['decision_id' => (int) $row['decision_id'], 'remaining' => (string) $row['remaining']];
            });
    }

    /** @return int new call id */
    public function createCall(User $actor, array $input): int
    {
        $data = $this->validCall($input, creating: true);
        return $this->guarded($actor, 'call.manage', 'call.create', 'grant_call', null,
            function (PDO $tx) use ($actor, $data): int {
                $stmt = $tx->prepare("INSERT INTO grant_calls (title, description, currency, total_budget, remaining_budget, closes_at, created_by)
                                      VALUES (?, ?, ?, ?, ?, ?::date + interval '1 day' - interval '1 second', ?) RETURNING id");
                $stmt->execute([$data['title'], $data['description'], $data['currency'], $data['total_budget'],
                                $data['total_budget'], $data['closes_on'], $actor->id]);
                $id = (int) $stmt->fetchColumn();
                $this->audit->withChange($tx, $actor, 'call.create', 'grant_call', $id,
                    ['total_budget' => $data['total_budget'], 'currency' => $data['currency']]);
                return $id;
            });
    }

    /** Officers may retitle a call, move its deadline, or close/reopen it. The budget is fixed at creation. */
    public function updateCall(User $actor, int $callId, array $input): void
    {
        $data = $this->validCall($input, creating: false);
        $this->guarded($actor, 'call.manage', 'call.update', 'grant_call', $callId,
            function (PDO $tx) use ($actor, $callId, $data): void {
                $upd = $tx->prepare("UPDATE grant_calls SET title = ?, description = ?, status = ?,
                                            closes_at = ?::date + interval '1 day' - interval '1 second'
                                      WHERE id = ?");
                $upd->execute([$data['title'], $data['description'], $data['status'], $data['closes_on'], $callId]);
                if ($upd->rowCount() !== 1) {
                    throw new Denied('not_visible', 'Grant call not found.');
                }
                $this->audit->withChange($tx, $actor, 'call.update', 'grant_call', $callId, ['status' => $data['status']]);
            });
    }

    // -------------------------------------------------------------- reviewer

    /** Save a draft review ($final = false) or submit it for good ($final = true). */
    public function saveReview(User $actor, int $reviewId, array $input, bool $final): void
    {
        $errors = [];
        $scoreRaw = trim((string) ($input['score'] ?? ''));
        $score = $scoreRaw === '' ? null : filter_var($scoreRaw, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 10]]);
        if ($score === false || ($final && $score === null)) {
            $errors['score'] = 'Give a whole-number score from 1 to 10.';
        }
        $comments = trim((string) ($input['comments'] ?? ''));
        if (mb_strlen($comments) > 4000) {
            $errors['comments'] = 'Keep comments under 4,000 characters.';
        } elseif ($final && mb_strlen($comments) < 10) {
            $errors['comments'] = 'Add a short justification (at least 10 characters) before submitting.';
        }
        if ($errors) {
            throw new ValidationFailed($errors);
        }

        $action = $final ? 'review.submit' : 'review.save_draft';
        $this->guarded($actor, 'review.write_assigned', $action, 'review', $reviewId,
            function (PDO $tx) use ($actor, $reviewId, $score, $comments, $final, $action): void {
                $r = $this->one($tx, 'SELECT r.status, r.proposal_id, p.status AS proposal_status, r.due_at < now() AS overdue
                                        FROM reviews r JOIN proposals p ON p.id = r.proposal_id
                                       WHERE r.id = ? AND r.reviewer_id = ?', [$reviewId, $actor->id]);
                if ($r === null) {
                    throw new Denied('not_assigned', 'Review assignment not found.');
                }
                if ($r['status'] === 'submitted') {
                    throw new Denied('review_finalized', 'This review has been submitted and can no longer be changed.');
                }
                if ($r['proposal_status'] !== 'under_review') {
                    throw new Denied('proposal_closed', 'This proposal is no longer under review.');
                }
                // The database enforces this too (reviews_guard); checking here gives a clear message and an audited denial.
                if ($r['overdue']) {
                    throw new Denied('review_overdue', 'The deadline for this review has passed. Ask the grants office for an extension.');
                }
                // Comments are encrypted here, bound to this review row.
                $enc = $comments === '' ? null : $this->cipher->encrypt($comments, 'reviews.comments:' . $reviewId);
                $upd = $tx->prepare("UPDATE reviews SET score = ?, comments_enc = ?, status = ?
                                      WHERE id = ? AND reviewer_id = ? AND status = 'assigned'");
                $upd->execute([$score, $enc, $final ? 'submitted' : 'assigned', $reviewId, $actor->id]);
                if ($upd->rowCount() !== 1) {
                    throw new Denied('review_finalized', 'This review has been submitted and can no longer be changed.');
                }
                $this->audit->withChange($tx, $actor, $action, 'review', $reviewId, ['proposal_id' => (int) $r['proposal_id']]);
                if ($final) {
                    $this->notify($tx, 'review_submitted', $reviewId);
                }
            });
    }

    /**
     * An officer moves a review deadline forward. The database refuses anything else: another role, an earlier date,
     * a finalized review, or a change to the review's content in the same statement.
     *
     * @return int the proposal id (for the redirect)
     */
    public function extendReviewDeadline(User $actor, int $reviewId, string $newDate): int
    {
        if (!$this->isFutureDate($newDate)) {
            throw new ValidationFailed(['due_at' => 'Choose a new deadline in the future (YYYY-MM-DD).']);
        }
        return $this->guarded($actor, 'review.assign', 'review.extend_deadline', 'review', $reviewId,
            function (PDO $tx) use ($actor, $reviewId, $newDate): int {
                $r = $this->one($tx, 'SELECT r.status, r.proposal_id, r.due_at, p.status AS proposal_status
                                        FROM reviews r JOIN proposals p ON p.id = r.proposal_id WHERE r.id = ?', [$reviewId]);
                if ($r === null) {
                    throw new Denied('not_visible', 'Review not found.');
                }
                if ($r['status'] !== 'assigned' || $r['proposal_status'] !== 'under_review') {
                    throw new Denied('review_closed', 'Only the deadline of an open review can be extended.');
                }
                $new = $this->one($tx, "SELECT (?::date + interval '1 day' - interval '1 second') AS due", [$newDate])['due'];
                if ($r['due_at'] !== null && strtotime($new) <= strtotime($r['due_at'])) {
                    throw new ValidationFailed(['due_at' => 'The new deadline must be later than the current one (' . substr($r['due_at'], 0, 10) . ').']);
                }
                $upd = $tx->prepare("UPDATE reviews SET due_at = ?::date + interval '1 day' - interval '1 second' WHERE id = ? AND status = 'assigned'");
                $upd->execute([$newDate, $reviewId]);
                if ($upd->rowCount() !== 1) {
                    throw new Denied('review_closed', 'Only the deadline of an open review can be extended.');
                }
                $this->audit->withChange($tx, $actor, 'review.extend_deadline', 'review', $reviewId,
                    ['proposal_id' => (int) $r['proposal_id'], 'new_due' => $newDate]);
                return (int) $r['proposal_id'];
            });
    }

    // --------------------------------------------------------------- helpers

    /** Queue an e-mail in the SAME transaction as the change; the database chooses the recipient and the text. */
    private function notify(PDO $tx, string $kind, int $ref): void
    {
        $tx->prepare('SELECT notify_enqueue(?, ?, ?)')->execute([$kind, $ref, $this->publicUrl]);
    }

    private function guarded(User $actor, string $permission, string $action, string $type, ?int $id, callable $work): mixed
    {
        try {
            if (!Policy::can($actor, $permission)) {
                throw new Denied('role_not_permitted', 'Your role does not permit this action.');
            }
            return $this->db->asActor($actor->id, $work);
        } catch (Denied $e) {
            // The business transaction is already rolled back at this point.
            $this->audit->standalone($actor, $action, $type, $id, 'denied', ['reason' => $e->reason]);
            throw $e;
        }
    }

    private function one(PDO $tx, string $sql, array $args): ?array
    {
        $stmt = $tx->prepare($sql);
        $stmt->execute($args);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    private function validProposal(array $input): array
    {
        $errors = [];
        $title = trim((string) ($input['title'] ?? ''));
        $abstract = trim((string) ($input['abstract'] ?? ''));
        $amount = Money::parse((string) ($input['requested_amount'] ?? ''));
        if (mb_strlen($title) < 3 || mb_strlen($title) > 200) {
            $errors['title'] = 'Give the proposal a title of 3 to 200 characters.';
        }
        if (mb_strlen($abstract) > 5000) {
            $errors['abstract'] = 'Keep the abstract under 5,000 characters.';
        }
        if ($amount === null || Money::cents($amount) <= 0) {
            $errors['requested_amount'] = 'Enter the requested amount as a positive number, for example 7000.00.';
        }
        if ($errors) {
            throw new ValidationFailed($errors);
        }
        return ['title' => $title, 'abstract' => $abstract, 'requested_amount' => $amount];
    }

    private function requireWithinCallBudget(string $requested, string $callTotal): void
    {
        if (Money::cents($requested) > Money::cents($callTotal)) {
            throw new ValidationFailed(['requested_amount' =>
                'The request exceeds the total budget of this call (' . Money::format($callTotal) . ').']);
        }
    }

    private function validCall(array $input, bool $creating): array
    {
        $errors = [];
        $title = trim((string) ($input['title'] ?? ''));
        $description = trim((string) ($input['description'] ?? ''));
        $closesOn = trim((string) ($input['closes_on'] ?? ''));
        $status = (string) ($input['status'] ?? 'open');
        if (mb_strlen($title) < 3 || mb_strlen($title) > 200) {
            $errors['title'] = 'Give the call a title of 3 to 200 characters.';
        }
        if (mb_strlen($description) > 4000) {
            $errors['description'] = 'Keep the description under 4,000 characters.';
        }
        if (!$this->isFutureDate($closesOn) && ($creating || $status === 'open')) {
            $errors['closes_on'] = 'Choose a closing date in the future (YYYY-MM-DD).';
        } elseif (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $closesOn)) {
            $errors['closes_on'] = 'Use the format YYYY-MM-DD.';
        }
        if (!in_array($status, ['open', 'closed'], true)) {
            $errors['status'] = 'Choose Open or Closed.';
        }
        $data = ['title' => $title, 'description' => $description, 'closes_on' => $closesOn, 'status' => $status];
        if ($creating) {
            $currency = strtoupper(trim((string) ($input['currency'] ?? '')));
            $budget = Money::parse((string) ($input['total_budget'] ?? ''));
            if (!preg_match('/^[A-Z]{3}$/', $currency)) {
                $errors['currency'] = 'Use a three-letter currency code such as MAD.';
            }
            if ($budget === null || Money::cents($budget) <= 0) {
                $errors['total_budget'] = 'Enter the total budget as a positive amount.';
            }
            $data += ['currency' => $currency, 'total_budget' => $budget];
        }
        if ($errors) {
            throw new ValidationFailed($errors);
        }
        return $data;
    }

    private function isFutureDate(string $ymd): bool
    {
        $d = \DateTimeImmutable::createFromFormat('!Y-m-d', $ymd, new \DateTimeZone('UTC'));
        return $d !== false && $d->format('Y-m-d') === $ymd && $d >= new \DateTimeImmutable('today', new \DateTimeZone('UTC'));
    }
}
