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
 * Every read the screens need. Two independent filters apply to each query:
 * an explicit predicate written here (owner_id = me, reviewer_id = me ...)
 * and the row-level security policy in PostgreSQL. Lists, searches, counts
 * and detail pages all go through these methods, so they agree by construction:
 * dashboard counts are computed from the same rows the user can list.
 */
final class GrantQueries
{
    public function __construct(
        private readonly Database $db,
        private readonly AuditWriter $audit,
        private readonly FieldCipher $cipher,
    ) {
    }

    // ------------------------------------------------------------ researcher

    public function openCalls(User $actor): array
    {
        return $this->read($actor, 'call.read',
            "SELECT id, title, description, currency, total_budget, closes_at
               FROM grant_calls
              WHERE status = 'open' AND now() >= opens_at AND now() < closes_at
              ORDER BY closes_at", []);
    }

    public function call(User $actor, int $callId): ?array
    {
        return $this->read($actor, 'call.read',
            "SELECT id, title, description, currency, total_budget, remaining_budget, closes_at, status,
                    status = 'open' AND now() >= opens_at AND now() < closes_at AS is_open
               FROM grant_calls WHERE id = ?", [$callId])[0] ?? null;
    }

    /** The researcher's own proposals, optionally filtered by a title search. */
    public function myProposals(User $actor, string $search = ''): array
    {
        return $this->read($actor, 'proposal.read_own',
            "SELECT p.id, p.title, p.status, p.requested_amount, p.currency, p.updated_at,
                    c.title AS call_title, c.closes_at,
                    c.status = 'open' AND now() < c.closes_at AS call_open
               FROM proposals p JOIN grant_calls c ON c.id = p.call_id
              WHERE p.owner_id = ? AND p.title ILIKE ? ESCAPE '\\'
              ORDER BY p.updated_at DESC, p.id DESC", [$actor->id, self::contains($search)]);
    }

    /** One of the researcher's own proposals with its final decision, if any. */
    public function myProposal(User $actor, int $proposalId): ?array
    {
        $row = $this->read($actor, 'proposal.read_own',
            "SELECT p.id, p.call_id, p.title, p.abstract, p.status, p.requested_amount, p.currency,
                    p.created_at, p.updated_at, p.submitted_at,
                    c.title AS call_title, c.closes_at, c.total_budget,
                    c.status = 'open' AND now() < c.closes_at AS call_open,
                    d.outcome, d.awarded_amount, d.rationale, d.decided_at
               FROM proposals p
               JOIN grant_calls c ON c.id = p.call_id
               LEFT JOIN decisions d ON d.proposal_id = p.id
              WHERE p.id = ? AND p.owner_id = ?", [$proposalId, $actor->id])[0] ?? null;
        if ($row === null) {
            // Not found and not permitted look identical to the user (no hint
            // that the record exists) and are both recorded as a denied read.
            $this->audit->standalone($actor, 'proposal.view', 'proposal', $proposalId, 'denied', ['reason' => 'not_visible']);
        }
        return $row;
    }

    // -------------------------------------------------------------- reviewer

    public function myAssignments(User $actor): array
    {
        return $this->read($actor, 'review.read_assigned',
            "SELECT r.id, r.status, r.score, r.assigned_at, r.due_at, r.submitted_at,
                    (r.status = 'assigned' AND r.due_at < now()) AS overdue,
                    p.title, p.status AS proposal_status, p.requested_amount, p.currency, c.title AS call_title
               FROM reviews r
               JOIN proposals p ON p.id = r.proposal_id
               JOIN grant_calls c ON c.id = p.call_id
              WHERE r.reviewer_id = ?
              ORDER BY (r.status = 'assigned') DESC, r.due_at NULLS LAST, r.id", [$actor->id]);
    }

    /** One assignment with the proposal it covers and the reviewer's own (decrypted) comments. */
    public function myAssignment(User $actor, int $reviewId): ?array
    {
        $row = $this->read($actor, 'review.read_assigned',
            "SELECT r.id, r.status, r.score, r.comments_enc, r.assigned_at, r.due_at, r.submitted_at,
                    (r.status = 'assigned' AND r.due_at < now()) AS overdue,
                    p.id AS proposal_id, p.title, p.abstract, p.status AS proposal_status,
                    p.requested_amount, p.currency, p.submitted_at AS proposal_submitted_at,
                    c.title AS call_title, u.full_name AS applicant_name, u.department AS applicant_department
               FROM reviews r
               JOIN proposals p ON p.id = r.proposal_id
               JOIN grant_calls c ON c.id = p.call_id
               JOIN users u ON u.id = p.owner_id
              WHERE r.id = ? AND r.reviewer_id = ?", [$reviewId, $actor->id])[0] ?? null;
        if ($row === null) {
            $this->audit->standalone($actor, 'review.view', 'review', $reviewId, 'denied', ['reason' => 'not_visible']);
            return null;
        }
        $this->audit->standalone($actor, 'review.view', 'review', $reviewId, 'success', ['proposal_id' => $row['proposal_id']]);
        return $this->withComments($row);
    }

    // --------------------------------------------------------------- officer

    public function officerQueue(User $actor, string $search = ''): array
    {
        return $this->read($actor, 'proposal.read_submitted',
            "SELECT p.id, p.title, p.status, p.requested_amount, p.currency, p.submitted_at,
                    c.title AS call_title, u.full_name AS applicant_name,
                    (SELECT count(*) FROM reviews r WHERE r.proposal_id = p.id) AS reviews_assigned,
                    (SELECT count(*) FROM reviews r WHERE r.proposal_id = p.id AND r.status = 'submitted') AS reviews_done,
                    (SELECT count(*) FROM reviews r WHERE r.proposal_id = p.id AND r.status = 'assigned' AND r.due_at < now()) AS reviews_overdue
               FROM proposals p
               JOIN grant_calls c ON c.id = p.call_id
               JOIN users u ON u.id = p.owner_id
              WHERE p.status <> 'draft' AND p.title ILIKE ? ESCAPE '\\'
              ORDER BY (p.status IN ('submitted','under_review')) DESC, p.submitted_at, p.id", [self::contains($search)]);
    }

    public function calls(User $actor): array
    {
        return $this->read($actor, 'call.manage',
            "SELECT c.id, c.title, c.description, c.currency, c.total_budget, c.remaining_budget, c.closes_at, c.status,
                    c.status = 'open' AND now() < c.closes_at AS is_open,
                    (SELECT count(*) FROM proposals p WHERE p.call_id = c.id) AS proposal_count
               FROM grant_calls c ORDER BY c.closes_at DESC, c.id DESC", []);
    }

    /** Everything the decision screen shows: proposal, call balance, reviews, decision. */
    public function proposalForDecision(User $actor, int $proposalId): ?array
    {
        $p = $this->read($actor, 'proposal.read_submitted',
            "SELECT p.id, p.call_id, p.owner_id, p.title, p.abstract, p.status, p.requested_amount, p.currency, p.submitted_at,
                    c.title AS call_title, c.total_budget, c.remaining_budget,
                    u.full_name AS applicant_name, u.department AS applicant_department,
                    d.outcome, d.awarded_amount, d.rationale, d.decided_at, du.full_name AS decided_by_name
               FROM proposals p
               JOIN grant_calls c ON c.id = p.call_id
               JOIN users u ON u.id = p.owner_id
               LEFT JOIN decisions d ON d.proposal_id = p.id
               LEFT JOIN users du ON du.id = d.decided_by
              WHERE p.id = ? AND p.status <> 'draft'", [$proposalId])[0] ?? null;
        if ($p === null) {
            $this->audit->standalone($actor, 'proposal.view', 'proposal', $proposalId, 'denied', ['reason' => 'not_visible']);
            return null;
        }
        $reviews = $this->read($actor, 'proposal.read_submitted',
            "SELECT r.id, r.reviewer_id, r.status, r.score, r.comments_enc, r.assigned_at, r.due_at, r.submitted_at,
                    (r.status = 'assigned' AND r.due_at < now()) AS overdue, u.full_name AS reviewer_name
               FROM reviews r JOIN users u ON u.id = r.reviewer_id
              WHERE r.proposal_id = ? ORDER BY r.id", [$proposalId]);
        $p['reviews'] = array_map($this->withComments(...), $reviews);
        $this->audit->standalone($actor, 'proposal.view', 'proposal', $proposalId, 'success', ['with_reviews' => count($reviews)]);
        return $p;
    }

    /** Active reviewers who could still be assigned (never the applicant, never twice). */
    public function assignableReviewers(User $actor, int $proposalId, int $ownerId): array
    {
        return $this->read($actor, 'review.assign',
            "SELECT u.id, u.full_name, u.department FROM users u
              WHERE u.role = 'reviewer' AND u.is_active AND u.id <> ?
                AND NOT EXISTS (SELECT 1 FROM reviews r WHERE r.proposal_id = ? AND r.reviewer_id = u.id)
              ORDER BY u.full_name", [$ownerId, $proposalId]);
    }

    // --------------------------------------------------------------- helpers

    private function read(User $actor, string $permission, string $sql, array $args): array
    {
        if (!Policy::can($actor, $permission)) {
            return [];
        }
        return $this->db->asActor($actor->id, static function (PDO $tx) use ($sql, $args): array {
            $stmt = $tx->prepare($sql);
            $stmt->execute($args);
            return $stmt->fetchAll();
        });
    }

    /** Turn user text into a literal "contains" pattern: %, _ and \ lose their wildcard meaning. */
    private static function contains(string $search): string
    {
        return '%' . addcslashes(trim($search), '%_\\') . '%';
    }

    private function withComments(array $review): array
    {
        $review['comments'] = $review['comments_enc'] === null ? ''
            : $this->cipher->decrypt($review['comments_enc'], 'reviews.comments:' . $review['id']);
        unset($review['comments_enc']);
        return $review;
    }
}
