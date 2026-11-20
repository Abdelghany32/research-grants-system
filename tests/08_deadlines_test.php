<?php
declare(strict_types=1);
// Requirement: review deadlines are enforced by the database; only officers extend them, only forwards.

require_once __DIR__ . '/helpers_workflow.php';

/** Create a call, a submitted proposal and a review assigned to $reviewer with the given due date; returns [proposalId, reviewId]. */
function make_assigned(string $title, string $due): array
{
    $wf = T::app()->workflow();
    $call = make_call('Deadline call ' . $title, '10000');
    $p = $wf->createDraft(T::user('amina.elidrissi'), $call, ['title' => $title, 'abstract' => str_repeat('Fictional abstract. ', 3), 'requested_amount' => '1000']);
    $wf->submitProposal(T::user('amina.elidrissi'), $p);
    $review = $wf->assignReviewer(T::user('nadia.berrada'), $p, T::user('salma.tazi')->id, $due);
    return [$p, $review];
}

test('DEADLINE a reviewer cannot save or submit after the due date (application and database)', function (): void {
    $wf = T::app()->workflow();
    $salma = T::user('salma.tazi');
    $nadia = T::user('nadia.berrada');
    $p = T::proposalId('Fixture: review past its deadline');
    $review = (int) T::sqlAs($nadia, 'SELECT id FROM reviews WHERE proposal_id = ?', [$p])['rows'][0]['id'];   // fixture: due 2 seconds after the load
    sleep(1);
    check(T::sqlAs($nadia, 'SELECT due_at < now() AS past FROM reviews WHERE id = ?', [$review])['rows'][0]['past'], 'the fixture deadline has passed');
    denied('review_overdue', fn () => $wf->saveReview($salma, $review, ['score' => '7', 'comments' => 'Too late for a draft.'], false), 'no draft after the deadline');
    denied('review_overdue', fn () => $wf->saveReview($salma, $review, ['score' => '8', 'comments' => 'Too late to submit now.'], true), 'no final review after the deadline');
    // The database refuses it on its own, whatever the application does.
    sqlstate('23514', fn () => T::sqlAs($salma, "UPDATE reviews SET status = 'submitted', score = 8 WHERE id = ?", [$review]), 'the guard trigger refuses a late submission');
    sqlstate('23514', fn () => T::sqlAs($salma, 'UPDATE reviews SET score = 9 WHERE id = ?', [$review]), 'and a late edit');
    check(count(T::audit("action = 'review.submit' AND outcome = 'denied' AND resource_id = ? AND details->>'reason' = 'review_overdue'", [$review])) >= 1, 'the refusal is audited');
    // The screens: overdue is visible to both sides, and the reviewer's form is closed.
    $b = (new Browser())->login('salma.tazi');
    check(str_contains($b->get('/reviews')->body, 'Overdue'), 'the reviewer list flags the overdue review');
    check(str_contains($b->get('/reviews/' . $review)->body, 'deadline for this review has passed'), 'the workspace explains why the form is closed');
    // An officer extends the deadline, and the reviewer can finish.
    $wf->extendReviewDeadline($nadia, $review, gmdate('Y-m-d', time() + 7 * 86400));
    $wf->saveReview($salma, $review, ['score' => '8', 'comments' => 'Submitted after the extension.'], true);
    same('submitted', T::sqlAs($nadia, 'SELECT status FROM reviews WHERE id = ?', [$review])['rows'][0]['status'], 'the review can be submitted after an extension');
});

test('DEADLINE only a grants officer can move a deadline, only forwards, and nothing else changes with it', function (): void {
    $wf = T::app()->workflow();
    $nadia = T::user('nadia.berrada');
    $salma = T::user('salma.tazi');
    [$p, $review] = make_assigned('Deadline proposal two', gmdate('Y-m-d', time() + 5 * 86400));
    $before = T::sqlAs($nadia, 'SELECT due_at FROM reviews WHERE id = ?', [$review])['rows'][0]['due_at'];

    // The reviewer cannot extend their own deadline, by raw SQL.
    sqlstate('23514', fn () => T::sqlAs($salma, "UPDATE reviews SET due_at = due_at + interval '30 days' WHERE id = ?", [$review]), 'a reviewer cannot extend');
    // An officer cannot shorten it, remove it, or edit the review in the same statement, by raw SQL.
    sqlstate('23514', fn () => T::sqlAs($nadia, "UPDATE reviews SET due_at = due_at - interval '1 day' WHERE id = ?", [$review]), 'nobody can shorten a deadline');
    sqlstate('23514', fn () => T::sqlAs($nadia, 'UPDATE reviews SET due_at = NULL WHERE id = ?', [$review]), 'nobody can remove a deadline');
    sqlstate('23514', fn () => T::sqlAs($nadia, "UPDATE reviews SET due_at = due_at + interval '1 day', score = 10 WHERE id = ?", [$review]), 'a deadline change cannot also change the review');
    sqlstate('23514', fn () => T::sqlAs($nadia, 'UPDATE reviews SET score = 1 WHERE id = ?', [$review]), 'an officer cannot edit a review');
    same($before, T::sqlAs($nadia, 'SELECT due_at FROM reviews WHERE id = ?', [$review])['rows'][0]['due_at'], 'nothing changed after the refusals');

    // The legitimate way: the workflow, audited.
    $newDate = gmdate('Y-m-d', time() + 12 * 86400);
    same($p, $wf->extendReviewDeadline($nadia, $review, $newDate), 'the officer extends through the workflow');
    check(str_starts_with(T::sqlAs($nadia, 'SELECT due_at FROM reviews WHERE id = ?', [$review])['rows'][0]['due_at'], $newDate), 'the new deadline is stored');
    same(1, count(T::audit("action = 'review.extend_deadline' AND outcome = 'success' AND resource_id = ?", [$review])), 'the extension is in the audit trail');
    $earlier = gmdate('Y-m-d', time() + 6 * 86400);
    try {
        $wf->extendReviewDeadline($nadia, $review, $earlier);
        check(false, 'an earlier date must be refused');
    } catch (App\Grants\ValidationFailed $e) {
        check(isset($e->errors['due_at']), 'an earlier date is refused with a message');
    }
    denied('role_not_permitted', fn () => $wf->extendReviewDeadline($salma, $review, gmdate('Y-m-d', time() + 20 * 86400)), 'the workflow refuses a reviewer');
    denied('role_not_permitted', fn () => $wf->extendReviewDeadline(T::user('amina.elidrissi'), $review, gmdate('Y-m-d', time() + 20 * 86400)), 'and a researcher');
    // A finalized review cannot be extended.
    $wf->saveReview($salma, $review, ['score' => '8', 'comments' => 'Final review text here.'], true);
    denied('review_closed', fn () => $wf->extendReviewDeadline($nadia, $review, gmdate('Y-m-d', time() + 30 * 86400)), 'a submitted review cannot be extended');
});

test('DEADLINE an assignment cannot be created with a deadline in the past', function (): void {
    $nadia = T::user('nadia.berrada');
    $wf = T::app()->workflow();
    $call = make_call('Past deadline call', '5000');
    $p = $wf->createDraft(T::user('youssef.benali'), $call, ['title' => 'Past deadline proposal', 'abstract' => str_repeat('Fictional abstract. ', 3), 'requested_amount' => '500']);
    $wf->submitProposal(T::user('youssef.benali'), $p);
    try {
        $wf->assignReviewer($nadia, $p, T::user('salma.tazi')->id, gmdate('Y-m-d', time() - 3 * 86400));
        check(false, 'a past deadline must be refused');
    } catch (App\Grants\ValidationFailed $e) {
        check(isset($e->errors['due_at']), 'the workflow refuses a past date');
    }
    sqlstate('23514', fn () => T::sqlAs($nadia, "INSERT INTO reviews (proposal_id, reviewer_id, assigned_by, due_at) VALUES (?, ?, ?, now() - interval '1 day')", [$p, T::user('salma.tazi')->id, $nadia->id]), 'and so does the database');
});
