<?php
declare(strict_types=1);

/** Create a call with the given budget, as the officer. */
function make_call(string $title, string $budget): int
{
    return T::app()->workflow()->createCall(T::user('nadia.berrada'), [
        'title' => $title, 'currency' => 'MAD', 'total_budget' => $budget, 'closes_on' => gmdate('Y-m-d', time() + 30 * 86400)]);
}

/** Take a new proposal through submit -> assign -> final review, ready for a decision. */
function make_reviewed_proposal(int $callId, string $owner, string $title, string $amount, string $reviewer = 'salma.tazi'): int
{
    $wf = T::app()->workflow();
    $id = $wf->createDraft(T::user($owner), $callId, ['title' => $title, 'abstract' => str_repeat('Fictional abstract. ', 3), 'requested_amount' => $amount]);
    $wf->submitProposal(T::user($owner), $id);
    $reviewId = $wf->assignReviewer(T::user('nadia.berrada'), $id, T::user($reviewer)->id, null);
    $wf->saveReview(T::user($reviewer), $reviewId, ['score' => '8', 'comments' => 'Solid fictional proposal.'], true);
    return $id;
}

function call_balance(int $callId): string
{
    return T::sqlAs(T::user('nadia.berrada'), 'SELECT remaining_budget FROM grant_calls WHERE id = ?', [$callId])['rows'][0]['remaining_budget'];
}

/** Start tests/workers/award.php as a separate OS process with its own database connection. */
function start_award_worker(int $proposalId, string $amount, float $startAt = 0.0)
{
    $process = proc_open(['php', __DIR__ . '/workers/award.php', (string) $proposalId, $amount, (string) $startAt],
        [['file', '/dev/null', 'r'], ['pipe', 'w'], ['pipe', 'w']], $pipes);
    return ['process' => $process, 'pipes' => $pipes];   // keep the handle: dropping it closes the pipes
}

function worker_result(array $worker): array
{
    $out = stream_get_contents($worker['pipes'][1]);
    $err = stream_get_contents($worker['pipes'][2]);
    $json = json_decode((string) $out, true);
    if (!is_array($json)) {
        throw new RuntimeException("worker failed: $out $err");
    }
    return $json;
}
