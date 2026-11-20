<?php
declare(strict_types=1);
// Requirement: workflow Draft -> Submitted -> Under review -> Approved | Declined,
// with ownership, state and confidentiality rules enforced twice (PHP + PostgreSQL).
require_once __DIR__ . '/helpers_workflow.php';

test('FLOW one grant end to end, with each boundary checked on the way', function (): void {
    $wf = T::app()->workflow();
    $amina = T::user('amina.elidrissi'); $youssef = T::user('youssef.benali');
    $salma = T::user('salma.tazi'); $nadia = T::user('nadia.berrada');
    $call = make_call('Flow test call', '50000');

    // Draft: only the author can edit.
    $p = $wf->createDraft($amina, $call, ['title' => 'End-to-end flow proposal', 'abstract' => '', 'requested_amount' => '20000']);
    $wf->updateDraft($amina, $p, ['title' => 'End-to-end flow proposal (edited)', 'abstract' => 'A fictional abstract long enough to submit.', 'requested_amount' => '20000.50']);
    denied('not_visible', fn () => $wf->updateDraft($youssef, $p, ['title' => 'Hijacked', 'requested_amount' => '1']), 'another researcher cannot edit the draft');
    denied('not_visible', fn () => $wf->submitProposal($youssef, $p), 'another researcher cannot submit it');
    denied('not_assignable', fn () => $wf->assignReviewer($nadia, $p, $salma->id, null), 'a draft cannot be sent to review');

    // Submit: content freezes.
    $wf->submitProposal($amina, $p);
    denied('not_a_draft', fn () => $wf->submitProposal($amina, $p), 'second submit (double click) is refused');
    denied('not_a_draft', fn () => $wf->updateDraft($amina, $p, ['title' => 'Late edit', 'requested_amount' => '1']), 'submitted proposal cannot be edited');
    denied('not_own_draft', fn () => $wf->deleteDraft($amina, $p), 'submitted proposal cannot be deleted');
    same(0, T::sqlAs($amina, "UPDATE proposals SET title = 'Late edit by SQL' WHERE id = ?", [$p])['affected'], 'database also refuses the edit');

    // Decision needs a completed review.
    denied('not_under_review', fn () => $wf->recordDecision($nadia, $p, 'approved', '100', ''), 'no decision before review');
    $review = $wf->assignReviewer($nadia, $p, $salma->id, gmdate('Y-m-d', time() + 7 * 86400));
    same('under_review', T::sqlAs($nadia, 'SELECT status FROM proposals WHERE id = ?', [$p])['rows'][0]['status'], 'assignment moves it to under review');
    denied('already_assigned', fn () => $wf->assignReviewer($nadia, $p, $salma->id, null), 'same reviewer cannot be assigned twice');
    denied('review_missing', fn () => $wf->recordDecision($nadia, $p, 'approved', '100', ''), 'assigned but unfinished review is not enough');

    // Review: draft, then final and frozen.
    $wf->saveReview($salma, $review, ['score' => '6', 'comments' => 'First impressions.'], false);
    $wf->saveReview($salma, $review, ['score' => '9', 'comments' => 'Confidential: excellent team, fund it.'], true);
    denied('review_finalized', fn () => $wf->saveReview($salma, $review, ['score' => '2', 'comments' => 'Changed my mind entirely.'], true), 'final review cannot be edited');
    same(0, T::sqlAs($salma, 'UPDATE reviews SET score = 2 WHERE id = ?', [$review])['affected'], 'database hides the finalized review from UPDATE');
    same(0, T::sqlAs($nadia, 'UPDATE reviews SET score = 10 WHERE id = ?', [$review])['affected'], 'officer cannot alter the reviewer\'s score');

    // Decision.
    $r = $wf->recordDecision($nadia, $p, 'approved', '15000', 'Approved at a reduced amount.');
    same('35000.00', $r['remaining'], 'balance after award');
    same('9', (string) T::sqlAs($nadia, 'SELECT score FROM reviews WHERE id = ?', [$review])['rows'][0]['score'], 'original score preserved');
    denied('already_decided', fn () => $wf->recordDecision($nadia, $p, 'declined', '', ''), 'decision is final');
    denied('not_assignable', fn () => $wf->assignReviewer($nadia, $p, T::user('karim.ouazzani')->id, null), 'no assignment after the decision');

    // The applicant sees the outcome, never the review.
    $mine = T::app()->queries()->myProposal($amina, $p);
    same(['approved', '15000.00', 'Approved at a reduced amount.'], [$mine['outcome'], $mine['awarded_amount'], $mine['rationale']], 'applicant sees the decision');
    $html = (new Browser())->login('amina.elidrissi')->get('/proposals/' . $p)->body;
    check(str_contains($html, 'Approved') && str_contains($html, '15,000.00'), 'decision shown on the applicant page');
    check(!str_contains($html, 'excellent team') && !str_contains($html, '9 / 10'), 'confidential review not shown to the applicant');

    $actions = array_column(T::audit("resource_type = 'proposal' AND resource_id = ? AND outcome = 'success' AND action <> 'proposal.view'", [$p]), 'action');
    same(['proposal.create', 'proposal.update', 'proposal.submit', 'review.assign', 'decision.record'], $actions, 'audit trail tells the same story');
});

test('FLOW the same journey works through the web forms', function (): void {
    $call = make_call('Web form call', '9000');
    $researcher = (new Browser())->login('youssef.benali');
    $researcher->get('/proposals/new?call=' . $call);
    $r = $researcher->post('/proposals', ['call_id' => $call, 'title' => 'x', 'abstract' => 'kept text', 'requested_amount' => 'abc', 'intent' => 'save']);
    same(422, $r->status, 'invalid form is redisplayed');
    check(str_contains($r->body, 'kept text') && str_contains($r->body, 'value="abc"'), 'entered values are preserved');
    check(str_contains($r->body, 'id="title-error"') && str_contains($r->body, 'id="requested_amount-error"'), 'errors appear next to both fields');
    $r = $researcher->post('/proposals', ['call_id' => $call, 'title' => 'Web form proposal', 'abstract' => 'A fictional abstract that is long enough.', 'requested_amount' => '4,000.00', 'intent' => 'submit']);
    same(303, $r->status, 'valid submission redirects');
    $p = (int) basename($r->location);

    $officer = (new Browser())->login('nadia.berrada');
    $page = $officer->get('/officer/proposals/' . $p);
    check(str_contains($page->body, 'Assign a reviewer first'), 'unavailable decision is explained in plain language');
    check(!str_contains($page->body, 'id="decision-form"'), 'decision form is not offered yet');
    same(303, $officer->post("/officer/proposals/$p/assign", ['reviewer_id' => T::user('karim.ouazzani')->id, 'due_at' => ''])->status, 'assign');
    check(str_contains($officer->get('/officer/proposals/' . $p)->body, 'Waiting for a completed review'), 'still explained while the review is pending');

    $reviewer = (new Browser())->login('karim.ouazzani');
    $reviewId = (int) T::sqlAs(T::user('karim.ouazzani'), 'SELECT id FROM reviews WHERE proposal_id = ?', [$p])['rows'][0]['id'];
    $reviewer->get('/reviews/' . $reviewId);
    same(422, $reviewer->post('/reviews/' . $reviewId, ['score' => '11', 'comments' => 'Too high a score.', 'intent' => 'submit'])->status, 'score out of range');
    same(303, $reviewer->post('/reviews/' . $reviewId, ['score' => '7', 'comments' => 'Reasonable pilot study.', 'intent' => 'submit'])->status, 'final review');
    same(403, $reviewer->post('/reviews/' . $reviewId, ['score' => '1', 'comments' => 'Second thoughts here.', 'intent' => 'submit'])->status, 'edit after final is refused');

    $page = $officer->get('/officer/proposals/' . $p);
    check(str_contains($page->body, 'id="decision-form"') && str_contains($page->body, '7 / 10'), 'decision form and score now shown');
    $r = $officer->post("/officer/proposals/$p/decision", ['outcome' => 'approved', 'awarded_amount' => '9500', 'rationale' => '']);
    same(422, $r->status, 'award above the request is refused');
    check(str_contains($r->body, 'cannot exceed the requested amount') && str_contains($r->body, 'value="9500"'), 'reason shown at the field, value kept');
    same(303, $officer->post("/officer/proposals/$p/decision", ['outcome' => 'approved', 'awarded_amount' => '4000', 'rationale' => 'Funded.'])->status, 'decision recorded');
    same('5000.00', call_balance($call), 'balance after the web decision');
    $again = $officer->post("/officer/proposals/$p/decision", ['outcome' => 'approved', 'awarded_amount' => '4000', 'rationale' => '']);
    same(422, $again->status, 'repeated confirmation is refused');
    same('5000.00', call_balance($call), 'balance unchanged by the repeat');
});

test('FLOW submission is refused after the deadline (PHP and PostgreSQL)', function (): void {
    $amina = T::user('amina.elidrissi');
    $draft = T::proposalId('Fixture: draft in an expired call');
    denied('deadline_passed', fn () => T::app()->workflow()->submitProposal($amina, $draft), 'workflow refuses late submission');
    sqlstate('23514', fn () => T::sqlAs($amina, "UPDATE proposals SET status = 'submitted' WHERE id = ?", [$draft]), 'trigger refuses late submission');
    $expired = (int) T::sqlAs($amina, "SELECT id FROM grant_calls WHERE title = 'Fixture: expired call'")['rows'][0]['id'];
    denied('call_not_open', fn () => T::app()->workflow()->createDraft($amina, $expired, ['title' => 'Too late', 'requested_amount' => '10']), 'no new draft in a closed call');
    check(!in_array($expired, array_column(T::app()->queries()->openCalls($amina), 'id'), true), 'expired call is not listed as open');
});

test('FLOW self-review is blocked (PHP and PostgreSQL)', function (): void {
    $nadia = T::user('nadia.berrada');
    $rachid = T::user('rachid.fixture');                       // submitted a proposal, later became a reviewer
    $own = T::proposalId('Fixture: proposal by a future reviewer');
    denied('self_review', fn () => T::app()->workflow()->assignReviewer($nadia, $own, $rachid->id, null), 'workflow blocks self-review');
    sqlstate('23514', fn () => T::sqlAs($nadia, 'INSERT INTO reviews (proposal_id, reviewer_id, assigned_by) VALUES (?, ?, ?)', [$own, $rachid->id, $nadia->id]), 'trigger blocks self-review');
    check(!in_array($rachid->id, array_column(T::app()->queries()->assignableReviewers($nadia, $own, $rachid->id), 'id'), true), 'applicant is not offered in the reviewer list');
    denied('not_a_reviewer', fn () => T::app()->workflow()->assignReviewer($nadia, $own, T::user('amina.elidrissi')->id, null), 'a non-reviewer cannot be assigned');
});

test('FLOW illegal state changes are refused by the database itself', function (): void {
    $nadia = T::user('nadia.berrada');
    $waiting = T::proposalId('Solar-Powered Desalination');        // submitted
    $inReview = T::proposalId('Seismic Retrofitting');             // under review, review pending
    sqlstate('23514', fn () => T::sqlAs($nadia, "UPDATE proposals SET status = 'approved' WHERE id = ?", [$inReview]), 'approved without a decision row');
    sqlstate('23514', fn () => T::sqlAs($nadia, "UPDATE proposals SET status = 'approved' WHERE id = ?", [$waiting]), 'submitted cannot jump to approved');
    // Finding F01: the runtime account cannot insert decisions at all; the only door is record_decision().
    foreach ([[$inReview, 'approved', 10, 'MAD'], [$inReview, 'declined', 10, 'MAD'], [T::proposalId('Federated Learning'), 'declined', 0, 'EUR']] as [$id, $outcome, $amount, $currency]) {
        sqlstate('42501', fn () => T::sqlAs($nadia, 'INSERT INTO decisions (proposal_id, outcome, awarded_amount, currency, decided_by) VALUES (?, ?, ?, ?, ?)', [$id, $outcome, $amount, $currency, $nadia->id]), "direct INSERT of a $outcome decision is refused by privileges");
    }
    // The same illegal requests through the only permitted door are refused by the function.
    denied('review_missing', fn () => T::app()->workflow()->recordDecision($nadia, $inReview, 'approved', '10', ''), 'decision without a completed review');
    denied('not_under_review', fn () => T::app()->workflow()->recordDecision($nadia, $waiting, 'approved', '10', ''), 'decision on a proposal that is only submitted');
    $guards = T::rawRuntime()->query("SELECT string_agg(tgname, ',' ORDER BY tgname) FROM pg_trigger WHERE NOT tgisinternal AND tgenabled = 'O' AND tgname IN ('decisions_guard','grant_calls_guard','proposals_guard','reviews_guard','audit_events_no_change','audit_events_no_truncate')")->fetchColumn();
    same('audit_events_no_change,audit_events_no_truncate,decisions_guard,grant_calls_guard,proposals_guard,reviews_guard', $guards, 'the database guard triggers are all enabled (they are exercised as the schema owner by tests/owner_guards.sql)');
});

test('DATA review comments are encrypted at rest and bound to their row', function (): void {
    $nadia = T::user('nadia.berrada');
    $p1 = T::proposalId('Federated Learning');
    $row = T::sqlAs($nadia, 'SELECT id, comments_enc FROM reviews WHERE proposal_id = ?', [$p1])['rows'][0];
    check(preg_match('/^v2:[a-z0-9]+:/', $row['comments_enc']) === 1, 'stored value is versioned ciphertext that names its key');
    check(!str_contains($row['comments_enc'], 'threat model') && !str_contains(base64_decode(substr($row['comments_enc'], strrpos($row['comments_enc'], ':') + 1)), 'threat model'), 'plaintext is not in the database value');
    $cipher = T::app()->cipher();
    check(str_contains($cipher->decrypt($row['comments_enc'], 'reviews.comments:' . $row['id']), 'threat model'), 'authorized decryption with the key works');
    try {
        $cipher->decrypt($row['comments_enc'], 'reviews.comments:' . ($row['id'] + 1));
        check(false, 'ciphertext moved to another row must not decrypt');
    } catch (RuntimeException $e) {
        check(str_contains($e->getMessage(), 'failed authentication'), 'ciphertext moved to another row is rejected');
    }
    check($cipher->encrypt('same text', 'ctx') !== $cipher->encrypt('same text', 'ctx'), 'a fresh nonce is used every time');
    check(str_contains(T::app()->queries()->proposalForDecision($nadia, $p1)['reviews'][0]['comments'], 'threat model'), 'officer screen shows decrypted comments');
});

test('DATA key management: key ids, rotation without a flag day, legacy values, tampered headers', function (): void {
    $dir = sys_get_temp_dir() . '/keyring-' . bin2hex(random_bytes(4));
    mkdir($dir, 0700);
    $key = static fn () => base64_encode(random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES));
    [$k1, $k2] = [$key(), $key()];

    // 1. A legacy single-line file is key "k1" and still reads values written in the original v1 format.
    file_put_contents("$dir/legacy", "$k1\n");
    $legacy = App\Security\FieldCipher::fromKeyFile("$dir/legacy");
    same('k1', $legacy->activeKeyId(), 'legacy file = key k1');
    $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
    $v1 = 'v1:' . base64_encode($nonce . sodium_crypto_aead_xchacha20poly1305_ietf_encrypt('old comment', 'reviews.comments:7', $nonce, base64_decode($k1)));
    same('old comment', $legacy->decrypt($v1, 'reviews.comments:7'), 'v1 value decrypts');
    $v2old = $legacy->encrypt('written under k1', 'reviews.comments:7');
    check(str_starts_with($v2old, 'v2:k1:'), 'new values name their key');
    same('k1', App\Security\FieldCipher::keyIdOf($v1), 'v1 values report key k1');
    same('k1', App\Security\FieldCipher::keyIdOf($v2old), 'v2 values report their key');

    // 2. Rotation: add k2 as the FIRST line. New writes use k2, old values still decrypt.
    file_put_contents("$dir/ring", "k2:$k2\nk1:$k1\n");
    $ring = App\Security\FieldCipher::fromKeyFile("$dir/ring");
    same('k2', $ring->activeKeyId(), 'the first line is the active key');
    same(['k2', 'k1'], $ring->keyIds(), 'both keys are loaded');
    $new = $ring->encrypt('written under k2', 'reviews.comments:7');
    check(str_starts_with($new, 'v2:k2:'), 'new values use the new key');
    same('written under k1', $ring->decrypt($v2old, 'reviews.comments:7'), 'values written under the old key still decrypt');
    same('old comment', $ring->decrypt($v1, 'reviews.comments:7'), 'legacy values still decrypt');

    // 3. Retirement: a keyring without k1 cannot read k1 values - which is why retirement waits for zero rows.
    file_put_contents("$dir/new-only", "k2:$k2\n");
    $only = App\Security\FieldCipher::fromKeyFile("$dir/new-only");
    try {
        $only->decrypt($v2old, 'reviews.comments:7');
        check(false, 'a retired key cannot decrypt');
    } catch (RuntimeException $e) {
        check(str_contains($e->getMessage(), "not in the keyring"), 'the error names the missing key');
    }

    // 4. The header is authenticated: relabelling a ciphertext with another key id, or another row, fails.
    $relabelled = preg_replace('/^v2:k2:/', 'v2:k1:', $new);
    foreach ([[$relabelled, 'reviews.comments:7', 'relabelled key id'], [$new, 'reviews.comments:8', 'another row']] as [$value, $ctx, $what]) {
        try {
            $ring->decrypt($value, $ctx);
            check(false, "$what must not decrypt");
        } catch (RuntimeException $e) {
            check(str_contains($e->getMessage(), 'failed authentication'), "$what is rejected");
        }
    }

    // 5. Malformed keyrings are refused (short key, duplicate id, bad id, empty file).
    foreach (["k1:" . base64_encode('short') . "\n", "k1:$k1\nk1:$k2\n", "BAD ID:$k1\n", "# only a comment\n"] as $i => $bad) {
        file_put_contents("$dir/bad$i", $bad);
        try {
            App\Security\FieldCipher::fromKeyFile("$dir/bad$i");
            check(false, "malformed keyring $i must be refused");
        } catch (RuntimeException $e) {
            check(true, "malformed keyring $i refused");
        }
    }
    array_map('unlink', glob("$dir/*"));
    rmdir($dir);
});
