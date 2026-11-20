<?php
declare(strict_types=1);

namespace App\Http\Controllers;

use App\Grants\Denied;
use App\Grants\ValidationFailed;
use App\Http\Response;

/** Grants officer screens: queue, decision screen, grant calls. */
final class OfficerController extends Controller
{
    public function queue(): Response
    {
        $q = $this->query('q');
        $all = $this->app->queries()->officerQueue($this->user);
        return $this->page('officer/queue', [
            'title' => 'Decision queue', 'q' => $q,
            'proposals' => $q === '' ? $all : $this->app->queries()->officerQueue($this->user, $q),
            'counts' => array_count_values(array_column($all, 'status')),
        ]);
    }

    public function show(int $id): Response
    {
        return $this->decisionScreen($id, ['outcome' => '', 'awarded_amount' => '', 'rationale' => '']);
    }

    public function assign(int $id): Response
    {
        try {
            $this->app->workflow()->assignReviewer($this->user, $id, (int) $this->input('reviewer_id'), $this->input('due_at'));
            $this->flash('success', 'Reviewer assigned. The proposal is under review.');
        } catch (ValidationFailed $e) {
            return $this->decisionScreen($id, ['outcome' => '', 'awarded_amount' => '', 'rationale' => ''], $e->errors);
        } catch (Denied $e) {
            $this->flash('error', $e->getMessage());
        }
        return Response::redirect('/officer/proposals/' . $id);
    }

    /** POST /officer/reviews/{id}/extend - move a review deadline forward. */
    public function extendDeadline(int $id): Response
    {
        $proposalId = null;
        try {
            $proposalId = $this->app->workflow()->extendReviewDeadline($this->user, $id, $this->input('due_at'));
            $this->flash('success', 'Review deadline extended.');
        } catch (ValidationFailed $e) {
            $this->flash('error', implode(' ', $e->errors));
        } catch (Denied $e) {
            if ($e->reason === 'not_visible') {
                return $this->notFound();
            }
            $this->flash('error', $e->getMessage());
        }
        $back = (int) $this->input('proposal_id');
        return Response::redirect('/officer/proposals/' . ($proposalId ?? ($back > 0 ? $back : 0)));
    }

    /** POST /officer/proposals/{id}/decision - the confirm button on the decision screen. */
    public function decide(int $id): Response
    {
        $values = ['outcome' => $this->input('outcome'), 'awarded_amount' => $this->input('awarded_amount'),
                   'rationale' => $this->input('rationale')];
        try {
            $result = $this->app->workflow()->recordDecision($this->user, $id, $values['outcome'],
                $values['awarded_amount'], $values['rationale']);
        } catch (ValidationFailed $e) {
            return $this->decisionScreen($id, $values, $e->errors);
        } catch (Denied $e) {
            // Money problems are shown next to the amount field; the screen is
            // rebuilt from fresh data so the officer sees the current balance.
            $field = in_array($e->reason, ['insufficient_funds', 'exceeds_requested'], true) ? 'awarded_amount' : 'decision';
            return $this->decisionScreen($id, $values, [$field => $e->getMessage()]);
        }
        $this->flash('success', 'Decision recorded. Remaining call balance: ' . money($result['remaining']) . '.');
        return Response::redirect('/officer/proposals/' . $id);
    }

    public function calls(): Response
    {
        return $this->page('officer/calls', ['title' => 'Grant calls', 'calls' => $this->app->queries()->calls($this->user)]);
    }

    public function newCall(): Response
    {
        return $this->callForm(null, ['title' => '', 'description' => '', 'currency' => 'MAD', 'total_budget' => '',
                                      'closes_on' => '', 'status' => 'open']);
    }

    public function storeCall(): Response
    {
        $values = $this->callValues();
        try {
            $this->app->workflow()->createCall($this->user, $values);
        } catch (ValidationFailed $e) {
            return $this->callForm(null, $values, $e->errors);
        }
        $this->flash('success', 'Grant call published.');
        return Response::redirect('/officer/calls');
    }

    public function editCall(int $id): Response
    {
        $call = $this->app->queries()->call($this->user, $id);
        if ($call === null) {
            return $this->notFound();
        }
        return $this->callForm($call, $call + ['closes_on' => substr($call['closes_at'], 0, 10)]);
    }

    public function updateCall(int $id): Response
    {
        $values = $this->callValues();
        try {
            $this->app->workflow()->updateCall($this->user, $id, $values);
        } catch (ValidationFailed $e) {
            $call = $this->app->queries()->call($this->user, $id);
            return $call === null ? $this->notFound() : $this->callForm($call, $values + $call, $e->errors);
        }
        $this->flash('success', 'Grant call updated.');
        return Response::redirect('/officer/calls');
    }

    private function decisionScreen(int $id, array $values, array $errors = []): Response
    {
        $p = $this->app->queries()->proposalForDecision($this->user, $id);
        if ($p === null) {
            return $this->notFound();
        }
        $done = array_filter($p['reviews'], static fn (array $r): bool => $r['status'] === 'submitted');
        // Plain-language reason when the decision form is unavailable.
        $blocked = match (true) {
            $p['outcome'] !== null => null,
            $p['status'] === 'submitted' => 'Assign a reviewer first. A decision needs at least one completed review.',
            !$done => 'Waiting for a completed review. The decision form opens when a reviewer submits a score.',
            default => null,
        };
        return $this->page('officer/decision', [
            'title' => 'Decision: ' . $p['title'], 'p' => $p, 'values' => $values, 'errors' => $errors,
            'blocked' => $blocked, 'canDecide' => $p['outcome'] === null && $blocked === null,
            'reviewers' => $p['outcome'] === null
                ? $this->app->queries()->assignableReviewers($this->user, $id, (int) $p['owner_id']) : [],
        ], $errors ? 422 : 200);
    }

    private function callForm(?array $call, array $values, array $errors = []): Response
    {
        return $this->page('officer/call_form', [
            'title' => $call === null ? 'New grant call' : 'Edit grant call',
            'call' => $call, 'values' => $values, 'errors' => $errors,
        ], $errors ? 422 : 200);
    }

    private function callValues(): array
    {
        return ['title' => $this->input('title'), 'description' => $this->input('description'),
                'currency' => $this->input('currency'), 'total_budget' => $this->input('total_budget'),
                'closes_on' => $this->input('closes_on'), 'status' => $this->input('status') ?: 'open'];
    }
}
