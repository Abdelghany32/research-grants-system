<?php
declare(strict_types=1);

namespace App\Http\Controllers;

use App\Grants\Denied;
use App\Grants\ValidationFailed;
use App\Http\Response;

/** Researcher screens: inbox, proposal form, proposal detail. */
final class ProposalController extends Controller
{
    public function inbox(): Response
    {
        $q = $this->query('q');
        $all = $this->app->queries()->myProposals($this->user);
        $shown = $q === '' ? $all : $this->app->queries()->myProposals($this->user, $q);
        return $this->page('researcher/inbox', [
            'title' => 'My proposals',
            'calls' => $this->app->queries()->openCalls($this->user),
            'proposals' => $shown,
            'q' => $q,
            // Counts come from the same permitted rows that are listed.
            'counts' => array_count_values(array_column($all, 'status')),
        ]);
    }

    public function create(): Response
    {
        $call = $this->app->queries()->call($this->user, (int) $this->query('call'));
        if ($call === null || !$call['is_open']) {
            $this->flash('error', 'That call is not open for proposals.');
            return Response::redirect('/proposals');
        }
        return $this->form($call, null, ['title' => '', 'abstract' => '', 'requested_amount' => '']);
    }

    /** POST /proposals - "Save draft" or "Submit proposal" on a new proposal. */
    public function store(): Response
    {
        $callId = (int) $this->input('call_id');
        $values = $this->formValues();
        try {
            $id = $this->app->workflow()->createDraft($this->user, $callId, $values);
        } catch (ValidationFailed $e) {
            $call = $this->app->queries()->call($this->user, $callId);
            return $call === null ? $this->notFound() : $this->form($call, null, $values, $e->errors);
        } catch (Denied $e) {
            $this->flash('error', $e->getMessage());
            return Response::redirect('/proposals');
        }
        return $this->input('intent') === 'submit' ? $this->submit($id) : $this->saved($id);
    }

    public function show(int $id): Response
    {
        $p = $this->app->queries()->myProposal($this->user, $id);
        if ($p === null) {
            return $this->notFound();
        }
        if ($p['status'] === 'draft') {
            $call = ['id' => $p['call_id'], 'title' => $p['call_title'], 'closes_at' => $p['closes_at'],
                     'currency' => $p['currency'], 'total_budget' => $p['total_budget'], 'is_open' => $p['call_open']];
            return $this->form($call, $p, $p);
        }
        return $this->page('researcher/show', ['title' => $p['title'], 'p' => $p]);
    }

    /** POST /proposals/{id} - "Save draft" or "Submit proposal" on an existing draft. */
    public function update(int $id): Response
    {
        $values = $this->formValues();
        try {
            $this->app->workflow()->updateDraft($this->user, $id, $values);
        } catch (ValidationFailed $e) {
            return $this->redisplay($id, $values, $e->errors);
        }
        return $this->input('intent') === 'submit' ? $this->submit($id) : $this->saved($id);
    }

    public function delete(int $id): Response
    {
        $this->app->workflow()->deleteDraft($this->user, $id);
        $this->flash('success', 'Draft deleted.');
        return Response::redirect('/proposals');
    }

    private function submit(int $id): Response
    {
        try {
            $this->app->workflow()->submitProposal($this->user, $id);
        } catch (ValidationFailed $e) {
            // The draft itself was saved; only the submission is refused.
            return $this->redisplay($id, $this->formValues(), $e->errors);
        } catch (Denied $e) {
            $this->flash('error', $e->getMessage() . ' Your draft was saved.');
            return Response::redirect('/proposals/' . $id);
        }
        $this->flash('success', 'Proposal submitted. The research office will assign a reviewer.');
        return Response::redirect('/proposals/' . $id);
    }

    private function saved(int $id): Response
    {
        $this->flash('success', 'Draft saved. It is not submitted yet.');
        return Response::redirect('/proposals/' . $id);
    }

    private function redisplay(int $id, array $values, array $errors): Response
    {
        $p = $this->app->queries()->myProposal($this->user, $id);
        if ($p === null) {
            return $this->notFound();
        }
        $call = ['id' => $p['call_id'], 'title' => $p['call_title'], 'closes_at' => $p['closes_at'],
                 'currency' => $p['currency'], 'total_budget' => $p['total_budget'], 'is_open' => $p['call_open']];
        return $this->form($call, $p, $values, $errors);
    }

    private function form(array $call, ?array $proposal, array $values, array $errors = []): Response
    {
        return $this->page('researcher/form', [
            'title' => $proposal === null ? 'New proposal' : 'Edit draft',
            'call' => $call, 'proposal' => $proposal, 'values' => $values, 'errors' => $errors,
        ], $errors ? 422 : 200);
    }

    private function formValues(): array
    {
        return ['title' => $this->input('title'), 'abstract' => $this->input('abstract'),
                'requested_amount' => $this->input('requested_amount')];
    }
}
