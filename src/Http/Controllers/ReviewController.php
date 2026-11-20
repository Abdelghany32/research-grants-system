<?php
declare(strict_types=1);

namespace App\Http\Controllers;

use App\Grants\ValidationFailed;
use App\Http\Response;

/** Reviewer screens: assignment list and review workspace. */
final class ReviewController extends Controller
{
    public function index(): Response
    {
        $rows = $this->app->queries()->myAssignments($this->user);
        return $this->page('reviewer/list', [
            'title' => 'My reviews', 'assignments' => $rows,
            'counts' => array_count_values(array_column($rows, 'status')),
        ]);
    }

    public function show(int $id): Response
    {
        $r = $this->app->queries()->myAssignment($this->user, $id);
        if ($r === null) {
            return $this->notFound();
        }
        return $this->workspace($r, ['score' => (string) ($r['score'] ?? ''), 'comments' => $r['comments']]);
    }

    /** POST /reviews/{id} - "Save draft" or "Submit final review". */
    public function save(int $id): Response
    {
        $values = ['score' => $this->input('score'), 'comments' => $this->input('comments')];
        $final = $this->input('intent') === 'submit';
        try {
            $this->app->workflow()->saveReview($this->user, $id, $values, $final);
        } catch (ValidationFailed $e) {
            $r = $this->app->queries()->myAssignment($this->user, $id);
            return $r === null ? $this->notFound() : $this->workspace($r, $values, $e->errors);
        }
        $this->flash('success', $final ? 'Review submitted. It can no longer be changed.' : 'Draft review saved. It is not submitted yet.');
        return Response::redirect('/reviews/' . $id);
    }

    private function workspace(array $review, array $values, array $errors = []): Response
    {
        return $this->page('reviewer/workspace', [
            'title' => 'Review: ' . $review['title'], 'r' => $review, 'values' => $values, 'errors' => $errors,
        ], $errors ? 422 : 200);
    }
}
