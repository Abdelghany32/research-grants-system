<?php
declare(strict_types=1);

namespace App\Http\Controllers;

use App\App;
use App\Auth\User;
use App\Http\Kernel;
use App\Http\Response;
use App\Http\View;

abstract class Controller
{
    public function __construct(protected readonly App $app, protected readonly ?User $user)
    {
    }

    protected function page(string $template, array $data, int $status = 200): Response
    {
        return Response::html(View::page($template, $data + [
            'app' => $this->app, 'user' => $this->user, 'errors' => [],
            'flash' => $this->app->session()->pull('flash'),
        ]), $status);
    }

    protected function flash(string $kind, string $message): void
    {
        $this->app->session()->set('flash', ['kind' => $kind, 'message' => $message]);
    }

    protected function notFound(): Response
    {
        return Kernel::error($this->app, $this->user, 404, 'Not found',
            'This record does not exist or you do not have access to it.');
    }

    /** POST field as a string (arrays and missing values become ''). */
    protected function input(string $name): string
    {
        $v = $_POST[$name] ?? '';
        return is_string($v) ? $v : '';
    }

    protected function query(string $name): string
    {
        $v = $_GET[$name] ?? '';
        return is_string($v) ? trim($v) : '';
    }
}
