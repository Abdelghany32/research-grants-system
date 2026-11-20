<?php
declare(strict_types=1);

namespace App\Http\Controllers;

use App\Http\Response;

/** The signed-in user's own sign-in security: registered security keys (WebAuthn). */
final class AccountController extends Controller
{
    public function security(): Response
    {
        return $this->page('account_security', ['title' => 'Sign-in security', 'keys' => $this->app->auth()->webauthnKeys($this->user)]);
    }

    public function webauthnOptions(): Response
    {
        $options = $this->app->auth()->webauthnBeginRegister();
        return $options === null ? Response::json(['ok' => false, 'error' => 'Sign in again.'], 401) : Response::json(['ok' => true, 'options' => $options]);
    }

    public function webauthnRegister(): Response
    {
        $credential = json_decode($this->input('credential'), true, 8);
        $ok = is_array($credential) && $this->app->auth()->webauthnFinishRegister($credential, $this->input('name'));
        if ($ok) {
            $this->flash('success', 'Security key added.');
        }
        return $ok ? Response::json(['ok' => true, 'redirect' => '/account/security'])
                   : Response::json(['ok' => false, 'error' => 'The key could not be registered. Check the name and try again.'], 400);
    }

    public function webauthnDelete(int $id): Response
    {
        $ok = $this->app->auth()->webauthnDelete($id);
        $ok ? $this->flash('success', 'Security key removed.') : $this->flash('error', 'That key could not be removed. It may be your last second factor.');
        return Response::redirect('/account/security');
    }
}
