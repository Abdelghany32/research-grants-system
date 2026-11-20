<?php
declare(strict_types=1);

namespace App\Http\Controllers;

use App\Auth\LoginThrottled;
use App\Auth\MfaChallenge;
use App\Auth\Policy;
use App\Http\Response;

final class AuthController extends Controller
{
    public function home(): Response
    {
        return Response::redirect($this->user === null ? '/login' : Policy::HOME[$this->user->role]);
    }

    public function showLogin(): Response
    {
        if ($this->user !== null) {
            return $this->home();
        }
        return $this->page('login', ['title' => 'Sign in', 'email' => '']);
    }

    public function login(): Response
    {
        $email = $this->input('email');
        try {
            $user = $this->app->auth()->login($email, $this->input('password'));
        } catch (LoginThrottled $e) {
            // Depends only on the caller's own address: it says nothing about any account.
            if (!headers_sent()) {
                header('Retry-After: ' . $e->retryAfterSeconds);
            }
            return $this->page('login', [
                'title' => 'Sign in', 'email' => $email,
                'errors' => ['login' => 'Too many failed attempts from this network address. Wait a few minutes and try again.'],
            ], 429);
        }
        if ($user === null) {
            // One message for every failure: unknown account, wrong password,
            // disabled or locked. The real reason is in the audit log only.
            return $this->page('login', [
                'title' => 'Sign in', 'email' => $email,
                'errors' => ['login' => 'The e-mail or password is incorrect, or the account is temporarily locked.'],
            ], 401);
        }
        if ($user instanceof MfaChallenge) {
            return Response::redirect('/login/mfa');         // password right; the second factor is still owed
        }
        return Response::redirect(Policy::HOME[$user->role]);
    }

    /** GET /login/mfa - ask for the code, or (first sign-in of an officer or auditor) enrol an authenticator app. */
    public function showMfa(): Response
    {
        if ($this->user !== null) {
            return $this->home();
        }
        $pending = $this->app->auth()->pendingMfaUser();
        if ($pending === null) {
            return Response::redirect('/login');
        }
        return $this->mfaPage($pending, $this->query('recovery') === '1');
    }

    /** POST /login/mfa - verify the code (or a recovery code); on first use, finish the enrolment. */
    public function verifyMfa(): Response
    {
        $auth = $this->app->auth();
        $pending = $auth->pendingMfaUser();
        if ($pending === null) {
            return Response::redirect('/login');
        }
        $enrolled = $auth->mfaEnrolled($pending);
        $recovery = $enrolled && $this->input('mode') === 'recovery';
        try {
            if (!$enrolled) {
                $done = $auth->enrollMfa($this->input('code'));
                if ($done !== null) {
                    // Shown once, in this response only: the codes exist nowhere else in clear.
                    return $this->page('login_mfa_codes', ['title' => 'Save your recovery codes', 'codes' => $done['recovery'], 'user' => $done['user']]);
                }
            } else {
                $user = $auth->completeMfa($recovery ? $this->input('recovery_code') : $this->input('code'), $recovery);
                if ($user !== null) {
                    return Response::redirect(Policy::HOME[$user->role]);
                }
            }
        } catch (LoginThrottled $e) {
            if (!headers_sent()) {
                header('Retry-After: ' . $e->retryAfterSeconds);
            }
            return $this->page('login', ['title' => 'Sign in', 'email' => '', 'errors' => ['login' => 'Too many failed attempts from this network address. Wait a few minutes and try again.']], 429);
        }
        if ($auth->pendingMfaUser() === null) {
            return $this->page('login', ['title' => 'Sign in', 'email' => '', 'errors' => ['login' => 'Too many wrong codes. Start again with your e-mail and password.']], 401);
        }
        return $this->mfaPage($pending, $recovery, ['code' => $recovery ? 'That recovery code is not valid.' : 'That code is not valid. Check the time on your phone and try the next code.'], 401);
    }

    private function mfaPage($pending, bool $recovery, array $errors = [], int $status = 200): Response
    {
        $auth = $this->app->auth();
        $enrolled = $auth->mfaEnrolled($pending);
        $data = ['title' => $enrolled ? 'Second factor' : 'Set up two-step sign-in', 'pending' => $pending, 'enrolled' => $enrolled,
                 'recovery' => $recovery, 'errors' => $errors, 'hasKeys' => $auth->pendingHasKeys()];
        if (!$enrolled) {
            $data += ['secret' => $auth->mfaEnrollmentSecret(), 'uri' => $auth->mfaUri($pending)];
        }
        return $this->page('login_mfa', $data, $status);
    }

    /** POST /login/webauthn/options - the challenge for the user's registered keys. */
    public function webauthnOptions(): Response
    {
        try {
            $options = $this->app->auth()->webauthnBeginLogin();
        } catch (LoginThrottled) {
            return Response::json(['ok' => false, 'error' => 'Too many failed attempts. Wait a few minutes.'], 429);
        }
        return $options === null ? Response::json(['ok' => false, 'error' => 'No security key is available for this sign-in.'], 400)
                                 : Response::json(['ok' => true, 'options' => $options]);
    }

    /** POST /login/webauthn/verify - check the signed challenge; on success the sign-in is complete. */
    public function webauthnVerify(): Response
    {
        $credential = json_decode($this->input('credential'), true, 8);
        try {
            $user = is_array($credential) ? $this->app->auth()->webauthnFinishLogin($credential) : null;
        } catch (LoginThrottled) {
            return Response::json(['ok' => false, 'error' => 'Too many failed attempts. Wait a few minutes.'], 429);
        }
        if ($user === null) {
            return Response::json(['ok' => false, 'error' => 'The security key was not accepted. Try again or use another method.'], 401);
        }
        return Response::json(['ok' => true, 'redirect' => Policy::HOME[$user->role]]);
    }

    public function logout(): Response
    {
        $this->app->auth()->logout();
        return Response::redirect('/login');
    }
}
