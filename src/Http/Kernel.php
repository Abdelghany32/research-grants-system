<?php
declare(strict_types=1);

namespace App\Http;

use App\App;
use App\Auth\Csrf;
use App\Auth\Policy;
use App\Auth\User;
use App\Grants\Denied;
use App\Http\Controllers\AuditController;
use App\Http\Controllers\AccountController;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\OfficerController;
use App\Http\Controllers\ProposalController;
use App\Http\Controllers\ReviewController;
use Throwable;

/**
 * The single path every request takes:
 *   headers -> session -> route -> CSRF (POST) -> login -> permission -> controller
 * Follow a button: its form action is a row in ROUTES, which names the
 * permission and the controller method, which calls one GrantWorkflow operation.
 */
final class Kernel
{
    // [method, path pattern, required permission (null = public), controller, method]
    private const ROUTES = [
        ['GET',  '/login',                          null,                       AuthController::class,     'showLogin'],
        ['POST', '/login',                          null,                       AuthController::class,     'login'],
        ['GET',  '/login/mfa',                      null,                       AuthController::class,     'showMfa'],
        ['POST', '/login/mfa',                      null,                       AuthController::class,     'verifyMfa'],
        ['POST', '/login/webauthn/options',         null,                       AuthController::class,     'webauthnOptions'],
        ['POST', '/login/webauthn/verify',          null,                       AuthController::class,     'webauthnVerify'],
        ['POST', '/logout',                         null,                       AuthController::class,     'logout'],
        ['GET',  '/',                               null,                       AuthController::class,     'home'],

        ['GET',  '/proposals',                      'proposal.read_own',        ProposalController::class, 'inbox'],
        ['GET',  '/proposals/new',                  'proposal.write_own_draft', ProposalController::class, 'create'],
        ['POST', '/proposals',                      'proposal.write_own_draft', ProposalController::class, 'store'],
        ['GET',  '/proposals/{id}',                 'proposal.read_own',        ProposalController::class, 'show'],
        ['POST', '/proposals/{id}',                 'proposal.write_own_draft', ProposalController::class, 'update'],
        ['POST', '/proposals/{id}/delete',          'proposal.write_own_draft', ProposalController::class, 'delete'],

        ['GET',  '/reviews',                        'review.read_assigned',     ReviewController::class,   'index'],
        ['GET',  '/reviews/{id}',                   'review.read_assigned',     ReviewController::class,   'show'],
        ['POST', '/reviews/{id}',                   'review.write_assigned',    ReviewController::class,   'save'],

        ['GET',  '/officer',                        'proposal.read_submitted',  OfficerController::class,  'queue'],
        ['GET',  '/officer/proposals/{id}',         'proposal.read_submitted',  OfficerController::class,  'show'],
        ['POST', '/officer/proposals/{id}/assign',  'review.assign',            OfficerController::class,  'assign'],
        ['POST', '/officer/proposals/{id}/decision', 'decision.record',         OfficerController::class,  'decide'],
        ['POST', '/officer/reviews/{id}/extend',    'review.assign',            OfficerController::class,  'extendDeadline'],
        ['GET',  '/officer/calls',                  'call.manage',              OfficerController::class,  'calls'],
        ['GET',  '/officer/calls/new',              'call.manage',              OfficerController::class,  'newCall'],
        ['POST', '/officer/calls',                  'call.manage',              OfficerController::class,  'storeCall'],
        ['GET',  '/officer/calls/{id}',             'call.manage',              OfficerController::class,  'editCall'],
        ['POST', '/officer/calls/{id}',             'call.manage',              OfficerController::class,  'updateCall'],

        ['GET',  '/account/security',               'account.security',         AccountController::class,  'security'],
        ['POST', '/account/security/webauthn/options', 'account.security',      AccountController::class,  'webauthnOptions'],
        ['POST', '/account/security/webauthn/register', 'account.security',     AccountController::class,  'webauthnRegister'],
        ['POST', '/account/security/webauthn/{id}/delete', 'account.security',  AccountController::class,  'webauthnDelete'],

        ['GET',  '/audit',                          'audit.read',               AuditController::class,    'timeline'],
        ['GET',  '/audit/export.csv',               'audit.read',               AuditController::class,    'export'],
    ];

    public static function handle(App $app): Response
    {
        self::securityHeaders();
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        if ($method === 'HEAD') {
            $method = 'GET';   // HEAD is a GET without the body; Apache drops the body itself
        }
        $path = rtrim(parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/', '/') ?: '/';
        $user = null;

        try {
            $app->session()->start();
            [$route, $params] = self::match($method, $path);
            if ($route === null) {
                return self::error($app, null, 404, 'Page not found', 'There is nothing at this address.');
            }
            [, , $permission, $controller, $action] = $route;

            if ($method === 'POST' && !Csrf::isValid($app->session(), $_POST['_csrf'] ?? null)) {
                $app->audit()->standalone($app->auth()->currentUser(), 'request.csrf_rejected', null, null, 'denied', ['path' => $path]);
                return self::error($app, null, 400, 'Form expired',
                    'This form is no longer valid. Go back, reload the page and try again.');
            }

            $user = $app->auth()->currentUser();
            if ($permission !== null) {
                if ($user === null) {
                    return Response::redirect('/login');
                }
                if (!Policy::can($user, $permission)) {
                    // Wrong role for this area: refuse and record who tried what.
                    $app->audit()->standalone($user, 'request.forbidden', null, null, 'denied',
                        ['path' => $path, 'method' => $method, 'required' => $permission]);
                    return self::error($app, $user, 403, 'Not permitted',
                        'Your role does not have access to this page.');
                }
            }
            return (new $controller($app, $user))->$action(...$params);
        } catch (Denied $e) {
            // Already audited by the workflow. Same page for "missing" and "forbidden".
            $status = $e->reason === 'not_visible' ? 404 : 403;
            return self::error($app, $user, $status, $status === 404 ? 'Not found' : 'Not permitted', $e->getMessage());
        } catch (Throwable $e) {
            // Safe error handling: details to the private log, a reference to the user.
            $app->logError($e);
            return self::error($app, $user, 500, 'Something went wrong',
                'The request could not be completed. Quote reference ' . $app->correlationId . ' to the research office.');
        }
    }

    /** @return array{0:?array,1:array<int,int>} */
    private static function match(string $method, string $path): array
    {
        foreach (self::ROUTES as $route) {
            // {id} only ever matches digits, so controllers receive a real integer.
            $regex = '#^' . str_replace('{id}', '(\d{1,18})', $route[1]) . '$#';
            if ($route[0] === $method && preg_match($regex, $path, $m)) {
                return [$route, array_map('intval', array_slice($m, 1))];
            }
        }
        return [null, []];
    }

    public static function error(App $app, ?User $user, int $status, string $title, string $message): Response
    {
        return Response::html(View::page('error', [
            'app' => $app, 'user' => $user, 'title' => $title, 'message' => $message, 'status' => $status,
        ]), $status);
    }

    private static function securityHeaders(): void
    {
        // No inline script or style is allowed: an injected <script> would not run.
        header("Content-Security-Policy: default-src 'self'; img-src 'self' data:; object-src 'none'; "
             . "base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('Referrer-Policy: same-origin');
        // Finding F05: switch off browser features the application never uses.
        header('Permissions-Policy: accelerometer=(), camera=(), geolocation=(), gyroscope=(), '
             . 'magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()');
        header('Cross-Origin-Opener-Policy: same-origin');
        header('Cross-Origin-Resource-Policy: same-origin');
        header('Cache-Control: no-store');   // pages with personal data are not kept by the browser
    }
}
