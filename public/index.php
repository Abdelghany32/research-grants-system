<?php
declare(strict_types=1);

// Single HTTP entry point. Apache sends every non-file request here
// (FallbackResource); everything else in the project is outside the web root.
if (PHP_SAPI === 'cli-server' && is_file(__DIR__ . parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH))) {
    return false;   // PHP's built-in server (used by the HTTP tests) serves static assets itself
}

require __DIR__ . '/../src/bootstrap.php';

App\Http\Kernel::handle(App\App::fromEnvironment())->send();
