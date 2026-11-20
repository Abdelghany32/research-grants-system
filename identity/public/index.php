<?php
declare(strict_types=1);

// Entry point of the identity service (internal network only, never published to the host).
require __DIR__ . '/../../src/bootstrap.php';

App\Identity\IdentityService::handle(App\App::fromEnvironment());
