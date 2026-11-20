<?php
declare(strict_types=1);
// Test runner.   php tests/run.php [name-filter]
// Exit code 0 only if every test passed. Run it through scripts/test.sh, which
// first rebuilds the grants_test database so results are repeatable.
require __DIR__ . '/../src/bootstrap.php';
require __DIR__ . '/support.php';

if ((getenv('DB_NAME') ?: '') !== 'grants_test') {
    fwrite(STDERR, "Refusing to run: tests change data and must use DB_NAME=grants_test (use scripts/test.sh).\n");
    exit(2);
}

// Throw-away servers on the test database, wired exactly like production: web FRONT ENDS in "remote" identity mode,
// each talking to an IDENTITY SERVICE (local mode, holds the keys). Three pairs, because the identity service owns the
// session limits and the one-time-code policy:
//   front end 8099 -> identity 8095   normal
//   front end 8098 -> identity 8094   1-second inactivity limit (session-expiry test)
//   front end 8096 -> identity 8093   one-time-code REPLAY PROTECTION on (the others switch it off, because the tests
//                                     sign the same officer in many times within one 30-second step)
putenv('MFA_REPLAY_PROTECTION=0');
$servers = [];
$start = static function (int $port, string $docroot, array $env) use (&$servers): void {
    $servers[] = proc_open(['php', '-S', "127.0.0.1:$port", '-t', $docroot, $docroot . '/index.php'],
        [['file', '/dev/null', 'r'], ['file', '/dev/null', 'w'], ['file', '/dev/null', 'w']], $pipes, null, array_merge(getenv(), $env));
};
foreach ([[8095, ['MFA_REPLAY_PROTECTION' => '0']], [8094, ['SESSION_IDLE_SECONDS' => '1', 'MFA_REPLAY_PROTECTION' => '0']], [8093, ['MFA_REPLAY_PROTECTION' => '1']]] as [$port, $extra]) {
    $start($port, __DIR__ . '/../identity/public', $extra + ['IDENTITY_MODE' => 'local', 'PHP_CLI_SERVER_WORKERS' => '4']);
}
foreach ([[8099, 8095], [8098, 8094], [8096, 8093]] as [$port, $identityPort]) {
    $start($port, __DIR__ . '/../public', ['IDENTITY_MODE' => 'remote', 'IDENTITY_URL' => "http://127.0.0.1:$identityPort"]);
}
register_shutdown_function(static function () use (&$servers): void {
    foreach ($servers as $s) { proc_terminate($s); }
});
foreach ([8093, 8094, 8095, 8096, 8098, 8099] as $port) {
    for ($i = 0; $i < 60 && !@fsockopen('127.0.0.1', $port); $i++) { usleep(100_000); }
}

printf("PHP %s, PostgreSQL %s, database %s, account %s\n\n", PHP_VERSION,
    T::app()->db()->pdo()->query('SHOW server_version')->fetchColumn(),
    T::app()->db()->pdo()->query('SELECT current_database()')->fetchColumn(),
    T::app()->db()->pdo()->query('SELECT current_user')->fetchColumn());

foreach (glob(__DIR__ . '/*_test.php') as $file) {
    echo '--- ' . basename($file) . "\n";
    require $file;
}

$failed = array_filter(T::$results, static fn (array $r): bool => $r[1] !== null);
printf("\n%d tests, %d assertions, %d failed\n", count(T::$results), T::$assertions, count($failed));
exit($failed ? 1 : 0);
