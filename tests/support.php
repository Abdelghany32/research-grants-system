<?php
declare(strict_types=1);
// Tiny test toolkit: explicit assertions, real PostgreSQL, real HTTP.
// No mocks - every check runs against the restricted database accounts.

use App\App;
use App\Auth\User;

final class TestFailure extends RuntimeException
{
}

final class T
{
    public static array $results = [];
    public static int $assertions = 0;
    private static ?App $app = null;

    public static function config(): array
    {
        return require __DIR__ . '/../config/config.php';
    }

    /** A fresh App (new connections, new correlation ID). */
    public static function newApp(): App
    {
        return new App(self::config(), '127.0.0.1');
    }

    public static function app(): App
    {
        return self::$app ??= self::newApp();
    }

    public static function user(string $localPart): User
    {
        $stmt = self::app()->db()->pdo()->prepare('SELECT id, email, full_name, department, role FROM users WHERE email = ?');
        $stmt->execute([$localPart . '@uni.example']);
        return User::fromRow($stmt->fetch());
    }

    /** A valid actor token for a user (the web process holds the key; a database password alone cannot make one). */
    public static function actorToken(int $userId, int $ttl = 120): string
    {
        return self::app()->actorToken()->mint($userId, null, $ttl);
    }

    /** Inside an open transaction on a raw connection: present a valid token for $who. */
    public static function bindActor(PDO $pdo, User $who): void
    {
        $pdo->prepare("SELECT set_config('app.actor', ?, true)")->execute([self::actorToken($who->id)]);
    }

    /** A brand-new connection as the runtime account, with NO actor set. */
    public static function rawRuntime(): PDO
    {
        $c = self::config()['db'];
        return new PDO(sprintf('pgsql:host=%s;port=%s;dbname=%s;sslmode=verify-full;sslrootcert=%s',
            $c['host'], $c['port'], $c['name'], $c['sslrootcert']), $c['app_user'], $c['app_password'],
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
             PDO::ATTR_EMULATE_PREPARES => false]);
    }

    /** Forget the recorded login failures of one source address (all accounts), through the same function a successful login uses. */
    public static function forgiveFailures(string $ip = '127.0.0.1'): void
    {
        $pdo = self::rawAs('identity_user', 'identity_password');      // the sign-in throttle belongs to the identity account
        $pdo->prepare('SELECT auth_clear_failures(id, ?::inet) FROM users')->execute([$ip]);
        $pdo->prepare('SELECT auth_clear_failures(NULL, ?::inet)')->execute([$ip]);
    }

    /** An App whose requests appear to come from $ip (to test per-address behaviour). */
    public static function appFrom(string $ip): App
    {
        return new App(self::config(), $ip);
    }

    /** A brand-new connection as another database account (config keys, e.g. 'audit_writer_user'). */
    public static function rawAs(string $userKey, string $passwordKey): PDO
    {
        $c = self::config()['db'];
        return new PDO(sprintf('pgsql:host=%s;port=%s;dbname=%s;sslmode=verify-full;sslrootcert=%s',
            $c['host'], $c['port'], $c['name'], $c['sslrootcert']), $c[$userKey], $c[$passwordKey],
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
             PDO::ATTR_EMULATE_PREPARES => false]);
    }

    /** Run raw SQL as $actor on the runtime account (inside an actor transaction). */
    public static function sqlAs(User $actor, string $sql, array $args = []): array
    {
        return self::app()->db()->asActor($actor->id, static function (PDO $tx) use ($sql, $args): array {
            $stmt = $tx->prepare($sql);
            $stmt->execute($args);
            return ['rows' => $stmt->columnCount() ? $stmt->fetchAll() : [], 'affected' => $stmt->rowCount()];
        });
    }

    /** Raw SQL as $actor on the IDENTITY account (second-factor functions and the like), inside an actor transaction. */
    public static function identitySqlAs(User $actor, string $sql, array $args = []): array
    {
        return self::app()->identityDb()->asActor($actor->id, static function (PDO $tx) use ($sql, $args): array {
            $stmt = $tx->prepare($sql);
            $stmt->execute($args);
            return ['rows' => $stmt->columnCount() ? $stmt->fetchAll() : [], 'affected' => $stmt->rowCount()];
        });
    }

    /** Audit events as the auditor account sees them. */
    public static function audit(string $where, array $args = []): array
    {
        $stmt = self::app()->auditorDb()->pdo()->prepare("SELECT * FROM audit_timeline WHERE $where ORDER BY id");
        $stmt->execute($args);
        return $stmt->fetchAll();
    }

    /** The demo TOTP secret (base32) of an officer or auditor, from the mounted secrets/demo-totp.txt. */
    public static function totpSecret(string $localPart): string
    {
        foreach (file('/run/grants/demo-totp.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
            $p = explode("\t", $line);
            if ($p[0] === $localPart . '@uni.example') {
                return $p[1];
            }
        }
        throw new RuntimeException("no TOTP secret for $localPart");
    }

    public static function totpCode(string $localPart, int $stepOffset = 0): string
    {
        return \App\Auth\Totp::code(self::totpSecret($localPart), \App\Auth\Totp::step() + $stepOffset);
    }

    public static function password(string $localPart): string
    {
        foreach (file('/run/grants/demo-credentials.txt', FILE_IGNORE_NEW_LINES) as $line) {
            [$email, $password] = explode("\t", $line);
            if ($email === $localPart . '@uni.example') {
                return $password;
            }
        }
        throw new RuntimeException("no credential for $localPart");
    }

    public static function proposalId(string $titleStart): int
    {
        // Looked up through the audit-free owner path is impossible here, so ask as the officer or the owner.
        foreach (['nadia.berrada', 'amina.elidrissi', 'youssef.benali'] as $who) {
            $r = self::sqlAs(self::user($who), "SELECT id FROM proposals WHERE title LIKE ? ORDER BY id LIMIT 1", [$titleStart . '%']);
            if ($r['rows']) {
                return (int) $r['rows'][0]['id'];
            }
        }
        throw new RuntimeException("no proposal titled $titleStart");
    }
}

function test(string $name, callable $body): void
{
    global $argv;
    if (isset($argv[1]) && !str_contains($name, $argv[1])) {
        return;
    }
    try {
        $body();
        T::$results[] = [$name, null];
        echo "PASS  $name\n";
    } catch (Throwable $e) {
        T::$results[] = [$name, $e];
        echo "FAIL  $name\n      " . $e::class . ': ' . $e->getMessage() . ' (' . basename($e->getFile()) . ':' . $e->getLine() . ")\n";
    }
}

function check(bool $condition, string $claim): void
{
    T::$assertions++;
    if (!$condition) {
        throw new TestFailure("expected: $claim");
    }
}

function same(mixed $expected, mixed $actual, string $claim): void
{
    T::$assertions++;
    if ($expected !== $actual) {
        throw new TestFailure("$claim - expected " . var_export($expected, true) . ', got ' . var_export($actual, true));
    }
}

/** The callable must be refused with a Denied exception carrying this reason. */
function denied(string $reason, callable $body, string $claim): void
{
    T::$assertions++;
    try {
        $body();
    } catch (\App\Grants\Denied $e) {
        if ($e->reason !== $reason) {
            throw new TestFailure("$claim - denied for '{$e->reason}', expected '$reason'");
        }
        return;
    }
    throw new TestFailure("$claim - expected Denied($reason) but the action was allowed");
}

/** The callable must fail inside PostgreSQL with this SQLSTATE (e.g. 42501 = insufficient privilege). */
function sqlstate(string $state, callable $body, string $claim): void
{
    T::$assertions++;
    try {
        $body();
    } catch (PDOException $e) {
        if ($e->getCode() !== $state) {
            throw new TestFailure("$claim - SQLSTATE {$e->getCode()}, expected $state: " . $e->getMessage());
        }
        return;
    }
    throw new TestFailure("$claim - expected SQLSTATE $state but the statement succeeded");
}

/** Minimal browser: keeps cookies, follows nothing, fetches CSRF tokens from forms. */
final class Browser
{
    private string $jar;
    public int $status = 0;
    public string $body = '';
    public string $location = '';
    public string $headers = '';

    public function __construct(private readonly string $base = 'http://127.0.0.1:8099')
    {
        $this->jar = tempnam(sys_get_temp_dir(), 'jar');
    }

    public function get(string $path): self
    {
        return $this->request($path, null);
    }

    public function post(string $path, array $fields, bool $withCsrf = true): self
    {
        if ($withCsrf) {
            $fields['_csrf'] = $this->csrf();
        }
        return $this->request($path, $fields);
    }

    /** Sign in. Officers and auditors are then asked for a second factor: it is completed here unless $completeMfa is false. */
    public function login(string $localPart, ?string $password = null, bool $completeMfa = true): self
    {
        $this->get('/login');
        $this->post('/login', ['email' => $localPart . '@uni.example', 'password' => $password ?? T::password($localPart)]);
        if ($completeMfa && $this->status === 303 && str_ends_with($this->location, '/login/mfa')) {
            $this->get('/login/mfa');
            $this->post('/login/mfa', ['code' => T::totpCode($localPart)]);
        }
        return $this;
    }

    public function csrf(): string
    {
        if (!preg_match('/name="_csrf" value="([0-9a-f]+)"/', $this->body, $m)) {
            $this->get('/login');
            preg_match('/name="_csrf" value="([0-9a-f]+)"/', $this->body, $m);
            if (!$m) { $this->get('/'); $this->get($this->location ?: '/login'); preg_match('/name="_csrf" value="([0-9a-f]+)"/', $this->body, $m); }
        }
        return $m[1] ?? '';
    }

    public function cookie(): string
    {
        return preg_match('/\t(grants_session|__Host-grants)\t(\S+)/', (string) file_get_contents($this->jar), $m) ? $m[2] : '';
    }

    private function request(string $path, ?array $post): self
    {
        $ch = curl_init($this->base . $path);
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true, CURLOPT_COOKIEJAR => $this->jar,
            CURLOPT_COOKIEFILE => $this->jar, CURLOPT_FOLLOWLOCATION => false, CURLOPT_TIMEOUT => 30]);
        if ($post !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($post));
        }
        $raw = (string) curl_exec($ch);
        $size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $this->status = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $this->headers = substr($raw, 0, $size);
        $this->body = substr($raw, $size);
        $this->location = preg_match('/^Location: (\S+)/mi', $this->headers, $m) ? $m[1] : '';
        unset($ch);   // flushes the cookie jar to disk
        return $this;
    }
}
