<?php
declare(strict_types=1);

namespace App\Database;

use App\Security\ActorTokenSource;
use PDO;
use Throwable;

/** One PostgreSQL connection for one database account. */
final class Database
{
    private ?PDO $pdo = null;

    public function __construct(
        private readonly string $dsn,
        private readonly string $user,
        #[\SensitiveParameter] private readonly string $password,
        private readonly ?ActorTokenSource $tokens = null,
    ) {
    }

    public function pdo(): PDO
    {
        return $this->pdo ??= new PDO($this->dsn, $this->user, $this->password, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            // Real server-side prepared statements: SQL text and values travel separately.
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]);
    }

    /**
     * Run $work in one transaction on behalf of an authenticated user.
     *
     * The actor comes from the server-side session, never from request input,
     * and is presented to the database as a signed actor token (findings O02/O03):
     * the database verifies the signature itself, so the database password alone
     * cannot claim an identity. set_config(..., true) is SET LOCAL: the value
     * disappears at COMMIT or ROLLBACK, so a reused connection cannot carry this
     * actor into the next request. Row-level security policies read it via
     * current_actor_id().
     */
    public function asActor(int $actorId, callable $work): mixed
    {
        $pdo = $this->pdo();
        $pdo->beginTransaction();
        try {
            if ($this->tokens === null) {
                throw new \LogicException('This connection cannot act on behalf of a user: no actor key is configured.');
            }
            $pdo->prepare("SELECT set_config('app.actor', ?, true)")->execute([$this->tokens->tokenFor($actorId)]);
            $result = $work($pdo);
            $pdo->commit();
            return $result;
        } catch (Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            throw $e;
        }
    }
}
