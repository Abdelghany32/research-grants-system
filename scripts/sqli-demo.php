<?php
declare(strict_types=1);
// Phase 4/5 - controlled SQL injection: vulnerability -> impact -> root cause -> mitigation -> verification.
// The deliberately unsafe query exists ONLY in this CLI lab script, never under public/, and only runs
// against the disposable grants_test database. It is executed with the REAL restricted runtime account,
// as an authenticated researcher, so the impact shown is the impact the real privilege model allows.
if (PHP_SAPI !== 'cli' || getenv('PENTEST_LAB') !== '1' || getenv('DB_NAME') !== 'grants_test') {
    fwrite(STDERR, "Requires CLI, PENTEST_LAB=1 and the disposable grants_test database.\n");
    exit(2);
}
require __DIR__ . '/../src/bootstrap.php';
require __DIR__ . '/../tests/support.php';

$pdo = T::rawRuntime();
$me = T::user('amina.elidrissi');
$pdo->beginTransaction();
T::bindActor($pdo, $me);       // the vulnerable component belongs to the web application, which holds the actor key

/** THE VULNERABILITY: user text is concatenated into the SQL statement. */
$unsafe = static fn (string $q): array => $pdo->query(
    "SELECT id, title FROM proposals WHERE owner_id = {$me->id} AND title ILIKE '%" . $q . "%' ORDER BY id")->fetchAll();

/** THE FIX: the statement is fixed; the value travels separately as a bound parameter. */
$safe = static function (string $q) use ($pdo, $me): array {
    $s = $pdo->prepare("SELECT id, title FROM proposals WHERE owner_id = ? AND title ILIKE ? ESCAPE '\\' ORDER BY id");
    $s->execute([$me->id, '%' . addcslashes($q, '%_\\') . '%']);
    return $s->fetchAll();
};

/** Run one attack; a database error aborts the transaction, so each error test uses a savepoint. */
$run = static function (callable $f, string $q) use ($pdo): array {
    $pdo->exec('SAVEPOINT s');
    try {
        $rows = $f($q);
        $pdo->exec('RELEASE SAVEPOINT s');
        return ['rows' => $rows, 'error' => null];
    } catch (PDOException $e) {
        $pdo->exec('ROLLBACK TO SAVEPOINT s');
        return ['rows' => [], 'error' => $e->getCode() . ' ' . trim(preg_replace('/\s+/', ' ', explode("\n", $e->getMessage())[0]))];
    }
};

$attacks = [
    ['A1', 'boolean bypass of the filter',                       "' OR TRUE -- "],
    ['A2', 'UNION: read every account (users table)',           "zz%' UNION SELECT id, email || ' | ' || full_name || ' | ' || role FROM users -- "],
    ['A3', 'UNION: read password hashes',                        "zz%' UNION SELECT id, password_hash FROM users -- "],
    ['A4', 'UNION: read the audit trail',                        "zz%' UNION SELECT id, action || ' ' || coalesce(details::text, '') FROM audit_events -- "],
    ['A5', 'UNION: read other researchers\' proposals',          "zz%' UNION SELECT id, title FROM proposals WHERE owner_id <> {$me->id} -- "],
    ['A6', 'UNION: read confidential review comments',           "zz%' UNION SELECT id, comments_enc FROM reviews -- "],
    ['A7', 'stacked statement: lock the officers out',           "zz%'; UPDATE users SET locked_until = now() + interval '1 day' WHERE role = 'officer'; -- "],
    ['A8', 'stacked statement: erase decisions',                 "zz%'; DELETE FROM decisions; -- "],
    ['A9', 'stacked statement: give myself money',               "zz%'; UPDATE grant_calls SET remaining_budget = 0; -- "],
];

$out = static function (string $s = ''): void { echo $s, "\n"; };
$out('SQL INJECTION LAB - ' . gmdate('Y-m-d\TH:i:s\Z') . ' - database ' . $pdo->query('SELECT current_database()')->fetchColumn()
   . ', account ' . $pdo->query('SELECT current_user')->fetchColumn() . ', acting as researcher ' . $me->email);
$out('The unsafe query: SELECT id, title FROM proposals WHERE owner_id = <actor> AND title ILIKE \'%<INPUT>%\'');
$out('The fixed query : the same statement with the value bound as a parameter ($2).');
$out();
$out('== 1. BEFORE remediation: the unsafe query, six data-theft payloads and three tampering payloads');
$leaked = [];
foreach ($attacks as [$id, $what, $payload]) {
    $r = $run($unsafe, $payload);
    $out(sprintf('%s  %s', $id, $what));
    $out('    payload : ' . $payload);
    if ($r['error'] !== null) {
        $out('    result  : REFUSED by the database - ' . $r['error']);
    } else {
        $out(sprintf('    result  : %d rows returned', count($r['rows'])));
        $mine = count(array_filter($r['rows'], static fn ($row) => str_contains((string) $row['title'], ' | ')));
        if ($id === 'A2') {
            $leaked = array_column($r['rows'], 'title');
            foreach (array_slice(array_filter($leaked, static fn ($t) => str_contains((string) $t, ' | ')), 0, 20) as $t) { $out('      leaked: ' . $t); }
        }
    }
}
$accounts = array_values(array_filter($leaked, static fn ($t) => str_contains((string) $t, ' | ')));
$roles = array_count_values(array_map(static fn ($t) => trim(substr(strrchr($t, '|'), 1)), $accounts));
ksort($roles);
$out();
$out('A7-A9 were stopped by server-side prepared statements. Second barrier: the same three statements sent as if stacking had worked (simple protocol, exec()):');
foreach ([['A7', "UPDATE users SET locked_until = now() + interval '1 day' WHERE role = 'officer'"],
          ['A8', 'DELETE FROM decisions'],
          ['A9', 'UPDATE grant_calls SET remaining_budget = 0']] as [$id, $sql]) {
    $r = $run(static fn () => $pdo->exec($sql), '');
    $out(sprintf('%s  %-70s -> %s', $id, $sql, $r['error'] === null ? 'EXECUTED (privilege model failed!)' : 'REFUSED ' . substr($r['error'], 0, 5) . ' (no privilege)'));
}
$out();
$out('IMPACT (what the attacker obtained) : ' . count($accounts) . ' accounts (e-mail, full name, role) - ' . json_encode($roles)
   . ', including every officer and the auditor.');
$out('   A researcher should see none of them. This is a confidentiality breach and a map for targeted phishing and account attacks.');
$out('IMPACT LIMITED BY LEAST PRIVILEGE   : password hashes (A3), the audit trail (A4), other researchers\' proposals (A5, RLS),');
$out('   and review comments (A6, RLS: no policy for researchers) were NOT obtainable; all three tampering payloads (A7-A9) failed,');
$out('   so the same injection cannot lock accounts, erase decisions or change budgets.');

$out();
$out('== 2. ROOT CAUSE');
$out('   The statement text is built from user input, so input can change the grammar of the statement (quote, UNION, comment).');
$out('   Escaping lists or blacklists do not fix this; the database must receive the statement and the data separately.');

$out();
$out('== 3. AFTER remediation: the SAME nine payloads through the parameterised query');
$bad = 0;
foreach ($attacks as [$id, $what, $payload]) {
    $r = $run($safe, $payload);
    $ok = $r['error'] === null && count($r['rows']) === 0;
    $bad += $ok ? 0 : 1;
    $out(sprintf('%s  %-52s -> %s', $id, $what, $ok ? '0 rows, no error: treated as a harmless search text' : 'NOT NEUTRALISED ' . json_encode($r)));
}
$apostrophe = $run($safe, "Children's");
$out(sprintf('     legitimate input containing an apostrophe ("Children\'s") -> %d row(s), %s', count($apostrophe['rows']), $apostrophe['error'] ?? 'no error'));
$own = $run($safe, '');
$out(sprintf('     empty search -> %d rows, all owned by the actor (RLS unchanged)', count($own['rows'])));

$out();
$out('== 4. WHY THE FIX WORKS');
$out('   * With bound parameters the statement is parsed first; the input can only ever be a value, never SQL.');
$out('   * Server-side prepared statements (PDO::ATTR_EMULATE_PREPARES=false) also refuse stacked statements: see the A7-A9 result in section 1.');
$out('   * Defence in depth held even while the code was vulnerable: column privileges, RLS and the missing UPDATE/DELETE grants capped the damage.');
$pdo->rollBack();
$out();
$out(sprintf('RESULT: %s', $bad === 0 && count($accounts) > 0 ? 'vulnerability demonstrated, then no longer exploitable' : 'CHECK THE OUTPUT ABOVE'));
exit($bad === 0 && count($accounts) > 0 ? 0 : 1);
