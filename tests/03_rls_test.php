<?php
declare(strict_types=1);
// Requirement: row-level security on sensitive proposal access.

test('RLS a connection with no identity sees nothing and can write nothing (fails closed)', function (): void {
    $pdo = T::rawRuntime();
    foreach (['proposals', 'reviews', 'decisions', 'grant_calls'] as $table) {
        same(0, $pdo->query("SELECT count(*) FROM $table")->fetchColumn(), "$table is empty without an identity");
    }
    sqlstate('42501', fn () => $pdo->exec("INSERT INTO proposals (call_id, owner_id, title, requested_amount, currency) VALUES (1, 1, 'No identity', 10, 'MAD')"),
        'insert without identity violates the policy');
    same(0, $pdo->exec("UPDATE proposals SET title = 'changed'"), 'update without identity touches no row');
    same(0, $pdo->exec('DELETE FROM proposals'), 'delete without identity touches no row');
});

test('RLS an unknown or inactive user id sees nothing', function (): void {
    $ghost = new App\Auth\User(999999, 'ghost@uni.example', 'Ghost', 'None', 'officer');
    same(0, T::sqlAs($ghost, 'SELECT count(*) AS n FROM proposals')['rows'][0]['n'], 'role is looked up in the database, not trusted from PHP');
});

test('RLS researchers A and B each see only their own proposals, in successive requests', function (): void {
    $amina = T::user('amina.elidrissi');
    $youssef = T::user('youssef.benali');
    $a = T::sqlAs($amina, 'SELECT DISTINCT owner_id FROM proposals')['rows'];
    $b = T::sqlAs($youssef, 'SELECT DISTINCT owner_id FROM proposals')['rows'];   // same connection, next transaction
    same([['owner_id' => $amina->id]], $a, 'A sees only A');
    same([['owner_id' => $youssef->id]], $b, 'B sees only B');
    $theirs = T::proposalId('Seismic Retrofitting');
    same([], T::sqlAs($amina, 'SELECT id FROM proposals WHERE id = ?', [$theirs])['rows'], 'A cannot read B by id');
    same(0, T::sqlAs($amina, "UPDATE proposals SET title = 'hijacked' WHERE id = ?", [$theirs])['affected'], 'A cannot update B');
    same(0, T::sqlAs($amina, 'DELETE FROM proposals WHERE id = ?', [$theirs])['affected'], 'A cannot delete B');
    same(null, T::app()->queries()->myProposal($amina, $theirs), 'application read returns nothing');
    same(404, (new Browser())->login('amina.elidrissi')->get('/proposals/' . $theirs)->status, 'detail page returns 404');
    check(count(T::audit("action = 'proposal.view' AND outcome = 'denied' AND resource_id = ? AND actor_id = ?", [$theirs, $amina->id])) >= 2, 'denied reads recorded');
});

test('RLS a reused connection does not carry the previous actor', function (): void {
    $db = T::newApp()->db();
    $pdo = $db->pdo();
    $seen = $db->asActor(T::user('amina.elidrissi')->id, fn (PDO $tx) => $tx->query('SELECT count(*) FROM proposals')->fetchColumn());
    check($seen > 0, 'actor sees rows inside the transaction');
    same('', (string) $pdo->query("SELECT current_setting('app.actor', true)")->fetchColumn(), 'identity is gone after COMMIT');
    same(0, $pdo->query('SELECT count(*) FROM proposals')->fetchColumn(), 'same connection, no identity: no rows');
    try {
        $db->asActor(T::user('amina.elidrissi')->id, function (): void { throw new RuntimeException('boom'); });
    } catch (RuntimeException) {
    }
    same(0, $pdo->query('SELECT count(*) FROM proposals')->fetchColumn(), 'identity is gone after ROLLBACK too');
    $b = $db->asActor(T::user('youssef.benali')->id, fn (PDO $tx) => $tx->query('SELECT DISTINCT owner_id FROM proposals')->fetchAll(PDO::FETCH_COLUMN));
    same([T::user('youssef.benali')->id], $b, 'next actor on the same connection sees only their rows');
});

test('RLS the application cannot grant itself a role through a session variable', function (): void {
    $amina = T::user('amina.elidrissi');
    $n = T::app()->db()->asActor($amina->id, function (PDO $tx): int {
        $tx->query("SELECT set_config('app.user_role', 'officer', true), set_config('app.role', 'officer', true)");
        return (int) $tx->query('SELECT count(DISTINCT owner_id) FROM proposals')->fetchColumn();
    });
    same(1, $n, 'still limited to own rows');
});

test('RLS an unassigned reviewer cannot read the proposal or the review', function (): void {
    $karim = T::user('karim.ouazzani');
    $salma = T::user('salma.tazi');
    $p1 = T::proposalId('Federated Learning');             // assigned to Salma only
    $r1 = (int) T::sqlAs($salma, 'SELECT id FROM reviews WHERE proposal_id = ?', [$p1])['rows'][0]['id'];
    same([], T::sqlAs($karim, 'SELECT id FROM proposals WHERE id = ?', [$p1])['rows'], 'proposal hidden from unassigned reviewer');
    same([], T::sqlAs($karim, 'SELECT id FROM reviews WHERE id = ?', [$r1])['rows'], 'other reviewer\'s review hidden');
    same(0, T::sqlAs($karim, 'UPDATE reviews SET score = 1 WHERE id = ?', [$r1])['affected'], 'cannot overwrite another review');
    same(null, T::app()->queries()->myAssignment($karim, $r1), 'application read returns nothing');
    same(404, (new Browser())->login('karim.ouazzani')->get('/reviews/' . $r1)->status, 'workspace returns 404');
    check(count(T::audit("action = 'review.view' AND outcome = 'denied' AND resource_id = ? AND actor_id = ?", [$r1, $karim->id])) >= 2, 'denied reads recorded');
    same(1, count(T::sqlAs($salma, 'SELECT id FROM proposals WHERE id = ?', [$p1])['rows']), 'assigned reviewer can read it');
});

test('RLS drafts are private to their author; reviews are hidden from applicants', function (): void {
    $draft = T::proposalId('Low-Resource Darija');
    foreach (['nadia.berrada', 'salma.tazi', 'karim.ouazzani', 'youssef.benali', 'omar.chraibi'] as $who) {
        same([], T::sqlAs(T::user($who), 'SELECT id FROM proposals WHERE id = ?', [$draft])['rows'], "$who cannot read the draft");
    }
    foreach (['amina.elidrissi', 'youssef.benali', 'omar.chraibi'] as $who) {
        same(0, T::sqlAs(T::user($who), 'SELECT count(*) AS n FROM reviews')['rows'][0]['n'], "$who sees no review rows at all");
    }
    same(0, T::sqlAs(T::user('omar.chraibi'), 'SELECT count(*) AS n FROM proposals')['rows'][0]['n'], 'auditor sees no proposals');
    $decided = T::proposalId('Greywater');
    same(1, count(T::sqlAs(T::user('youssef.benali'), 'SELECT outcome FROM decisions WHERE proposal_id = ?', [$decided])['rows']), 'owner reads own decision');
    same(0, count(T::sqlAs(T::user('amina.elidrissi'), 'SELECT outcome FROM decisions WHERE proposal_id = ?', [$decided])['rows']), 'other researcher cannot');
});

test('RLS lists, search and counts stay inside the permitted rows', function (): void {
    $amina = T::user('amina.elidrissi');
    $q = T::app()->queries();
    $mine = array_column($q->myProposals($amina), 'id');
    same(count($mine), (int) T::sqlAs($amina, 'SELECT count(*) AS n FROM proposals')['rows'][0]['n'], 'list size equals what RLS permits');
    same([], $q->officerQueue($amina), 'researcher gets nothing from the officer queue');
    same([], $q->myAssignments($amina), 'researcher gets nothing from reviewer assignments');
    same([], array_column($q->myProposals($amina, 'Seismic'), 'title'), 'search cannot reach another researcher\'s title');
    $html = (new Browser())->login('amina.elidrissi')->get('/proposals?q=Seismic')->body;
    check(!str_contains($html, 'Seismic Retrofitting'), 'search page does not leak the other title');
    $html = (new Browser())->login('amina.elidrissi')->get('/proposals')->body;
    check(!str_contains($html, 'Greywater') && !str_contains($html, 'Desalination'), 'inbox lists no foreign proposals');
});

test('RLS search with an apostrophe returns only authorized records (injection regression)', function (): void {
    $q = T::app()->queries();
    $amina = T::user('amina.elidrissi');
    $youssef = T::user('youssef.benali');
    same(["Children's Digital Literacy in Rural Schools"], array_column($q->myProposals($amina, "Children's"), 'title'), 'owner finds the title with an apostrophe');
    same([], $q->myProposals($youssef, "Children's"), 'another researcher finds nothing');
    $all = count($q->myProposals($amina));
    foreach (["' OR '1'='1", "'; DROP TABLE proposals; --", "%' OR owner_id <> 0 --", '%', '_', '\\'] as $payload) {
        same([], $q->myProposals($amina, $payload), "payload [$payload] is treated as plain text");
    }
    same($all, count($q->myProposals($amina)), 'table intact afterwards');
    $b = (new Browser())->login('youssef.benali')->get('/proposals?q=' . rawurlencode("' OR '1'='1"));
    same(200, $b->status, 'page renders normally (no SQL error)');
    check(!str_contains($b->body, 'Federated') && !str_contains($b->body, 'Children'), 'no foreign rows in the response');
    check(str_contains($b->body, 'None of your proposals has a title containing'), 'empty state shown');
    same(1, count($q->officerQueue(T::user('nadia.berrada'), "Children's")), 'officer search handles the apostrophe too');
});
