<?php
declare(strict_types=1);
// Requirement: the auditor can export the audit trail as CSV - same permission, same filters, safe in a spreadsheet, itself audited.

test('EXPORT the auditor downloads the filtered timeline as a CSV file', function (): void {
    $b = (new Browser())->login('omar.chraibi');
    $b->get('/audit/export.csv?outcome=denied');
    same(200, $b->status, 'status');
    check(stripos($b->headers, 'Content-Type: text/csv') !== false, 'CSV content type');
    check((bool) preg_match('/Content-Disposition: attachment; filename="audit-\d{8}-\d{6}\.csv"/i', $b->headers), 'a download with a server-chosen file name');
    $rows = array_map(static fn (string $l) => str_getcsv($l, ',', '"', ''), array_filter(explode("\n", trim($b->body))));
    same(['id', 'time_utc', 'actor_email', 'actor_role', 'actor_proved', 'action', 'resource_type', 'resource_id', 'outcome', 'request_id', 'source_ip', 'details'], $rows[0], 'header row');
    check(count($rows) > 1, 'there are denied events to export');
    foreach (array_slice($rows, 1) as $r) {
        same('denied', $r[8], 'the outcome filter applies to the export');
        check(in_array($r[4], ['yes', 'no'], true), 'the proof column says yes or no');
    }
    check(!str_contains($b->body, 'Seismic') && !str_contains($b->body, 'Federated'), 'no proposal text leaves through the export');
    $events = T::audit("action = 'audit.export' AND outcome = 'success'");
    check(count($events) >= 1, 'the export itself is in the audit trail');
    $d = json_decode(end($events)['details'], true);
    same(count($rows) - 1, $d['rows'], 'the event records how many rows were exported');
    same('denied', $d['filters']['outcome'], 'and which filter');
});

test('EXPORT other roles and anonymous visitors are refused (403 audited, redirect)', function (): void {
    foreach (['amina.elidrissi', 'salma.tazi', 'nadia.berrada'] as $who) {
        $b = (new Browser())->login($who);
        same(403, $b->get('/audit/export.csv')->status, "$who is refused");
        check(!str_contains($b->body, 'time_utc'), "$who receives no data");
    }
    same(303, (new Browser())->get('/audit/export.csv')->status, 'anonymous visitors are sent to the login');
    check(count(T::audit("action = 'request.forbidden' AND details->>'path' = '/audit/export.csv'")) >= 3, 'every refusal is recorded');
});

test('EXPORT cells that a spreadsheet would execute are neutralised', function (): void {
    $cell = new ReflectionMethod(App\Http\Controllers\AuditController::class, 'cell');
    foreach (['=1+1' => "'=1+1", '+SUM(A1:A2)' => "'+SUM(A1:A2)", '-2+3' => "'-2+3", '@cmd' => "'@cmd", "\tx" => "'\tx", "\rx" => "'\rx",
              'plain' => 'plain', '' => '', '2026-11-17T10:00:00Z' => '2026-11-17T10:00:00Z', '{"reason": "x"}' => '{"reason": "x"}'] as $in => $out) {
        same($out, $cell->invoke(null, $in), 'cell ' . json_encode($in));
    }
});
