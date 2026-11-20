<?php
declare(strict_types=1);

namespace App\Http\Controllers;

use App\Audit\AuditReader;
use App\Http\Response;

/** Auditor screen: a filterable, read-only timeline of security events. */
final class AuditController extends Controller
{
    private function filters(): array
    {
        $f = [];
        foreach (['from', 'to', 'actor', 'action', 'outcome', 'resource_type', 'resource_id', 'correlation'] as $key) {
            $f[$key] = $this->query($key);
        }
        // Filters are validated before use; anything malformed is dropped.
        $isDate = static fn (string $s): bool => (bool) preg_match('/^\d{4}-\d{2}-\d{2}$/', $s) && strtotime($s) !== false;
        if (!$isDate($f['from'])) { $f['from'] = ''; }
        if (!$isDate($f['to'])) { $f['to'] = ''; }
        if (!in_array($f['outcome'], AuditReader::OUTCOMES, true)) { $f['outcome'] = ''; }
        if (!ctype_digit($f['resource_id'])) { $f['resource_id'] = ''; }
        if (!preg_match('/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/', $f['correlation'])) { $f['correlation'] = ''; }

        return $f;
    }

    public function timeline(): Response
    {
        $f = $this->filters();
        $reader = $this->app->auditReader();
        $events = $reader->timeline($f);
        // Reading the audit trail is itself an administrative action worth recording.
        $this->app->audit()->standalone($this->user, 'audit.view', 'audit_events', null, 'success',
            ['filters' => array_filter($f), 'rows' => count($events)]);

        return $this->page('auditor/timeline', [
            'title' => 'Audit timeline', 'events' => $events, 'f' => $f, 'options' => $reader->filterOptions(),
        ]);
    }

    /** GET /audit/export.csv - the same filters as the screen, as a spreadsheet-safe CSV (at most 5,000 rows). */
    public function export(): Response
    {
        $f = $this->filters();
        $limit = 5000;
        $events = $this->app->auditReader()->timeline($f, $limit);
        $this->app->audit()->standalone($this->user, 'audit.export', 'audit_events', null, 'success',
            ['filters' => array_filter($f), 'rows' => count($events), 'truncated' => count($events) >= $limit]);

        $out = fopen('php://temp', 'w+');
        fputcsv($out, ['id', 'time_utc', 'actor_email', 'actor_role', 'actor_proved', 'action', 'resource_type', 'resource_id',
                       'outcome', 'request_id', 'source_ip', 'details'], ',', '"', '');
        foreach ($events as $ev) {
            fputcsv($out, array_map(self::cell(...), [
                $ev['id'], gmdate('Y-m-d\TH:i:s\Z', strtotime($ev['occurred_at'])), $ev['actor_email'] ?? '', $ev['actor_role'] ?? '',
                $ev['actor_verified'] ? 'yes' : 'no', $ev['action'], $ev['resource_type'] ?? '', $ev['resource_id'] ?? '',
                $ev['outcome'], $ev['correlation_id'] ?? '', $ev['source_ip'] ?? '', $ev['details'],
            ]), ',', '"', '');
        }
        rewind($out);
        return Response::csv((string) stream_get_contents($out), 'audit-' . gmdate('Ymd-His') . '.csv');
    }

    /**
     * Spreadsheet formula injection: a cell that starts with = + - @ (or a tab or carriage return) would be
     * executed by Excel or LibreOffice. A leading apostrophe makes it plain text. Event text cannot contain
     * proposal content, but actor and detail fields still come from user-influenced values (e.g. a typed e-mail).
     */
    private static function cell(mixed $v): string
    {
        $s = (string) $v;
        return $s !== '' && strpbrk($s[0], "=+-@\t\r") !== false ? "'" . $s : $s;
    }
}
