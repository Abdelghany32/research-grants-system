<?php
declare(strict_types=1);

namespace App\Audit;

use App\Database\Database;

/**
 * Reads the audit timeline through the grants_auditor account, whose only
 * privilege is SELECT on the audit_timeline view (read-only by construction).
 */
final class AuditReader
{
    public const OUTCOMES = ['success', 'denied', 'failure'];

    public function __construct(private readonly Database $auditorDb)
    {
    }

    /** @param array{from?:string,to?:string,actor?:string,action?:string,outcome?:string,resource_type?:string,resource_id?:string,correlation?:string} $f */
    public function timeline(array $f, int $limit = 200): array
    {
        // Each filter contributes a fixed SQL fragment plus bound values;
        // user input never becomes part of the SQL text.
        $where = [];
        $args = [];
        if (($f['from'] ?? '') !== '') { $where[] = 'occurred_at >= ?::date'; $args[] = $f['from']; }
        if (($f['to'] ?? '') !== '') { $where[] = "occurred_at < ?::date + interval '1 day'"; $args[] = $f['to']; }
        if (($f['actor'] ?? '') !== '') { $where[] = 'actor_email = ?'; $args[] = $f['actor']; }
        if (($f['action'] ?? '') !== '') { $where[] = 'action = ?'; $args[] = $f['action']; }
        if (($f['outcome'] ?? '') !== '') { $where[] = 'outcome = ?'; $args[] = $f['outcome']; }
        if (($f['resource_type'] ?? '') !== '') { $where[] = 'resource_type = ?'; $args[] = $f['resource_type']; }
        if (($f['resource_id'] ?? '') !== '') { $where[] = 'resource_id = ?'; $args[] = (int) $f['resource_id']; }
        if (($f['correlation'] ?? '') !== '') { $where[] = 'correlation_id = ?::uuid'; $args[] = $f['correlation']; }

        $sql = 'SELECT id, occurred_at, actor_email, actor_name, actor_role, action, resource_type,
                       resource_id, outcome, correlation_id, source_ip, details, actor_verified
                FROM audit_timeline'
             . ($where ? ' WHERE ' . implode(' AND ', $where) : '')
             . ' ORDER BY occurred_at DESC, id DESC LIMIT ' . max(1, min($limit, 5000));
        $stmt = $this->auditorDb->pdo()->prepare($sql);
        $stmt->execute($args);
        return $stmt->fetchAll();
    }

    /** Values for the filter drop-downs. */
    public function filterOptions(): array
    {
        $pdo = $this->auditorDb->pdo();
        return [
            'actions' => $pdo->query('SELECT DISTINCT action FROM audit_timeline ORDER BY 1')->fetchAll(\PDO::FETCH_COLUMN),
            'actors'  => $pdo->query('SELECT DISTINCT actor_email FROM audit_timeline WHERE actor_email IS NOT NULL ORDER BY 1')->fetchAll(\PDO::FETCH_COLUMN),
            'types'   => $pdo->query('SELECT DISTINCT resource_type FROM audit_timeline WHERE resource_type IS NOT NULL ORDER BY 1')->fetchAll(\PDO::FETCH_COLUMN),
        ];
    }
}
