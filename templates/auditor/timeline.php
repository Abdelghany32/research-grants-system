<?php
$select = static function (string $name, string $label, array $choices, string $current): string {
    $h = '<div class="field"><label for="f-' . e($name) . '">' . e($label) . '</label><select id="f-' . e($name) . '" name="' . e($name) . '"><option value="">Any</option>';
    foreach ($choices as $c) {
        $h .= '<option value="' . e($c) . '"' . ($c === $current ? ' selected' : '') . '>' . e($c) . '</option>';
    }
    return $h . '</select></div>';
};
$active = array_filter($f);
?>
<header class="page-head">
  <p class="eyebrow">Auditor · read-only</p>
  <h1>Audit timeline</h1>
  <p class="lede">Security event metadata. Proposal text and review comments are never part of this record.</p>
</header>
<form class="card filters" method="get" action="/audit">
  <div class="field"><label for="f-from">From (UTC date)</label><input id="f-from" name="from" type="date" value="<?= e($f['from']) ?>"></div>
  <div class="field"><label for="f-to">To (UTC date)</label><input id="f-to" name="to" type="date" value="<?= e($f['to']) ?>"></div>
  <?= $select('actor', 'Actor', $options['actors'], $f['actor']) ?>
  <?= $select('action', 'Action', $options['actions'], $f['action']) ?>
  <?= $select('outcome', 'Outcome', App\Audit\AuditReader::OUTCOMES, $f['outcome']) ?>
  <?= $select('resource_type', 'Resource type', $options['types'], $f['resource_type']) ?>
  <div class="field"><label for="f-resource_id">Resource ID</label><input id="f-resource_id" name="resource_id" type="text" inputmode="numeric" value="<?= e($f['resource_id']) ?>"></div>
  <div class="field"><label for="f-correlation">Correlation ID</label><input id="f-correlation" name="correlation" type="text" value="<?= e($f['correlation']) ?>"></div>
  <div class="actions">
    <button class="btn btn-primary" type="submit"><?= icon('search') ?><span>Apply filters</span></button>
<?php if ($active): ?>
    <a class="btn btn-quiet" href="/audit">Clear filters</a>
<?php endif; ?>
    <a class="btn btn-quiet" href="/audit/export.csv?<?= e(http_build_query(array_filter($f))) ?>" download title="Download the events that match the filters as a CSV file (at most 5,000 rows)"><?= icon('download') ?><span>Export CSV</span></a>
  </div>
</form>
<p class="tally"><?= count($events) ?> event<?= count($events) === 1 ? '' : 's' ?> shown<?= count($events) >= 200 ? ' (newest 200; narrow the filters to see older events)' : '' ?></p>
<?php if (!$events): ?>
<p class="empty"><?= $active ? 'No event matches these filters. Remove a filter to widen the search.' : 'No security event has been recorded yet.' ?></p>
<?php else: ?>
<table class="stack timeline">
  <thead><tr><th scope="col">Time (UTC)</th><th scope="col">Actor</th><th scope="col">Action</th><th scope="col">Resource</th><th scope="col">Outcome</th><th scope="col">Details</th></tr></thead>
  <tbody>
<?php foreach ($events as $ev): ?>
    <tr class="outcome-<?= e($ev['outcome']) ?>">
      <td data-label="Time (UTC)"><?= utc($ev['occurred_at']) ?></td>
      <td data-label="Actor"><?= $ev['actor_email'] !== null ? e($ev['actor_name']) . ' <span class="muted">' . e($ev['actor_role']) . '</span>' . ($ev['actor_verified'] ? '' : ' <span class="muted" title="The actor is named, not proved: for example an account that failed to sign in, or an event written before identity binding.">(unverified)</span>') : '<span class="muted">Not signed in</span>' ?></td>
      <td data-label="Action"><code><?= e($ev['action']) ?></code></td>
      <td data-label="Resource"><?= $ev['resource_type'] !== null ? e($ev['resource_type']) . ($ev['resource_id'] !== null ? ' #' . e($ev['resource_id']) : '') : '—' ?></td>
      <td data-label="Outcome"><?= status_badge($ev['outcome']) ?></td>
      <td data-label="Details" class="details">
        <?php foreach (json_decode($ev['details'], true) ?: [] as $k => $v): ?><span class="kv"><?= e($k) ?>: <?= e(is_scalar($v) ? $v : json_encode($v)) ?></span> <?php endforeach; ?>
        <a class="corr" href="/audit?correlation=<?= e($ev['correlation_id']) ?>" title="Show all events from the same request">req <?= e(substr((string) $ev['correlation_id'], 0, 8)) ?></a>
      </td>
    </tr>
<?php endforeach; ?>
  </tbody>
</table>
<?php endif; ?>
