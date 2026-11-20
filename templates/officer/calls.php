<header class="page-head head-with-action">
  <div>
    <p class="eyebrow">Grants officer</p>
    <h1>Grant calls</h1>
  </div>
  <a class="btn btn-primary" href="/officer/calls/new"><?= icon('plus') ?><span>New call</span></a>
</header>
<?php if (!$calls): ?>
<p class="empty">No grant call exists yet. Select “New call” to publish the first one.</p>
<?php else: ?>
<table class="stack">
  <thead><tr><th scope="col">Call</th><th scope="col">Deadline</th><th scope="col">Status</th><th scope="col" class="num">Proposals</th><th scope="col" class="num">Budget</th><th scope="col" class="num">Remaining</th></tr></thead>
  <tbody>
<?php foreach ($calls as $c): ?>
    <tr>
      <td data-label="Call"><a class="serif title-link" href="/officer/calls/<?= e($c['id']) ?>"><?= e($c['title']) ?></a></td>
      <td data-label="Deadline"><?= utc($c['closes_at']) ?></td>
      <td data-label="Status"><?= status_badge($c['is_open'] ? 'open' : 'closed') ?></td>
      <td data-label="Proposals" class="num"><?= (int) $c['proposal_count'] ?></td>
      <td data-label="Budget" class="num"><?= e(money($c['total_budget'])) ?> <?= e($c['currency']) ?></td>
      <td data-label="Remaining" class="num"><?= e(money($c['remaining_budget'])) ?> <?= e($c['currency']) ?></td>
    </tr>
<?php endforeach; ?>
  </tbody>
</table>
<?php endif; ?>
