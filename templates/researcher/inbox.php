<?php
$next = [
    'draft' => 'Finish and submit', 'submitted' => 'Waiting for reviewer assignment',
    'under_review' => 'Waiting for review', 'approved' => 'View decision', 'declined' => 'View decision',
];
?>
<header class="page-head">
  <p class="eyebrow">Researcher</p>
  <h1>Open calls</h1>
</header>

<section aria-labelledby="calls-h">
  <h2 id="calls-h" class="visually-hidden">Open grant calls</h2>
<?php if (!$calls): ?>
  <p class="empty">No grant call is open right now. New calls appear here when the research office publishes them.</p>
<?php else: ?>
  <ul class="call-list">
<?php foreach ($calls as $c): ?>
    <li class="card call">
      <div>
        <h3 class="serif"><?= e($c['title']) ?></h3>
        <p class="muted"><?= e($c['description']) ?></p>
      </div>
      <dl class="facts">
        <div><dt>Deadline</dt><dd><?= utc($c['closes_at']) ?></dd></div>
        <div><dt>Total budget</dt><dd class="num"><?= e(money($c['total_budget'])) ?> <?= e($c['currency']) ?></dd></div>
      </dl>
      <a class="btn btn-primary" href="/proposals/new?call=<?= e($c['id']) ?>"><?= icon('plus') ?><span>Start proposal</span></a>
    </li>
<?php endforeach; ?>
  </ul>
<?php endif; ?>
</section>

<section aria-labelledby="mine-h">
  <div class="section-head">
    <h2 id="mine-h">My proposals</h2>
    <p class="tally">
      <?= (int) ($counts['draft'] ?? 0) ?> draft ·
      <?= (int) (($counts['submitted'] ?? 0) + ($counts['under_review'] ?? 0)) ?> in progress ·
      <?= (int) (($counts['approved'] ?? 0) + ($counts['declined'] ?? 0)) ?> decided
    </p>
  </div>
  <form class="search" method="get" action="/proposals" role="search">
    <label for="q">Search my proposals by title</label>
    <div class="search-row">
      <input id="q" name="q" type="search" value="<?= e($q) ?>" maxlength="200">
      <button class="btn" type="submit"><?= icon('search') ?><span>Search</span></button>
<?php if ($q !== ''): ?>
      <a class="btn btn-quiet" href="/proposals">Clear</a>
<?php endif; ?>
    </div>
  </form>
<?php if (!$proposals): ?>
  <p class="empty"><?= $q !== '' ? 'None of your proposals has a title containing “' . e($q) . '”.'
                               : 'You have no proposals yet. Choose an open call above and select “Start proposal”.' ?></p>
<?php else: ?>
  <table class="stack">
    <thead><tr><th scope="col">Title</th><th scope="col">Call</th><th scope="col" class="num">Requested</th><th scope="col">Status</th><th scope="col">Next action</th></tr></thead>
    <tbody>
<?php foreach ($proposals as $p): ?>
      <tr>
        <td data-label="Title"><a class="serif title-link" href="/proposals/<?= e($p['id']) ?>"><?= e($p['title']) ?></a></td>
        <td data-label="Call"><?= e($p['call_title']) ?></td>
        <td data-label="Requested" class="num"><?= e(money($p['requested_amount'])) ?> <?= e($p['currency']) ?></td>
        <td data-label="Status"><?= status_badge($p['status']) ?></td>
        <td data-label="Next action"><?php if ($p['status'] === 'draft' && !$p['call_open']): ?>Call closed — cannot be submitted<?php else: ?><?= e($next[$p['status']]) ?><?php endif; ?></td>
      </tr>
<?php endforeach; ?>
    </tbody>
  </table>
<?php endif; ?>
</section>
