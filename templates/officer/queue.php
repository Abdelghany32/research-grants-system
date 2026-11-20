<header class="page-head">
  <p class="eyebrow">Grants officer</p>
  <h1>Decision queue</h1>
  <p class="tally">
    <?= (int) ($counts['submitted'] ?? 0) ?> need a reviewer ·
    <?= (int) ($counts['under_review'] ?? 0) ?> under review ·
    <?= (int) (($counts['approved'] ?? 0) + ($counts['declined'] ?? 0)) ?> decided
  </p>
</header>
<form class="search" method="get" action="/officer" role="search">
  <label for="q">Search submitted proposals by title</label>
  <div class="search-row">
    <input id="q" name="q" type="search" value="<?= e($q) ?>" maxlength="200">
    <button class="btn" type="submit"><?= icon('search') ?><span>Search</span></button>
<?php if ($q !== ''): ?>
    <a class="btn btn-quiet" href="/officer">Clear</a>
<?php endif; ?>
  </div>
</form>
<?php if (!$proposals): ?>
<p class="empty"><?= $q !== '' ? 'No submitted proposal has a title containing “' . e($q) . '”.' : 'No proposal has been submitted yet. Drafts stay private to their authors.' ?></p>
<?php else: ?>
<table class="stack">
  <thead><tr><th scope="col">Proposal</th><th scope="col">Applicant</th><th scope="col">Call</th><th scope="col" class="num">Requested</th><th scope="col">Status</th><th scope="col">Reviews</th></tr></thead>
  <tbody>
<?php foreach ($proposals as $p): ?>
    <tr>
      <td data-label="Proposal"><a class="serif title-link" href="/officer/proposals/<?= e($p['id']) ?>"><?= e($p['title']) ?></a></td>
      <td data-label="Applicant"><?= e($p['applicant_name']) ?></td>
      <td data-label="Call"><?= e($p['call_title']) ?></td>
      <td data-label="Requested" class="num"><?= e(money($p['requested_amount'])) ?> <?= e($p['currency']) ?></td>
      <td data-label="Status"><?= status_badge($p['status']) ?></td>
      <td data-label="Reviews"><?= (int) $p['reviews_done'] ?> of <?= (int) $p['reviews_assigned'] ?> complete<?= (int) $p['reviews_overdue'] > 0 ? ' <span class="badge badge-denied">' . (int) $p['reviews_overdue'] . ' overdue</span>' : '' ?></td>
    </tr>
<?php endforeach; ?>
  </tbody>
</table>
<?php endif; ?>
