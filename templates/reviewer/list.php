<header class="page-head">
  <p class="eyebrow">Reviewer</p>
  <h1>My reviews</h1>
  <p class="tally"><?= (int) ($counts['assigned'] ?? 0) ?> awaiting your review · <?= (int) ($counts['submitted'] ?? 0) ?> submitted</p>
</header>
<?php if (!$assignments): ?>
<p class="empty">No proposal is assigned to you. Assignments appear here when the grants office requests your review.</p>
<?php else: ?>
<table class="stack">
  <thead><tr><th scope="col">Proposal</th><th scope="col">Call</th><th scope="col">Review due</th><th scope="col">Your review</th><th scope="col" class="num">Score</th></tr></thead>
  <tbody>
<?php foreach ($assignments as $a): ?>
    <tr>
      <td data-label="Proposal"><a class="serif title-link" href="/reviews/<?= e($a['id']) ?>"><?= e($a['title']) ?></a></td>
      <td data-label="Call"><?= e($a['call_title']) ?></td>
      <td data-label="Review due"><?= $a['due_at'] ? utc($a['due_at'], false) . (!empty($a['overdue']) ? ' <span class="badge badge-denied">Overdue</span>' : '') : '<span class="muted">No deadline</span>' ?></td>
      <td data-label="Your review"><?= status_badge($a['status']) ?></td>
      <td data-label="Score" class="num"><?= $a['status'] === 'submitted' ? e($a['score']) . ' / 10' : '—' ?></td>
    </tr>
<?php endforeach; ?>
  </tbody>
</table>
<?php endif; ?>
