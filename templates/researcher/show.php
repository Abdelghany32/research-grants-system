<header class="page-head">
  <p class="eyebrow"><a href="/proposals">My proposals</a> / Proposal</p>
  <h1 class="serif"><?= e($p['title']) ?></h1>
  <p class="lede"><?= status_badge($p['status']) ?> <?= e($p['call_title']) ?></p>
</header>
<div class="split">
  <article class="card">
    <h2>Abstract</h2>
    <p class="prose"><?= nl2br(e($p['abstract'])) ?></p>
  </article>
  <aside class="card">
    <h2>Summary</h2>
    <dl class="facts facts-rows">
      <div><dt>Requested</dt><dd class="num"><?= e(money($p['requested_amount'])) ?> <?= e($p['currency']) ?></dd></div>
      <div><dt>Submitted</dt><dd><?= utc($p['submitted_at']) ?></dd></div>
<?php if ($p['outcome'] !== null): ?>
      <div><dt>Decision</dt><dd><?= status_badge($p['outcome']) ?></dd></div>
      <div><dt>Awarded</dt><dd class="num"><?= e(money($p['awarded_amount'])) ?> <?= e($p['currency']) ?></dd></div>
      <div><dt>Decided</dt><dd><?= utc($p['decided_at']) ?></dd></div>
<?php endif; ?>
    </dl>
<?php if ($p['outcome'] !== null && $p['rationale'] !== ''): ?>
    <h3>Message from the grants office</h3>
    <p class="prose"><?= nl2br(e($p['rationale'])) ?></p>
<?php elseif ($p['outcome'] === null): ?>
    <p class="hint">No decision yet. Reviewer scores and comments are confidential; you will see the final decision here.</p>
<?php endif; ?>
  </aside>
</div>
