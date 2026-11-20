<?php $final = $r['status'] === 'submitted'; $overdue = !empty($r['overdue']); $open = !$final && !$overdue && $r['proposal_status'] === 'under_review'; ?>
<header class="page-head">
  <p class="eyebrow"><a href="/reviews">My reviews</a> / Review</p>
  <h1 class="serif"><?= e($r['title']) ?></h1>
  <p class="lede"><?= status_badge($r['status']) ?>
    Assigned <?= utc($r['assigned_at'], false) ?> ·
    <?= $r['due_at'] ? 'review due ' . utc($r['due_at'], false) : 'no review deadline' ?>
    <?= $final ? ' · submitted ' . utc($r['submitted_at']) : '' ?></p>
</header>
<div class="split">
  <article class="card">
    <h2>Proposal summary</h2>
    <dl class="facts">
      <div><dt>Applicant</dt><dd><?= e($r['applicant_name']) ?>, <?= e($r['applicant_department']) ?></dd></div>
      <div><dt>Call</dt><dd><?= e($r['call_title']) ?></dd></div>
      <div><dt>Requested</dt><dd class="num"><?= e(money($r['requested_amount'])) ?> <?= e($r['currency']) ?></dd></div>
    </dl>
    <h3>Abstract</h3>
    <p class="prose"><?= nl2br(e($r['abstract'])) ?></p>
  </article>
  <section class="card" aria-labelledby="review-h">
    <h2 id="review-h">Your review</h2>
<?php if ($final): ?>
    <p class="notice"><?= icon('lock') ?> Submitted. This review is final and can no longer be changed.</p>
    <dl class="facts facts-rows">
      <div><dt>Score</dt><dd class="num"><?= e($r['score']) ?> / 10</dd></div>
    </dl>
    <h3>Confidential comments</h3>
    <p class="prose"><?= nl2br(e($r['comments'])) ?></p>
<?php elseif ($overdue): ?>
    <p class="notice"><?= icon('lock') ?> The deadline for this review has passed, so the form is closed. Ask the grants office for an extension.</p>
<?php elseif (!$open): ?>
    <p class="notice"><?= icon('lock') ?> This proposal is no longer under review, so the review form is closed.</p>
<?php else: ?>
    <form method="post" action="/reviews/<?= e($r['id']) ?>" novalidate>
      <?= csrf_field($app) ?>
      <div class="field field-short">
        <label for="score">Score (1 = weak, 10 = outstanding)</label>
        <input id="score" name="score" type="number" min="1" max="10" step="1" inputmode="numeric" class="num" value="<?= e($values['score']) ?>"<?= invalid_attrs($errors, 'score') ?>>
        <?= field_error($errors, 'score') ?>
      </div>
      <div class="field">
        <label for="comments">Confidential comments</label>
        <p class="hint" id="comments-hint">Seen by the grants office only. Never shown to the applicant. Stored encrypted.</p>
        <textarea id="comments" name="comments" rows="9" maxlength="4000" aria-describedby="comments-hint<?= isset($errors['comments']) ? ' comments-error' : '' ?>"<?= isset($errors['comments']) ? ' aria-invalid="true"' : '' ?>><?= e($values['comments']) ?></textarea>
        <?= field_error($errors, 'comments') ?>
      </div>
      <div class="actions">
        <button class="btn" type="submit" name="intent" value="save"><?= icon('save') ?><span>Save draft</span></button>
        <div class="final-action">
          <button class="btn btn-primary" type="submit" name="intent" value="submit" data-confirm="Submit this review? It cannot be changed afterwards."><?= icon('send') ?><span>Submit final review</span></button>
          <p class="hint">Final. A submitted review cannot be edited.</p>
        </div>
      </div>
    </form>
<?php endif; ?>
  </section>
</div>
