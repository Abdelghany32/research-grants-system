<?php $action = $proposal === null ? '/proposals' : '/proposals/' . $proposal['id']; ?>
<header class="page-head">
  <p class="eyebrow"><a href="/proposals">My proposals</a> / <?= $proposal === null ? 'New proposal' : 'Draft' ?></p>
  <h1><?= $proposal === null ? 'New proposal' : 'Edit draft' ?></h1>
  <p class="lede">For <strong><?= e($call['title']) ?></strong> · deadline <?= utc($call['closes_at']) ?></p>
</header>
<?php if ($errors): ?>
<p class="flash flash-error" role="alert"><?= icon('alert') ?> Nothing was lost. Please correct the highlighted fields.</p>
<?php endif; ?>
<?php if (!$call['is_open']): ?>
<p class="flash flash-error"><?= icon('alert') ?> This call has closed. The draft can still be edited but can no longer be submitted.</p>
<?php endif; ?>
<form class="card form" method="post" action="<?= e($action) ?>" novalidate>
  <?= csrf_field($app) ?>
  <input type="hidden" name="call_id" value="<?= e($call['id']) ?>">
  <div class="field">
    <label for="title">Proposal title</label>
    <input id="title" name="title" type="text" class="serif" maxlength="200" required value="<?= e($values['title']) ?>"<?= invalid_attrs($errors, 'title') ?>>
    <?= field_error($errors, 'title') ?>
  </div>
  <div class="field">
    <label for="abstract">Abstract</label>
    <p class="hint" id="abstract-hint">Required to submit. Up to 5,000 characters. Visible to assigned reviewers and the grants office.</p>
    <textarea id="abstract" name="abstract" rows="10" maxlength="5000" aria-describedby="abstract-hint<?= isset($errors['abstract']) ? ' abstract-error' : '' ?>"<?= isset($errors['abstract']) ? ' aria-invalid="true"' : '' ?>><?= e($values['abstract']) ?></textarea>
    <?= field_error($errors, 'abstract') ?>
  </div>
  <div class="field field-short">
    <label for="requested_amount">Requested amount (<?= e($call['currency']) ?>)</label>
    <p class="hint" id="amount-hint">Call budget: <?= e(money($call['total_budget'])) ?> <?= e($call['currency']) ?></p>
    <input id="requested_amount" name="requested_amount" type="text" inputmode="decimal" class="num" required value="<?= e($values['requested_amount']) ?>" aria-describedby="amount-hint<?= isset($errors['requested_amount']) ? ' requested_amount-error' : '' ?>"<?= isset($errors['requested_amount']) ? ' aria-invalid="true"' : '' ?>>
    <?= field_error($errors, 'requested_amount') ?>
  </div>
  <div class="actions">
    <button class="btn" type="submit" name="intent" value="save"><?= icon('save') ?><span>Save draft</span></button>
<?php if ($call['is_open']): ?>
    <div class="final-action">
      <button class="btn btn-primary" type="submit" name="intent" value="submit" data-confirm="Submit this proposal? After submission it can no longer be edited."><?= icon('send') ?><span>Submit proposal</span></button>
      <p class="hint">Final. A submitted proposal cannot be edited.</p>
    </div>
<?php endif; ?>
  </div>
</form>
<?php if ($proposal !== null): ?>
<form class="danger-zone" method="post" action="/proposals/<?= e($proposal['id']) ?>/delete">
  <?= csrf_field($app) ?>
  <button class="btn btn-quiet btn-danger" type="submit" data-confirm="Delete this draft permanently?"><?= icon('trash') ?><span>Delete draft</span></button>
</form>
<?php endif; ?>
