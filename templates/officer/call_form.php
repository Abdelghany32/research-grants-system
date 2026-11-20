<header class="page-head">
  <p class="eyebrow"><a href="/officer/calls">Grant calls</a> / <?= $call === null ? 'New' : 'Edit' ?></p>
  <h1><?= $call === null ? 'New grant call' : 'Edit grant call' ?></h1>
</header>
<?php if ($errors): ?>
<p class="flash flash-error" role="alert"><?= icon('alert') ?> Please correct the highlighted fields.</p>
<?php endif; ?>
<form class="card form" method="post" action="<?= $call === null ? '/officer/calls' : '/officer/calls/' . e($call['id']) ?>" novalidate>
  <?= csrf_field($app) ?>
  <div class="field">
    <label for="title">Call title</label>
    <input id="title" name="title" type="text" class="serif" maxlength="200" required value="<?= e($values['title']) ?>"<?= invalid_attrs($errors, 'title') ?>>
    <?= field_error($errors, 'title') ?>
  </div>
  <div class="field">
    <label for="description">Description</label>
    <textarea id="description" name="description" rows="4" maxlength="4000"<?= invalid_attrs($errors, 'description') ?>><?= e($values['description']) ?></textarea>
    <?= field_error($errors, 'description') ?>
  </div>
<?php if ($call === null): ?>
  <div class="field-row">
    <div class="field field-short">
      <label for="total_budget">Total budget</label>
      <input id="total_budget" name="total_budget" type="text" inputmode="decimal" class="num" required value="<?= e($values['total_budget']) ?>"<?= invalid_attrs($errors, 'total_budget') ?>>
      <?= field_error($errors, 'total_budget') ?>
    </div>
    <div class="field field-short">
      <label for="currency">Currency (ISO code)</label>
      <input id="currency" name="currency" type="text" maxlength="3" required value="<?= e($values['currency']) ?>"<?= invalid_attrs($errors, 'currency') ?>>
      <?= field_error($errors, 'currency') ?>
    </div>
  </div>
<?php else: ?>
  <p class="notice"><?= icon('lock') ?> Budget <?= e(money($call['total_budget'])) ?> <?= e($call['currency']) ?>, remaining <?= e(money($call['remaining_budget'])) ?>. The budget is fixed once a call is published; the balance only changes through recorded decisions.</p>
  <fieldset class="field">
    <legend>Status</legend>
    <label class="choice"><input type="radio" name="status" value="open"<?= $values['status'] === 'open' ? ' checked' : '' ?>> Open for proposals</label>
    <label class="choice"><input type="radio" name="status" value="closed"<?= $values['status'] === 'closed' ? ' checked' : '' ?>> Closed</label>
    <?= field_error($errors, 'status') ?>
  </fieldset>
<?php endif; ?>
  <div class="field field-short">
    <label for="closes_on">Closing date (end of day, UTC)</label>
    <input id="closes_on" name="closes_on" type="date" required value="<?= e($values['closes_on']) ?>"<?= invalid_attrs($errors, 'closes_on') ?>>
    <?= field_error($errors, 'closes_on') ?>
  </div>
  <div class="actions">
    <button class="btn btn-primary" type="submit"><?= icon('save') ?><span><?= $call === null ? 'Publish call' : 'Save changes' ?></span></button>
    <a class="btn btn-quiet" href="/officer/calls">Cancel</a>
  </div>
</form>
