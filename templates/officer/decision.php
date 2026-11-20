<?php $cur = e($p['currency']); ?>
<header class="page-head">
  <p class="eyebrow"><a href="/officer">Decision queue</a> / Proposal</p>
  <h1 class="serif"><?= e($p['title']) ?></h1>
  <p class="lede"><?= status_badge($p['status']) ?> <?= e($p['applicant_name']) ?>, <?= e($p['applicant_department']) ?> · <?= e($p['call_title']) ?></p>
</header>

<section class="card ledger" aria-labelledby="funds-h">
  <h2 id="funds-h">Funding position</h2>
  <dl class="figures">
    <div><dt>Requested</dt><dd class="num"><?= e(money($p['requested_amount'])) ?> <span class="cur"><?= $cur ?></span></dd></div>
    <div><dt>Available in call</dt><dd class="num"><?= e(money($p['remaining_budget'])) ?> <span class="cur"><?= $cur ?></span></dd></div>
<?php if ($p['outcome'] !== null): ?>
    <div><dt>Awarded</dt><dd class="num"><?= e(money($p['awarded_amount'])) ?> <span class="cur"><?= $cur ?></span></dd></div>
<?php else: ?>
    <div><dt>Proposed award</dt><dd class="num"><output id="proposed-award" for="awarded_amount">—</output> <span class="cur"><?= $cur ?></span></dd></div>
    <div><dt>Resulting balance</dt><dd class="num"><output id="resulting-balance" for="awarded_amount" data-available="<?= e($p['remaining_budget']) ?>" data-requested="<?= e($p['requested_amount']) ?>">—</output> <span class="cur"><?= $cur ?></span></dd></div>
<?php endif; ?>
  </dl>
  <p class="hint" id="balance-note" aria-live="polite"><?= $p['outcome'] === null ? 'Figures are previewed in the browser and recalculated on the server when you confirm.' : 'Total call budget ' . e(money($p['total_budget'])) . ' ' . $cur . '.' ?></p>
</section>

<div class="split">
  <div class="stack-col">
    <section class="card" aria-labelledby="reviews-h">
      <h2 id="reviews-h">Reviews</h2>
<?php if (!$p['reviews']): ?>
      <p class="empty">No reviewer is assigned yet.</p>
<?php endif; ?>
<?php foreach ($p['reviews'] as $r): ?>
      <div class="review">
        <p><strong><?= e($r['reviewer_name']) ?></strong> <?= status_badge($r['status']) ?>
<?php if ($r['status'] === 'submitted'): ?>
          <span class="score num"><?= e($r['score']) ?> / 10</span></p>
        <p class="prose"><?= nl2br(e($r['comments'])) ?></p>
        <p class="hint">Submitted <?= utc($r['submitted_at']) ?>. The reviewer’s score is final and cannot be altered.</p>
<?php else: ?>
        <?= $r['overdue'] ? '<span class="badge badge-denied">Overdue</span>' : '' ?></p><p class="hint">Assigned <?= utc($r['assigned_at'], false) ?><?= $r['due_at'] ? ', due ' . utc($r['due_at'], false) : '' ?>.</p>
<?php if ($p['outcome'] === null && $r['status'] === 'assigned'): ?>
        <form class="inline-form" method="post" action="/officer/reviews/<?= e($r['id']) ?>/extend">
          <?= csrf_field($app) ?>
          <input type="hidden" name="proposal_id" value="<?= e($p['id']) ?>">
          <div class="field">
            <label for="extend-<?= e($r['id']) ?>">New deadline</label>
            <input id="extend-<?= e($r['id']) ?>" name="due_at" type="date" required>
          </div>
          <button class="btn" type="submit"><?= icon('plus') ?><span>Extend deadline</span></button>
        </form>
<?php endif; ?>
<?php endif; ?>
      </div>
<?php endforeach; ?>
<?php if ($p['outcome'] === null): ?>
<?php if ($reviewers): ?>
      <form class="inline-form" method="post" action="/officer/proposals/<?= e($p['id']) ?>/assign">
        <?= csrf_field($app) ?>
        <div class="field">
          <label for="reviewer_id">Assign a reviewer</label>
          <select id="reviewer_id" name="reviewer_id" required>
<?php foreach ($reviewers as $rv): ?>
            <option value="<?= e($rv['id']) ?>"><?= e($rv['full_name']) ?> — <?= e($rv['department']) ?></option>
<?php endforeach; ?>
          </select>
        </div>
        <div class="field">
          <label for="due_at">Review due (optional)</label>
          <input id="due_at" name="due_at" type="date"<?= invalid_attrs($errors, 'due_at') ?>>
          <?= field_error($errors, 'due_at') ?>
        </div>
        <button class="btn" type="submit"><?= icon('plus') ?><span>Assign reviewer</span></button>
      </form>
<?php else: ?>
      <p class="hint">Every eligible reviewer is already assigned.</p>
<?php endif; ?>
<?php endif; ?>
    </section>
    <article class="card">
      <h2>Abstract</h2>
      <p class="prose"><?= nl2br(e($p['abstract'])) ?></p>
    </article>
  </div>

  <div class="stack-col">
    <section class="card" aria-labelledby="decision-h">
      <h2 id="decision-h">Decision</h2>
<?php if ($p['outcome'] !== null): ?>
      <p class="notice"><?= icon('lock') ?> Final decision: <?= status_badge($p['outcome']) ?> by <?= e($p['decided_by_name']) ?> on <?= utc($p['decided_at']) ?>.</p>
<?php if ($p['rationale'] !== ''): ?>
      <p class="prose"><?= nl2br(e($p['rationale'])) ?></p>
<?php endif; ?>
<?php elseif ($blocked !== null): ?>
      <p class="notice"><?= icon('lock') ?> <?= e($blocked) ?></p>
<?php else: ?>
<?php if (isset($errors['decision'])): ?>
      <p class="flash flash-error" role="alert"><?= icon('alert') ?> <?= e($errors['decision']) ?></p>
<?php endif; ?>
      <form id="decision-form" method="post" action="/officer/proposals/<?= e($p['id']) ?>/decision" novalidate>
        <?= csrf_field($app) ?>
        <fieldset class="field">
          <legend>Outcome</legend>
          <label class="choice"><input type="radio" name="outcome" value="approved"<?= $values['outcome'] === 'approved' ? ' checked' : '' ?>> Approve funding</label>
          <label class="choice"><input type="radio" name="outcome" value="declined"<?= $values['outcome'] === 'declined' ? ' checked' : '' ?>> Decline</label>
          <?= field_error($errors, 'outcome') ?>
        </fieldset>
        <div class="field field-short">
          <label for="awarded_amount">Award amount (<?= $cur ?>)</label>
          <p class="hint" id="award-hint">At most the requested amount and the available funds.</p>
          <input id="awarded_amount" name="awarded_amount" type="text" inputmode="decimal" class="num" value="<?= e($values['awarded_amount']) ?>" aria-describedby="award-hint<?= isset($errors['awarded_amount']) ? ' awarded_amount-error' : '' ?>"<?= isset($errors['awarded_amount']) ? ' aria-invalid="true"' : '' ?>>
          <?= field_error($errors, 'awarded_amount') ?>
        </div>
        <div class="field">
          <label for="rationale">Message to the applicant (optional)</label>
          <textarea id="rationale" name="rationale" rows="4" maxlength="2000"<?= invalid_attrs($errors, 'rationale') ?>><?= e($values['rationale']) ?></textarea>
          <?= field_error($errors, 'rationale') ?>
        </div>
        <div class="final-action">
          <button class="btn btn-primary" type="submit" data-confirm="Record this decision? It is final."><?= icon('decisions') ?><span>Confirm decision</span></button>
          <p class="hint">Final. One decision per proposal.</p>
        </div>
      </form>
<?php endif; ?>
    </section>
  </div>
</div>
