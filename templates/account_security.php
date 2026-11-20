<section class="card medium">
  <p class="eyebrow">Account</p>
  <h1 class="compact"><?= icon('shield') ?> Sign-in security</h1>
  <p class="lede">Security keys are the strongest second factor: the key proves it is talking to this site, so a look-alike page cannot capture it.</p>
<?php if ($keys === []): ?>
  <p class="hint">No security key is registered. You sign in with your authenticator app.</p>
<?php else: ?>
  <table class="keys">
    <thead><tr><th scope="col">Key</th><th scope="col">Added</th><th scope="col">Last used</th><th scope="col"><span class="sr-only">Remove</span></th></tr></thead>
    <tbody>
<?php foreach ($keys as $k): ?>
      <tr>
        <td><?= e($k['name']) ?></td>
        <td><?= e(substr((string) $k['created_at'], 0, 16)) ?></td>
        <td><?= $k['last_used_at'] ? e(substr((string) $k['last_used_at'], 0, 16)) : 'never' ?></td>
        <td>
          <form method="post" action="/account/security/webauthn/<?= (int) $k['id'] ?>/delete">
            <?= csrf_field($app) ?>
            <button class="btn btn-quiet" type="submit" data-confirm="Remove this security key?"><?= icon('trash') ?><span>Remove</span></button>
          </form>
        </td>
      </tr>
<?php endforeach; ?>
    </tbody>
  </table>
<?php endif; ?>
  <div id="wa-register" data-csrf="<?= e(App\Auth\Csrf::token($app->session())) ?>" hidden>
    <div class="field">
      <label for="wa-name">Name for the new key</label>
      <input id="wa-name" type="text" maxlength="60" value="Security key" autocomplete="off">
    </div>
    <button id="wa-add" class="btn btn-primary" type="button"><?= icon('plus') ?><span>Add a security key</span></button>
    <p class="flash flash-error" id="wa-error" role="alert" hidden></p>
  </div>
  <p class="hint" id="wa-unsupported" hidden>This browser does not support security keys.</p>
</section>
<script src="/assets/js/webauthn.js" defer></script>
