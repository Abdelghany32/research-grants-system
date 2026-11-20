<section class="card narrow login">
  <p class="eyebrow">University Research Office</p>
<?php if ($enrolled): ?>
  <h1><?= icon('shield') ?> Second factor</h1>
  <p class="lede">Hello <?= e($pending->fullName) ?>. Enter the <?= $recovery ? 'recovery code' : '6-digit code from your authenticator app' ?>.</p>
<?php else: ?>
  <h1 class="compact"><?= icon('shield') ?> Set up two-step sign-in</h1>
  <p class="lede">Your role requires a second factor. Add this account to an authenticator app (any TOTP app works), then enter the code it shows.</p>
<?php endif; ?>
<?php if (isset($errors['code'])): ?>
  <p class="flash flash-error" role="alert" id="code-error"><?= icon('alert') ?> <?= e($errors['code']) ?></p>
<?php endif; ?>
<?php if (!$enrolled): ?>
  <dl class="facts facts-rows">
    <div><dt>Account</dt><dd><?= e($pending->email) ?></dd></div>
    <div><dt>Setup key</dt><dd><code id="mfa-secret"><?= e(implode(' ', str_split($secret, 4))) ?></code></dd></div>
    <div><dt>Type</dt><dd>Time-based (TOTP), 6 digits, 30 seconds, SHA-1</dd></div>
  </dl>
  <p class="hint">Enter the setup key manually in your app, or open this address on the phone that has the app: <code class="corr wrap-anywhere"><?= e($uri) ?></code></p>
<?php endif; ?>
  <form method="post" action="/login/mfa" novalidate>
    <?= csrf_field($app) ?>
<?php if ($enrolled && $recovery): ?>
    <input type="hidden" name="mode" value="recovery">
    <div class="field">
      <label for="recovery_code">Recovery code</label>
      <input id="recovery_code" name="recovery_code" type="text" autocomplete="one-time-code" autocapitalize="none" spellcheck="false" required<?= isset($errors['code']) ? ' aria-describedby="code-error"' : '' ?>>
    </div>
<?php else: ?>
    <div class="field field-short">
      <label for="code">6-digit code</label>
      <input id="code" name="code" type="text" inputmode="numeric" pattern="[0-9 ]*" maxlength="7" autocomplete="one-time-code" class="num" required autofocus<?= isset($errors['code']) ? ' aria-describedby="code-error"' : '' ?>>
    </div>
<?php endif; ?>
    <button class="btn btn-primary" type="submit"><?= icon('lock') ?><span><?= $enrolled ? 'Verify' : 'Verify and turn on' ?></span></button>
  </form>
<?php if ($enrolled && $hasKeys && !$recovery): ?>
  <div id="wa-login" data-csrf="<?= e(App\Auth\Csrf::token($app->session())) ?>" hidden>
    <p class="hint">Or use a security key:</p>
    <button id="wa-go" class="btn" type="button"><?= icon('shield') ?><span>Use security key</span></button>
    <p class="flash flash-error" id="wa-error" role="alert" hidden></p>
  </div>
  <script src="/assets/js/webauthn.js" defer></script>
<?php endif; ?>
<?php if ($enrolled): ?>
  <p class="hint"><?= $recovery ? '<a href="/login/mfa">Use the app code instead</a>' : '<a href="/login/mfa?recovery=1">Lost your phone? Use a recovery code</a>' ?></p>
<?php endif; ?>
  <p class="hint"><a href="/login">Start again</a></p>
</section>
