<section class="card narrow login">
  <p class="eyebrow">University Research Office</p>
  <h1>Research Grants</h1>
  <p class="lede">Sign in with your university account.</p>
<?php if (isset($errors['login'])): ?>
  <p class="flash flash-error" role="alert" id="login-error"><?= icon('alert') ?> <?= e($errors['login']) ?></p>
<?php endif; ?>
  <form method="post" action="/login" novalidate>
    <?= csrf_field($app) ?>
    <div class="field">
      <label for="email">E-mail</label>
      <input id="email" name="email" type="email" autocomplete="username" required value="<?= e($email) ?>"<?= isset($errors['login']) ? ' aria-describedby="login-error"' : '' ?>>
    </div>
    <div class="field">
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required>
    </div>
    <button class="btn btn-primary" type="submit"><?= icon('lock') ?><span>Sign in</span></button>
  </form>
</section>
