<section class="card narrow login">
  <p class="eyebrow">University Research Office</p>
  <h1><?= icon('shield') ?> Save your recovery codes</h1>
  <p class="lede">Two-step sign-in is on. If you lose your phone, each code below signs you in <strong>once</strong>. They are shown only now and are stored only as one-way hashes.</p>
  <ul class="facts" id="recovery-codes">
<?php foreach ($codes as $c): ?>
    <li><code><?= e($c) ?></code></li>
<?php endforeach; ?>
  </ul>
  <p class="hint">Keep them somewhere safe and separate from your phone. A grants administrator can reset your second factor if you lose both.</p>
  <p><a class="btn btn-primary" href="<?= e(\App\Auth\Policy::HOME[$user->role]) ?>"><?= icon('arrow') ?><span>I have saved them, continue</span></a></p>
</section>
