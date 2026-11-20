<?php
/** @var App\App $app  @var ?App\Auth\User $user  @var string $title  @var string $content */
$nav = [
    'researcher' => [['/proposals', 'proposals', 'Proposals']],
    'reviewer'   => [['/reviews', 'reviews', 'Reviews']],
    'officer'    => [['/officer', 'decisions', 'Decisions'], ['/officer/calls', 'calls', 'Grant calls']],
    'auditor'    => [['/audit', 'audit', 'Audit']],
][$user->role ?? ''] ?? [];
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
// The most specific matching link is the current one.
$current = '';
foreach ($nav as [$href]) {
    if (str_starts_with($path, $href) && strlen($href) > strlen($current)) { $current = $href; }
}
$flash = $flash ?? null;
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= e($title) ?> · Research Grants</title>
<link rel="stylesheet" href="/assets/css/app.css">
<link rel="icon" href="data:,">
</head>
<body class="<?= $user ? 'with-rail' : 'plain' ?>">
<a class="skip-link" href="#main">Skip to content</a>
<?php if ($user): ?>
<header class="rail">
  <a class="brand" href="/"><span class="brand-mark" aria-hidden="true">RG</span><span class="brand-name">Research Grants</span></a>
  <nav aria-label="Main">
    <ul>
<?php foreach ($nav as [$href, $ic, $label]): ?>
      <li><a href="<?= e($href) ?>"<?= $href === $current ? ' aria-current="page"' : '' ?>><?= icon($ic) ?><span><?= e($label) ?></span></a></li>
<?php endforeach; ?>
    </ul>
  </nav>
  <div class="rail-user">
    <p class="who"><strong><?= e($user->fullName) ?></strong><span><?= e(ucfirst($user->role)) ?></span></p>
<?php if (App\Auth\Policy::can($user, 'account.security')): ?>
    <a class="btn btn-quiet" href="/account/security"><?= icon('shield') ?><span>Security</span></a>
<?php endif; ?>
    <form method="post" action="/logout">
      <?= csrf_field($app) ?>
      <button class="btn btn-quiet" type="submit"><?= icon('logout') ?><span>Sign out</span></button>
    </form>
  </div>
</header>
<?php endif; ?>
<main id="main" tabindex="-1">
<?php if ($flash): ?>
  <p class="flash flash-<?= e($flash['kind']) ?>" role="status"><?= icon($flash['kind'] === 'success' ? 'check' : 'alert') ?> <?= e($flash['message']) ?></p>
<?php endif; ?>
<?= $content ?>
</main>
<script src="/assets/js/app.js" defer></script>
</body>
</html>
