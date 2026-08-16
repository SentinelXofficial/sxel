<?php
declare(strict_types=1);

function current_user(): ?array
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }
    if (empty($_SESSION['uid'])) {
        return null;
    }
    $uid = (int) $_SESSION['uid'];
    $st = db()->prepare('SELECT id, username, fullname, email, role, bio FROM users WHERE id = ?');
    $st->execute([$uid]);
    $u = $st->fetch();
    return $u === false ? null : $u;
}

function render_page(string $title, string $content): void
{
    $user = current_user();
    $username = $user['username'] ?? 'guest';
    $nav = '';
    foreach ([
        '/' => 'Home',
        '/products' => 'Products',
        '/blog' => 'Blog',
        '/tools/ping' => 'Tools',
        '/upload' => 'Upload',
    ] as $path => $label) {
        $active = ($_SERVER['REQUEST_URI'] ?? '') === $path || str_starts_with($_SERVER['REQUEST_URI'] ?? '', $path . '?') || str_starts_with($_SERVER['REQUEST_URI'] ?? '', $path . '/');
        $nav .= sprintf('<a class="nav-link%s" href="%s">%s</a>', $active ? ' active' : '', $path, $label);
    }
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= htmlspecialchars($title) ?> · <?= APP_NAME ?></title>
<link rel="stylesheet" href="/css/style.css">
</head>
<body>
<header class="navbar">
  <div class="container navbar-inner">
    <a class="brand" href="/"><?= APP_NAME ?><span class="badge badge-warn">vuln</span></a>
    <nav class="nav"><?= $nav ?></nav>
    <div class="nav-auth">
      <?php if ($user !== null): ?>
        <span class="chip"><?= htmlspecialchars($username) ?><?= $user['role'] === 'admin' ? ' <span class="badge badge-admin">admin</span>' : '' ?></span>
        <a class="btn btn-ghost" href="/logout">Logout</a>
      <?php else: ?>
        <a class="btn btn-ghost" href="/login">Login</a>
        <a class="btn btn-primary" href="/register">Register</a>
      <?php endif; ?>
    </div>
  </div>
</header>
<main class="container main"><?= $content ?></main>
<footer class="footer">
  <div class="container">
    <p><?= APP_NAME ?> — <?= APP_TAGLINE ?>. Do not expose to the public internet.</p>
  </div>
</footer>
<script src="/js/app.js"></script>
</body>
</html>
<?php
}

function render_list(array $items, callable $row): string
{
    $out = '<ul class="list">';
    foreach ($items as $item) {
        $out .= '<li>' . $row($item) . '</li>';
    }
    return $out . '</ul>';
}

function h(?string $s): string
{
    return htmlspecialchars((string) $s);
}