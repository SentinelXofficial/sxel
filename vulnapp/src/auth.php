<?php
declare(strict_types=1);

function start_session(): void
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }
}

function require_login(): void
{
    start_session();
    if (empty($_SESSION['uid'])) {
        header('Location: /login?next=' . urlencode($_SERVER['REQUEST_URI'] ?? '/'));
        exit;
    }
}

function require_admin(): void
{
    require_login();
    $u = current_user();
    if ($u === null || $u['role'] !== 'admin') {
        http_response_code(403);
        render_page('Forbidden', '<div class="alert alert-danger">403 — admin access required.</div>');
        exit;
    }
}

function handle_login(): void
{
    start_session();
    $error = '';
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $username = trim((string) ($_POST['username'] ?? ''));
        $password = (string) ($_POST['password'] ?? '');
        $st = db()->prepare('SELECT id, username, role FROM users WHERE username = ? AND password = ?');
        $st->execute([$username, md5($password)]);
        $u = $st->fetch();
        if ($u === false) {
            $error = 'Invalid username or password.';
        } else {
            session_regenerate_id(true);
            $_SESSION['uid'] = (int) $u['id'];
            $_SESSION['role'] = $u['role'];
            header('Location: ' . (($_GET['next'] ?? '') ?: '/dashboard'));
            exit;
        }
    }
    $content = '<div class="card auth-card">
      <h1>Sign in</h1>
      <p class="muted">Demo credentials: <code>admin/admin</code> or <code>alice/alice123</code></p>';
    if ($error !== '') {
        $content .= '<div class="alert alert-danger">' . h($error) . '</div>';
    }
    $content .= '
      <form method="post" class="form">
        <label>Username<input type="text" name="username" required autofocus></label>
        <label>Password<input type="password" name="password" required></label>
        <button class="btn btn-primary" type="submit">Sign in</button>
      </form>
      <p class="muted"><a href="/register">Create an account</a></p>
    </div>';
    render_page('Sign in', $content);
}

function handle_register(): void
{
    start_session();
    $error = '';
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $username = trim((string) ($_POST['username'] ?? ''));
        $password = (string) ($_POST['password'] ?? '');
        $fullname = trim((string) ($_POST['fullname'] ?? ''));
        $email = trim((string) ($_POST['email'] ?? ''));
        try {
            $st = db()->prepare('INSERT INTO users (username, password, fullname, email) VALUES (?, ?, ?, ?)');
            $st->execute([$username, md5($password), $fullname, $email]);
            header('Location: /login?registered=1');
            exit;
        } catch (PDOException $e) {
            $error = 'Registration failed: username may already exist.';
        }
    }
    $content = '<div class="card auth-card">
      <h1>Create account</h1>';
    if ($error !== '') {
        $content .= '<div class="alert alert-danger">' . h($error) . '</div>';
    }
    $content .= '
      <form method="post" class="form">
        <label>Username<input type="text" name="username" required></label>
        <label>Full name<input type="text" name="fullname" required></label>
        <label>Email<input type="email" name="email" required></label>
        <label>Password<input type="password" name="password" required></label>
        <button class="btn btn-primary" type="submit">Register</button>
      </form>
      <p class="muted">Already have an account? <a href="/login">Sign in</a></p>
    </div>';
    render_page('Register', $content);
}

function handle_logout(): void
{
    start_session();
    session_destroy();
    header('Location: /');
    exit;
}