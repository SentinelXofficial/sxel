<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/layout.php';
require_once __DIR__ . '/auth.php';

$config = vulnapp_config();

/* ---------- helpers ---------- */

function b64url(string $b): string
{
    return rtrim(strtr(base64_encode($b), '+/', '-_'), '=');
}

function union_marker(string $q): string
{
    if (!preg_match('/UNION\s+SELECT\s+/i', $q, $m)) {
        return '';
    }
    $mid = substr($q, strpos($q, $m[0]) + strlen($m[0]));
    $end = strlen($mid);
    foreach (['-', '#', ';'] as $c) {
        $p = strpos($mid, $c);
        if ($p !== false && $p < $end) {
            $end = $p;
        }
    }
    $cols = explode(',', substr($mid, 0, $end));
    if (count($cols) !== 2) {
        return '';
    }
    $td = '';
    foreach ($cols as $c) {
        $td .= '<td>' . $c . '</td>';
    }
    return $td;
}

function sleep_seconds(string $q): int
{
    $low = strtolower($q);
    foreach ([3, 4, 5, 8] as $n) {
        if (strpos($low, "sleep($n)") !== false || strpos($low, "pg_sleep($n)") !== false
            || strpos($low, "0:0:$n") !== false) {
            return $n;
        }
    }
    if (strpos($low, 'randombblob') !== false) {
        return 4;
    }
    return 0;
}

/* ---------- pages ---------- */

function page_home(): void
{
    $rows = db()->query('SELECT id, name, price, category, stock FROM products ORDER BY id LIMIT 6')->fetchAll();
    $cards = '';
    foreach ($rows as $p) {
        $cards .= sprintf(
            '<a class="product-card" href="/product?id=%d">
               <h3>%s</h3>
               <p class="price">Rp %s</p>
               <p class="muted">%s · stock %d</p>
             </a>',
            (int) $p['id'], h($p['name']), number_format((float) $p['price']),
            h($p['category']), (int) $p['stock']
        );
    }
    render_page('Home', '
      <section class="hero">
        <h1>Welcome to ' . APP_NAME . '</h1>
        <p>Everything a modern shop needs: a catalog, a blog, an admin panel, and a few <em>surprises</em>.</p>
        <div class="hero-actions">
          <a class="btn btn-primary" href="/products">Browse products</a>
          <a class="btn btn-ghost" href="/blog">Read the blog</a>
        </div>
      </section>
      <section>
        <h2>Featured products</h2>
        <div class="grid">' . $cards . '</div>
      </section>');
}

function page_dashboard(): void
{
    require_login();
    $user = current_user();
    $users = (int) db()->query('SELECT COUNT(*) FROM users')->fetchColumn();
    $products = (int) db()->query('SELECT COUNT(*) FROM products')->fetchColumn();
    $comments = (int) db()->query('SELECT COUNT(*) FROM comments')->fetchColumn();
    $latest = db()->query('SELECT c.id, c.body, c.created_at, u.username, p.title
        FROM comments c JOIN users u ON u.id = c.user_id JOIN posts p ON p.id = c.post_id
        ORDER BY c.id DESC LIMIT 5')->fetchAll();
    $list = '';
    foreach ($latest as $c) {
        $list .= '<li><strong>' . h($c['username']) . '</strong> on "' . h($c['title']) . '": ' . h($c['body']) . ' <span class="muted">(' . h($c['created_at']) . ')</span></li>';
    }
    render_page('Dashboard', '
      <h1>Dashboard</h1>
      <p>Welcome back, <strong>' . h($user['fullname']) . '</strong> (' . h($user['email']) . ')</p>
      <div class="grid grid-3">
        <div class="stat-card"><span class="stat">' . $users . '</span> users</div>
        <div class="stat-card"><span class="stat">' . $products . '</span> products</div>
        <div class="stat-card"><span class="stat">' . $comments . '</span> comments</div>
      </div>
      <h2>Latest comments</h2>
      <ul class="list">' . $list . '</ul>');
}

function page_search(): void
{
    $q = (string) ($_GET['q'] ?? '');
    if ($q === '') {
        render_page('Search', '
          <div class="card"><h1>Search products</h1>
          <form class="form" method="get" action="/search">
            <label>Query<input type="text" name="q" placeholder="e.g. keyboard"></label>
            <button class="btn btn-primary" type="submit">Search</button>
          </form></div>');
        return;
    }

    if (preg_match('/UNION\s+SELECT/i', $q)) {
        $marker = union_marker($q);
        if ($marker !== '') {
            render_page('Search results', '
              <div class="alert alert-info">Union-based search results</div>
              <table class="table"><thead><tr><th>id</th><th>name</th></tr></thead>
              <tbody><tr>' . $marker . '</tr></tbody></table>');
            return;
        }
    }

    if (strpos($q, "'") !== false) {
        try {
            db()->query("SELECT name, description FROM products WHERE name LIKE '%" . $q . "%'");
        } catch (PDOException $e) {
            render_page('Search results', '
              <div class="alert alert-danger"><strong>Database error:</strong> ' . h($e->getMessage()) . '
              <br><small>query: SELECT name, description FROM products WHERE name LIKE \'%' . h($q) . '%\'</small></div>');
            return;
        }
    }

    $rows = db()->query("SELECT name, price, category FROM products WHERE name LIKE '%" . $q . "%'")->fetchAll();
    $list = '';
    foreach ($rows as $p) {
        $list .= '<li><strong>' . h($p['name']) . '</strong> — Rp ' . number_format((float) $p['price']) . ' <span class="muted">[' . h($p['category']) . ']</span></li>';
    }
    if ($list === '') {
        $list = '<li class="muted">No products match your query.</li>';
    }
    render_page('Search results', '
      <div class="alert alert-info">Results for <b>' . $q . '</b>:</div>
      <ul class="list">' . $list . '</ul>');
}

function page_products(): void
{
    $rows = db()->query('SELECT id, name, price, category, stock FROM products ORDER BY id')->fetchAll();
    $rowsHtml = '';
    foreach ($rows as $p) {
        $rowsHtml .= sprintf(
            '<tr><td><a href="/product?id=%d">%s</a></td><td>%s</td><td>Rp %s</td><td>%d</td></tr>',
            (int) $p['id'], h($p['name']), h($p['category']), number_format((float) $p['price']), (int) $p['stock']
        );
    }
    render_page('Products', '
      <h1>All products</h1>
      <table class="table"><thead><tr><th>Name</th><th>Category</th><th>Price</th><th>Stock</th></tr></thead>
      <tbody>' . $rowsHtml . '</tbody></table>');
}

function page_product(): void
{
    $q = (string) ($_GET['id'] ?? '1');

    $sleep = sleep_seconds($q);
    if ($sleep > 0) {
        usleep($sleep * 1_000_000);
    }

    $low = strtolower($q);
    $all = strpos($low, '1=1') !== false || strpos($low, "'a") !== false;
    $none = strpos($low, '1=2') !== false || strpos($low, "'b") !== false;

    try {
        if ($all) {
            $rows = db()->query('SELECT id, name, price FROM products')->fetchAll();
            $list = '';
            foreach ($rows as $p) {
                $list .= '<li><strong>' . h($p['name']) . '</strong> — Rp ' . number_format((float) $p['price']) . '</li>';
            }
            render_page('Product', '<h1>All products</h1><ul class="list">' . $list . '</ul>');
            return;
        }
        if ($none) {
            render_page('Product', '<div class="card"><h1>No product found</h1><p class="muted">The requested product does not exist in our catalog.</p><p class="muted">Please check the product id and try again later.</p></div>');
            return;
        }
        $st = db()->prepare('SELECT id, name, price, category, stock FROM products WHERE id = ?');
        $st->execute([(int) $q]);
        $p = $st->fetch();
        if ($p === false) {
            render_page('Product', '<div class="card"><h1>No product found</h1><p class="muted">The requested product does not exist in our catalog.</p><p class="muted">Please check the product id and try again later.</p></div>');
            return;
        }
        render_page('Product', sprintf(
            '<div class="card product-detail">
              <h1>%s</h1>
              <p class="price">Rp %s</p>
              <p class="muted">%s · stock %d</p>
            </div>',
            h($p['name']), number_format((float) $p['price']), h($p['category']), (int) $p['stock']
        ));
    } catch (PDOException $e) {
        render_page('Product', '<div class="card"><p class="muted">No product found.</p></div>');
    }
}

function page_blog(): void
{
    $rows = db()->query('SELECT p.id, p.title, p.created_at, u.username, (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) AS n
        FROM posts p JOIN users u ON u.id = p.user_id ORDER BY p.id DESC')->fetchAll();
    $list = '';
    foreach ($rows as $p) {
        $list .= '<li><a href="/post?id=' . (int) $p['id'] . '"><strong>' . h($p['title']) . '</strong></a>
          <span class="muted">by ' . h($p['username']) . ' · ' . h($p['created_at']) . ' · ' . (int) $p['n'] . ' comments</span></li>';
    }
    render_page('Blog', '<h1>Blog</h1><ul class="list">' . $list . '</ul>');
}

function page_post(): void
{
    $id = (string) ($_GET['id'] ?? '1');
    try {
        $st = db()->query('SELECT p.id, p.title, p.body, p.created_at, u.username
            FROM posts p JOIN users u ON u.id = p.user_id WHERE p.id = ' . $id);
        $post = $st->fetch();
    } catch (PDOException $e) {
        render_page('Post', '
          <div class="alert alert-danger"><strong>Database error:</strong> ' . h($e->getMessage()) . '</div>');
        return;
    }
    if ($post === false) {
        render_page('Post', '<div class="card"><p class="muted">Post not found.</p></div>');
        return;
    }
    $comments = db()->query('SELECT c.body, c.created_at, u.username FROM comments c
        JOIN users u ON u.id = c.user_id WHERE c.post_id = ' . (int) $id . ' ORDER BY c.id')->fetchAll();
    $html = '';
    foreach ($comments as $c) {
        $html .= '<div class="comment"><strong>' . h($c['username']) . '</strong>
          <span class="muted">' . h($c['created_at']) . '</span>
          <p>' . $c['body'] . '</p></div>';
    }
    render_page($post['title'], '
      <article class="card">
        <h1>' . $post['title'] . '</h1>
        <p class="muted">by ' . h($post['username']) . ' · ' . h($post['created_at']) . '</p>
        <p>' . $post['body'] . '</p>
      </article>
      <section class="card">
        <h2>' . count($comments) . ' comments</h2>
        <div id="comments">' . $html . '</div>
        <form id="comment-form" class="form" method="post" action="/comment">
          <input type="hidden" name="post_id" value="' . (int) $id . '">
          <label>Your comment<textarea name="body" rows="3" required></textarea></label>
          <button class="btn btn-primary" type="submit">Post comment</button>
        </form>
      </section>');
}

function page_comment(): void
{
    $postId = (int) ($_POST['post_id'] ?? 0);
    $body = (string) ($_POST['body'] ?? '');
    $uid = $_SESSION['uid'] ?? 1;
    if ($body === '' || $postId < 1) {
        header('Location: /post?id=' . $postId);
        exit;
    }
    $st = db()->prepare('INSERT INTO comments (post_id, user_id, body) VALUES (?, ?, ?)');
    $st->execute([$postId, (int) $uid, $body]);
    header('Location: /post?id=' . $postId);
    exit;
}

function page_profile(): void
{
    start_session();
    $id = (int) ($_GET['id'] ?? ($_SESSION['uid'] ?? 0));
    if ($id < 1) {
        render_page('Profile', '<div class="card"><p class="muted">Please log in or pick a user.</p></div>');
        return;
    }
    $st = db()->prepare('SELECT id, username, fullname, email, role, bio FROM users WHERE id = ?');
    $st->execute([$id]);
    $u = $st->fetch();
    if ($u === false) {
        render_page('Profile', '<div class="card"><p class="muted">User not found.</p></div>');
        return;
    }
    render_page('Profile: ' . $u['username'], '
      <div class="card">
        <h1>' . h($u['fullname']) . '</h1>
        <p class="muted">@' . h($u['username']) . ' · ' . h($u['role']) . '</p>
        <p>Email: ' . h($u['email']) . '</p>
        <p>' . h($u['bio']) . '</p>
      </div>');
}

function page_admin(): void
{
    require_admin();
    $users = db()->query('SELECT id, username, fullname, email, role FROM users ORDER BY id')->fetchAll();
    $rows = '';
    foreach ($users as $u) {
        $rows .= '<tr><td>' . (int) $u['id'] . '</td><td>' . h($u['username']) . '</td>
          <td>' . h($u['fullname']) . '</td><td>' . h($u['email']) . '</td>
          <td><span class="badge ' . ($u['role'] === 'admin' ? 'badge-admin' : '') . '">' . h($u['role']) . '</span></td></tr>';
    }
    $uploads = '';
    foreach (glob(vulnapp_config()['uploads_dir'] . '/*') ?: [] as $f) {
        $uploads .= '<li>' . h(basename($f)) . ' <span class="muted">(' . h((string) filesize($f)) . ' B)</span></li>';
    }
    render_page('Admin panel', '
      <h1>Admin panel</h1>
      <h2>Users</h2>
      <table class="table"><thead><tr><th>id</th><th>username</th><th>name</th><th>email</th><th>role</th></tr></thead>
      <tbody>' . $rows . '</tbody></table>
      <h2>Uploads</h2><ul class="list">' . $uploads . '</ul>');
}

function page_upload(): void
{
    start_session();
    $message = '';
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
        $name = basename((string) ($_FILES['file']['name'] ?? ''));
        $target = vulnapp_config()['uploads_dir'] . '/' . $name;
        if (move_uploaded_file((string) ($_FILES['file']['tmp_name'] ?? ''), $target)) {
            $message = 'Uploaded: <a href="/uploads/' . h($name) . '">' . h($name) . '</a>';
        } else {
            $message = 'Upload failed.';
        }
    }
    render_page('Upload', '
      <div class="card">
        <h1>Upload a file</h1>
        <p class="muted">Any file type is welcome here — we do not check.</p>
        ' . ($message !== '' ? '<div class="alert alert-success">' . $message . '</div>' : '') . '
        <form class="form" method="post" enctype="multipart/form-data">
          <label>File<input type="file" name="file" required></label>
          <button class="btn btn-primary" type="submit">Upload</button>
        </form>
      </div>');
}

function page_read(): void
{
    $file = (string) ($_GET['file'] ?? 'welcome.txt');
    if (strpos($file, "\0") !== false) {
        $file = '';
    }
    $path = vulnapp_config()['pages_dir'] . '/' . $file;
    $content = @file_get_contents($path);
    if ($content === false) {
        $content = 'Page not found: ' . $file;
    }
    render_page('Read', '<div class="card"><h1>File: ' . h($file) . '</h1><pre class="code">' . $content . '</pre></div>');
}

function page_fetch(): void
{
    $url = (string) ($_GET['url'] ?? '');
    header('Content-Type: application/json');
    if ($url === '' || !preg_match('#^https?://#i', $url)) {
        echo json_encode(['fetched' => false, 'error' => 'invalid url']);
        return;
    }
    $ctx = stream_context_create(['http' => ['timeout' => 5, 'follow_location' => 1, 'ignore_errors' => true]]);
    $body = @file_get_contents($url, false, $ctx);
    if ($body === false) {
        echo json_encode(['fetched' => false, 'error' => 'could not fetch ' . $url]);
        return;
    }
    echo json_encode(['fetched' => true, 'len' => strlen($body)]);
}

function page_ping(): void
{
    $host = $_GET['host'] ?? null;
    if ($host === null || stripos($host, 'sleep') !== false || stripos($host, 'ping') !== false) {
        usleep(3_200_000);
    }
    $output = "PING " . $host . " (127.0.0.1): 56 data bytes\n"
        . "64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.4 ms\n"
        . "64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.3 ms\n"
        . "--- " . $host . " ping statistics ---\n2 packets transmitted, 2 received, 0% packet loss";
    render_page('Ping', '
      <div class="card">
        <h1>Network diagnostics</h1>
        <form class="form" method="get" action="/ping">
          <label>Host<input type="text" name="host" value="' . h((string) $host) . '" placeholder="127.0.0.1"></label>
          <button class="btn btn-primary" type="submit">Ping</button>
        </form>
        <pre class="code">' . $output . '</pre>
      </div>');
}

function page_tools(): void
{
    render_page('Tools', '
      <div class="card">
        <h1>Developer tools</h1>
        <ul class="list">
          <li><a href="/ping">Network ping utility</a></li>
          <li><a href="/read?file=welcome.txt">Read a page (debug)</a></li>
          <li><a href="/fetch?url=https://example.com">URL fetcher (debug)</a></li>
          <li><a href="/go?url=https://example.com">Redirect helper</a></li>
        </ul>
      </div>');
}

function page_go(): void
{
    $url = (string) ($_GET['url'] ?? '/');
    header('Location: ' . $url);
    exit;
}

function api_token(): void
{
    $header = b64url('{"alg":"HS256","typ":"JWT"}');
    $payload = b64url(json_encode(['user' => 'admin', 'iat' => time()]));
    $sig = b64url(hash_hmac('sha256', $header . '.' . $payload, 'secret', true));
    header('Content-Type: text/plain');
    echo $header . '.' . $payload . '.' . $sig;
}

function api_user(): void
{
    $headers = function_exists('getallheaders') ? getallheaders() : [];
    $auth = $headers['Authorization'] ?? ($_SERVER['HTTP_AUTHORIZATION'] ?? '');
    header('Content-Type: application/json');
    $token = str_starts_with($auth, 'Bearer ') ? substr($auth, 7) : '';
    if ($token === '') {
        http_response_code(401);
        echo json_encode(['ok' => false]);
        return;
    }
    $parts = explode('.', $token);
    if (count($parts) !== 3) {
        http_response_code(401);
        echo json_encode(['ok' => false]);
        return;
    }
    [$h, $p, $s] = $parts;
    $headerJson = base64_decode(strtr($h, '-_', '+/'));
    if ($headerJson === false) {
        http_response_code(401);
        echo json_encode(['ok' => false]);
        return;
    }
    $header = json_decode((string) $headerJson, true);
    $alg = strtolower((string) ($header['alg'] ?? ''));
    switch ($alg) {
        case 'none':
            break;
        case 'hs256':
            $sig = base64_decode(strtr($s, '-_', '+/'));
            $expect = hash_hmac('sha256', $h . '.' . $p, 'secret', true);
            if ($sig === false || !hash_equals($expect, (string) $sig)) {
                http_response_code(401);
                echo json_encode(['ok' => false]);
                return;
            }
            break;
        default:
            http_response_code(401);
            echo json_encode(['ok' => false]);
            return;
    }
    $payload = json_decode((string) base64_decode(strtr($p, '-_', '+/')), true);
    echo json_encode(['ok' => true, 'user' => $payload['user'] ?? 'unknown']);
}

/* ---------- router ---------- */

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
$path = rtrim($path, '/');
if ($path === '') {
    $path = '/';
}

switch ($path) {
    case '/':              page_home(); break;
    case '/dashboard':     page_dashboard(); break;
    case '/login':         handle_login(); break;
    case '/register':      handle_register(); break;
    case '/logout':        handle_logout(); break;
    case '/search':        page_search(); break;
    case '/products':      page_products(); break;
    case '/product':       page_product(); break;
    case '/blog':          page_blog(); break;
    case '/post':          page_post(); break;
    case '/comment':       page_comment(); break;
    case '/profile':       page_profile(); break;
    case '/admin':         page_admin(); break;
    case '/upload':        page_upload(); break;
    case '/read':          page_read(); break;
    case '/fetch':         page_fetch(); break;
    case '/ping':          page_ping(); break;
    case '/tools':         page_tools(); break;
    case '/go':            page_go(); break;
    case '/api/token':     api_token(); break;
    case '/api/user':      api_user(); break;
    case '/admin.php':     render_page('Admin', '<div class="card"><h1>admin panel</h1><p class="muted">legacy login</p><form class="form"><label>Password<input type="password"></label><button class="btn btn-primary" type="submit">Login</button></form></div>'); break;
    case '/config.php':    render_page('config.php', '<div class="card"><pre class="code">' . h("<?php\n\$db_host = '127.0.0.1';\n\$db_user = 'vulnapp';\n\$db_pass = 'vulnapp';") . '</pre></div>'); break;
    case '/phpinfo.php':   render_page('phpinfo', '<div class="card"><h1>PHP Version 8.4.24</h1><table class="table"><tr><td>PHP Extension Build</td><td>API20240902,NTS</td></tr><tr><td>Loaded Configuration File</td><td>/etc/php/8.4/cli/php.ini</td></tr><tr><td>display_errors</td><td>On</td></tr></table></div>'); break;
    case '/backup.zip':    header('Content-Type: application/zip'); echo "PK\x03\x04 fake backup archive (not really a zip)"; break;
    case '/.git/HEAD':     header('Content-Type: text/plain'); echo 'ref: refs/heads/main'; break;
    default:
        http_response_code(404);
        render_page('Not found', '<div class="card"><h1>404</h1><p class="muted">' . h($path) . ' does not exist.</p></div>');
}