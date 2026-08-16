<?php
// Router for `php -S` (built-in development server).
// Serve real files as-is, everything else goes through the app.
if (php_sapi_name() === 'cli-server') {
    $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
    $file = __DIR__ . $path;
    if ($path !== '/' && is_file($file)) {
        return false;
    }
}
require __DIR__ . '/../src/app.php';