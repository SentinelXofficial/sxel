<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';

function db(): PDO
{
    static $pdo = null;
    if ($pdo === null) {
        $c = vulnapp_config();
        $dsn = sprintf(
            'mysql:host=%s;port=%s;dbname=%s;charset=utf8mb4',
            $c['db']['host'],
            $c['db']['port'],
            $c['db']['name']
        );
        $pdo = new PDO($dsn, $c['db']['user'], $c['db']['pass'], [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
    }
    return $pdo;
}

function db_error_page(PDOException $e, string $context): string
{
    return sprintf(
        '<div class="alert alert-danger"><strong>Database error:</strong> %s<br><small>while: %s</small></div>',
        htmlspecialchars($e->getMessage()),
        htmlspecialchars($context)
    );
}