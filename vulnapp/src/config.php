<?php
declare(strict_types=1);

const APP_NAME = 'VulnApp';
const APP_TAGLINE = 'Deliberately vulnerable demo shop';

function env(string $key, string $default): string
{
    $v = getenv($key);
    return $v === false || $v === '' ? $default : $v;
}

function vulnapp_config(): array
{
    static $cfg = null;
    if ($cfg === null) {
        $cfg = [
            'db' => [
                'host' => env('VULNAPP_DB_HOST', '127.0.0.1'),
                'port' => env('VULNAPP_DB_PORT', '3306'),
                'user' => env('VULNAPP_DB_USER', 'vulnapp'),
                'pass' => env('VULNAPP_DB_PASS', 'vulnapp'),
                'name' => env('VULNAPP_DB_NAME', 'vulnapp'),
            ],
            'uploads_dir' => __DIR__ . '/../public/uploads',
            'pages_dir' => sys_get_temp_dir() . '/vulnapp-pages',
        ];
    }
    return $cfg;
}