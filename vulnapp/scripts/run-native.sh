#!/usr/bin/env bash
# Run VulnApp with the PHP built-in server (native setup).
set -euo pipefail

cd "$(dirname "$0")/.."

PORT="${1:-8899}"
export PHP_CLI_SERVER_WORKERS="${PHP_CLI_SERVER_WORKERS:-4}"

mkdir -p "${TMPDIR:-/tmp}/vulnapp-pages"
cp -rn src/pages/* "${TMPDIR:-/tmp}/vulnapp-pages/" 2>/dev/null || true

echo "VulnApp listening on http://127.0.0.1:${PORT} (php -S, ${PHP_CLI_SERVER_WORKERS} workers)"
exec php -S 127.0.0.1:"${PORT}" -t public public/router.php