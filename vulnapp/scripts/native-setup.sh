#!/usr/bin/env bash
# Install PHP + MariaDB (Debian/Ubuntu) and initialize the VulnApp database.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

echo "[1/4] Installing packages (php-cli, php-mysql, php-curl, mariadb-server)..."
apt-get update
apt-get install -y php-cli php-mysql php-curl mariadb-server

echo "[2/4] Starting MariaDB..."
service mariadb start 2>/dev/null || mysqld_safe --skip-networking=0 &
for i in $(seq 1 30); do
  if mysqladmin ping 2>/dev/null; then break; fi
  sleep 1
done

echo "[3/4] Creating database and app user..."
mysql -u root <<'SQL'
CREATE DATABASE IF NOT EXISTS vulnapp CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'vulnapp'@'127.0.0.1' IDENTIFIED BY 'vulnapp';
CREATE USER IF NOT EXISTS 'vulnapp'@'localhost' IDENTIFIED BY 'vulnapp';
GRANT ALL PRIVILEGES ON vulnapp.* TO 'vulnapp'@'127.0.0.1';
GRANT ALL PRIVILEGES ON vulnapp.* TO 'vulnapp'@'localhost';
FLUSH PRIVILEGES;
SQL

echo "[4/4] Importing schema + seed data..."
mysql -u root < "$(dirname "$0")/../db/schema.sql"
mysql -u root < "$(dirname "$0")/../db/seed.sql"

echo "Done. Run: $(dirname "$0")/run-native.sh"