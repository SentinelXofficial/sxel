# VulnApp — deliberately vulnerable demo web app

A realistic, insecure shop built with **PHP + MariaDB/MySQL** (vanilla JS + CSS, no framework),
designed as a **target for sxel** and for security training. Do **not** deploy it to the
public internet or any shared network.

## Quick start

### Docker (recommended)

```bash
docker compose up --build
# app:  http://127.0.0.1:8899
```

### Native (Debian/Ubuntu)

```bash
sudo ./scripts/native-setup.sh   # installs php-cli, php-mysql, mariadb-server + seeds DB
./scripts/run-native.sh          # starts php -S on http://127.0.0.1:8899
```

Run multiple workers (avoids self-fetch deadlock on `/fetch`):

```bash
PHP_CLI_SERVER_WORKERS=4 ./scripts/run-native.sh
```

## Scan it with sxel

```bash
go build -o sxel ./cmd/sxel
./sxel -url http://127.0.0.1:8899
```

## Credentials

| username | password | role  |
|----------|----------|-------|
| admin    | admin    | admin |
| alice    | alice123 | user  |
| bob      | bob123   | user  |

Passwords are stored as plain MD5 (deliberately weak).

## Deliberate vulnerabilities

| Endpoint | Vulnerability |
|---|---|
| `/search?q=` | SQLi (error-based, union) + reflected XSS (raw echo) |
| `/product?id=` | SQLi boolean-blind + time-blind (SLEEP) |
| `/profile?id=` | IDOR — view any user's profile/email |
| `/post?id=` + `/comment` | SQLi (error) + stored XSS + CSRF (no token) |
| `/read?file=` | LFI / path traversal (serves `/etc/passwd` with `../../../../etc/passwd`) |
| `/fetch?url=` | SSRF (server-side fetch) |
| `/ping?host=` | Command injection (blind, time-based) |
| `/go?url=` | Open redirect |
| `/api/token`, `/api/user` | JWT with weak secret `secret`, alg `none` accepted |
| `/upload` | Unrestricted file upload (`/uploads/`) |
| `/admin` | Weak auth: MD5 + session role only |
| `/admin.php`, `/config.php`, `/phpinfo.php`, `/backup.zip`, `/.git/HEAD` | Fake sensitive files (dir-scan fodder) |
| Login/register | MD5 passwords, no rate limiting, no CSRF tokens |

## Layout

```
vulnapp/
├── docker-compose.yml        # web (php:8.3-apache) + db (mariadb:11)
├── Dockerfile
├── db/schema.sql             # tables + seed data
├── db/seed.sql
├── public/                   # webroot: index.php, router.php, css/, js/, uploads/
├── src/                      # app.php (router+handlers), auth.php, db.php, layout.php
└── scripts/                  # native-setup.sh, run-native.sh
```

## How the integration tests use this

`go test ./tests/integration/` builds and runs this app (php -S + local MariaDB) and scans
it with sxel's modules: SQLi (error/union/boolean/time), XSS, command injection, JWT,
path traversal, open redirect. If PHP or MariaDB is missing, those tests skip automatically.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `VULNAPP_DB_HOST` | `127.0.0.1` | DB host (Docker sets `db`) |
| `VULNAPP_DB_PORT` | `3306` | DB port |
| `VULNAPP_DB_USER` | `vulnapp` | DB user |
| `VULNAPP_DB_PASS` | `vulnapp` | DB password |
| `VULNAPP_DB_NAME` | `vulnapp` | Database name |