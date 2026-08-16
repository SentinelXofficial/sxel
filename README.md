# sxel

High-Performance Web Vulnerability Scanner — 40+ attack modules, YAML template engine,
and a deliberately vulnerable local lab for testing detection quality.

Open-source. No keys. No restrictions. Written in Go.

[![Go](https://img.shields.io/badge/go-1.26-00ADD8?logo=go&logoColor=white)](go.mod)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Release](https://img.shields.io/badge/release-v1.2.0-green)](https://github.com/SentinelXofficial/sxel/releases)

## Features

- **40+ scan modules** — injection, XSS, SSRF/XXE, JWT, GraphQL, smuggling, IDOR, upload, and more
- **Template engine** — Nuclei-compatible YAML schema, 110+ built-in templates
- **Adaptive engines** — Strobe (deep-dive pipeline), Snipe (single-endpoint), Clutch (race conditions), Breach (OAuth/SAML)
- **Blind detection** — time-based and boolean-based SQLi, OOB callbacks for SSRF/XXE/CMDi
- **WAF detection + auto-bypass**
- **Built-in lab (VulnApp)** — PHP + MariaDB deliberately vulnerable app for local practice and integration tests
- **Rich output** — HTML, JSON, CSV, Markdown, SARIF, terminal

## Installation

### Binary (fastest)

```bash
curl -LO https://github.com/SentinelXofficial/sxel/releases/latest/download/sxel-linux-amd64
chmod +x sxel-linux-amd64
sudo mv sxel-linux-amd64 /usr/local/bin/sxel
```

### Go install

```bash
go install github.com/SentinelXofficial/sxel/cmd/sxel@latest
```

### From source

```bash
git clone https://github.com/SentinelXofficial/sxel.git
cd sxel
go build -o sxel ./cmd/sxel/
```

### Update

```bash
sxel --update
```

## Quick Start

```bash
# Full scan: crawl + every module
sxel -u https://target.com --all --crawl

# Adaptive deep-dive
sxel -u https://target.com --strobe

# Deep-dive a single endpoint
sxel -u https://target.com/api/user/1 --snipe

# Template-based scan
sxel -u https://target.com --templates
```

## Usage

### Scan targeting

```bash
# Single URL
sxel -u "http://target.com/page?id=1"

# Multi-target from file
sxel -l targets.txt --all --json-output results.json --list-concurrency 5

# Crawl with scope control
sxel -u https://target.com --crawl --out-of-scope cdn.target.com
```

### Authentication & headers

```bash
# Login form + session handling
sxel -u https://target.com --auth-login https://target.com/login \
     --auth-user alice --auth-pass secret

# Custom headers / cookies
sxel -u https://target.com -H "Authorization: Bearer xxx" --cookie "session=abc"
```

### Module selection

```bash
# Everything
sxel -u https://target.com --all

# Pick modules by name
sxel -u https://target.com --modules sqli,xss,cmdi,ssrf,jwt

# Common one-offs
sxel -u https://target.com --graphql --idor --file-upload
sxel -u https://target.com --clutch          # race conditions
sxel -u https://target.com --dirscan         # directory brute force
sxel -u https://target.com --jwt --cookie "token=ey..."
```

### Proxying & resuming

```bash
# Through Burp / proxy
sxel -u https://target.com --proxy http://127.0.0.1:8080

# Interrupted scan? Resume from checkpoint
sxel -u https://target.com --resume --checkpoint state.json
```

### Reports

```bash
sxel -u https://target.com --all --html-output report.html --json-output report.json
sxel -u https://target.com --sarif-output sarif.json   # GitHub code scanning compatible
```

## Scan Modules (40+)

| Category       | Modules                                                                                   |
|----------------|-------------------------------------------------------------------------------------------|
| Injection      | SQLi (Error/Blind/Boolean), NoSQLi, Command Injection, SSTI, CRLF, Prototype Pollution    |
| Web            | XSS (Reflected/DOM/Stored), Open Redirect, CSRF, Path Traversal, LFI, RFI, Host Header    |
| Infrastructure | SSRF, XXE, JWT, GraphQL, WebSocket, gRPC, HTTP Smuggling, Cache Poisoning                 |
| Discovery      | Subdomain Enumeration, Directory Brute, JS Endpoint Extraction, Subdomain Takeover        |
| Access         | IDOR, CSRF, Cookie Audit, Rate Limit Detection                                            |
| Files          | Sensitive File Exposure, File Upload, Deserialization, Backup/Config Leaks                |
| Defense        | WAF Detection + Auto-Bypass, Security Headers, CORS, HTTP Methods                         |

## Engines

| Engine       | Description                                                              |
|--------------|--------------------------------------------------------------------------|
| Template     | YAML-based template runner — 110+ templates, Nuclei-compatible schema    |
| Strobe       | Adaptive deep-dive: fingerprint → smart scan → chains → templates        |
| Snipe        | All modules attack single endpoint simultaneously (3-phase deep-dive)    |
| Chain        | Multi-step attacks: extract variables → inject → verify                  |
| OOB Callback | Blind vulnerability detection (SSRF, XXE, CMDi) via callback server      |
| Fingerprint  | Tech stack detection + endpoint dedup + smart module selection           |
| Clutch       | Race condition / TOCTOU detection via burst requests                     |
| Breach       | OAuth 2.0 + SAML misconfiguration probe                                  |

## Local Testing Lab (VulnApp)

`sxel` ships with **VulnApp** — a deliberately vulnerable PHP + MariaDB shop (DVWA-style),
used by the integration tests to validate detection quality. Run it locally and scan it:

```bash
# Docker
cd vulnapp && docker compose up --build        # http://127.0.0.1:8899

# or native (Debian/Ubuntu)
sudo ./vulnapp/scripts/native-setup.sh
./vulnapp/scripts/run-native.sh                 # http://127.0.0.1:8899
```

```bash
./sxel -u http://127.0.0.1:8899 --crawl
```

Expected findings: SQLi (error/union/boolean/time), reflected + stored XSS, command
injection, JWT (alg none), path traversal, open redirect, IDOR, CSRF, upload — see
[`vulnapp/README.md`](vulnapp/README.md) for the full endpoint map and demo credentials.

The integration suite boots VulnApp (php -S + local MariaDB) and scans it with the real
modules. Tests auto-skip if PHP or MariaDB is not installed:

```bash
go test ./tests/integration/
```

## Templates

Nuclei-compatible YAML schema with 110+ built-in templates:

```yaml
id: cve-2024-example
brief:
  title: Example CVE
  level: critical
  label: [cve, rce]
moves:
  - verb: GET
    to:
      - "{{BaseURL}}/vulnerable-endpoint"
    signs:
      - on: word
        has:
          - "vulnerable"
```

- `{{BaseURL}}` — auto-expanded to target
- `on: word` — keyword match in body/header/all
- `on: status` — HTTP status code match
- `need: any|all` — OR/AND matching
- `flip: true` — negative matching (header NOT present)
- `head:` — custom request headers

## Example Output

```
[INFO] 2026-07-01 22:00:00 sxel v1.2.0 started
[INFO] 2026-07-01 22:00:00 Loaded 38 scan module(s)
[INFO] 2026-07-01 22:00:00 Target: https://target.com

[HIGH] SQL Injection (Error-Based)
  Target      "https://target.com/api/search?id=1'"
  Method      GET
  ParamKey    "id"
  Payload     "' OR 1=1--"
  Evidence    "error pattern 'SQL syntax'"

[+] 2026-07-01 22:01:30 Scan complete in 1m30s — 42 URLs, 5 forms, 3 findings
[+] 2026-07-01 22:01:30 HTML report -> report.html
```

## Contributing

1. Fork the repo
2. Create a feature branch
3. Add your module or template
4. Submit a PR

Templates go in `templates/<category>/your-template.yaml`.

## License

MIT — see [LICENSE](LICENSE).

---

**sxel** is maintained by [SentinelX Official](https://github.com/SentinelXofficial).