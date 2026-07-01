# sxel — High-Performance Web Vulnerability Scanner

Open-source. No keys. No restrictions. 40+ modules + template engine written in Go.

## Installation

**Go install:**
```bash
go install github.com/SentinelXofficial/sxel/cmd/sxel@latest
```

**Binary download:**
```bash
curl -LO https://github.com/SentinelXofficial/sxel/releases/latest/download/sxel-linux-amd64
chmod +x sxel-linux-amd64
sudo mv sxel-linux-amd64 /usr/local/bin/sxel
```

**Build from source:**
```bash
git clone https://github.com/SentinelXofficial/sxel.git
cd sxel
go build -o sxel ./cmd/sxel/
```

**Update:**
```bash
sxel --update
```

## Quick Start

```bash
sxel -u https://target.com --all --crawl
sxel -u https://target.com --strobe
sxel -u https://target.com/api/user/1 --snipe
sxel -u https://target.com --templates
```

## Features

### Scan Modules (40+)
| Category       | Modules                                                                                   |
|----------------|-------------------------------------------------------------------------------------------|
| Injection      | SQLi (Error/Blind/Boolean), NoSQLi, Command Injection, SSTI, CRLF, Prototype Pollution    |
| Web            | XSS (Reflected/DOM/Stored), Open Redirect, CSRF, Path Traversal, LFI, RFI, Host Header    |
| Infrastructure | SSRF, XXE, JWT, GraphQL, WebSocket, gRPC, HTTP Smuggling, Cache Poisoning                 |
| Discovery      | Subdomain Enumeration, Directory Brute, JS Endpoint Extraction, Subdomain Takeover        |
| Access         | IDOR, CSRF, Cookie Audit, Rate Limit Detection                                            |
| Files          | Sensitive File Exposure, File Upload, Deserialization, Backup/Config Leaks                |
| Defense        | WAF Detection + Auto-Bypass, Security Headers, CORS, HTTP Methods                         |

### Engines
| Engine         | Description                                                               |
|----------------|---------------------------------------------------------------------------|
| Template       | YAML-based template runner — 110+ templates, Nuclei-compatible schema     |
| Strobe         | Adaptive deep-dive: fingerprint → smart scan → chains → templates         |
| Snipe          | All modules attack single endpoint simultaneously (3-phase deep-dive)     |
| Chain          | Multi-step attacks: extract variables → inject → verify                   |
| OOB Callback   | Blind vulnerability detection (SSRF, XXE, CMDI) via callback server       |
| Fingerprint    | Tech stack detection + endpoint dedup + smart module selection            |
| Clutch         | Race condition / TOCTOU detection via burst requests                      |
| Breach         | OAuth 2.0 + SAML misconfiguration probe                                   |

### Output
| Format         | Flag                  |
|----------------|-----------------------|
| HTML           | `--html-output`       |
| JSON           | `--json-output`       |
| CSV            | `--csv-output`        |
| Markdown       | `--md-output`         |
| Terminal       | Xray-style structured |

## Usage

```bash
# Full scan with everything
sxel -u https://target.com --all --crawl

# Adaptive smart scan
sxel -u https://target.com --strobe

# Deep-dive single endpoint
sxel -u https://target.com/api/user/1 --snipe

# Template-based scanning
sxel -u https://target.com --templates --template-dir ./templates/

# Race condition detection
sxel -u https://target.com --clutch

# Multi-target from file
sxel -l targets.txt --all --json-output results.json --list-concurrency 5

# Crawl with custom depth + WAF bypass
sxel -u https://target.com --crawl --depth 3 --waf-bypass

# Auth + custom headers
sxel -u https://target.com -H "Authorization: Bearer xxx" --cookie "session=abc"

# Specific modules
sxel -u https://target.com --sql-only --blind --proxy http://127.0.0.1:8080

# Resume interrupted scan
sxel -u https://target.com --resume --checkpoint state.json

# Sprint B engines
sxel -u https://target.com --strobe --snipe --clutch --breach --grpc

# Help
sxel --help
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

## Sprint B Engines (v1.0.3)

| Flag | Engine | Description |
|------|--------|-------------|
| `--templates` | Template Runner | YAML template scanning (110+ templates) |
| `--strobe` | Strobe | Adaptive fingerprint → scan → chains → templates |
| `--snipe` | Snipe | All modules deep-dive single endpoint |
| `--clutch` | Clutch | Race condition / TOCTOU detection |
| `--breach` | Breach | OAuth + SAML misconfiguration |
| `--grpc` | gRPC | gRPC reflection + REST gateway |

## Output

```
[INFO] 2026-07-01 22:00:00 sxel v1.0.3 started
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
