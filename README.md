# sxel — High-Performance Web Vulnerability Scanner

Open-source. No keys. No restrictions. 30+ modules written in Go.

## Installation

**Go install:**

```bash
go install github.com/SentinelXofficial/sxel/cmd/sxel@latest
```

**Binary download:**

```bash
curl -LO https://github.com/SentinelXofficial/sxel/releases/latest/download/sxel-linux-amd64
chmod +x sxel-linux-amd64
mv sxel-linux-amd64 /usr/local/bin/sxel
```

**Build from source:**

```bash
git clone https://github.com/SentinelXofficial/sxel.git
cd sxel
go build -o sxel ./cmd/sxel/
```

## Quick Start

```bash
sxel -u https://target.com --all --crawl
```

## Features

| Category       | Modules                                                                                   |
|----------------|-------------------------------------------------------------------------------------------|
| Injection      | SQLi (Error/Blind/Boolean), NoSQLi, Command Injection, SSTI, CRLF                         |
| Web            | XSS (Reflected/DOM/Stored), Open Redirect, CSRF, Path Traversal, LFI, RFI                 |
| Infrastructure | SSRF, XXE, JWT, GraphQL, WebSocket, gRPC, HTTP Smuggling, Cache Poisoning                 |
| Discovery      | Subdomain Enumeration, Directory Brute, JS Endpoint Extraction, Subdomain Takeover        |
| Access         | IDOR, BAC, Privilege Escalation                                                           |
| Defense        | WAF Detection + Auto-Bypass, Security Headers Audit, Rate Limit Testing                   |
| Advanced       | Prototype Pollution, Deserialization, File Upload, OOB Interaction                        |
| Engine         | Deep Crawl, Sieve, Forge, Chain, Merge, Strobe                                             |
| Output         | HTML, JSON, CSV, Markdown, SARIF                                                          |

## Usage

```bash
sxel -u https://target.com --all --crawl
sxel -u https://target.com --crawl --depth 3 --waf-detect
sxel -l targets.txt --all --json-output results.json
sxel --help
```

## Output

```
[INF] [scanner] sXray 1.0.0
[INF] [scanner] loaded 37 modules
[INF] [scanner] crawling https://target.com

[INF] [crawler] found 42 endpoints
[INF] [scanner] starting scan...

[VULN] [sqli] https://target.com/api/search?id=1' -- Error-based SQL Injection
[VULN] [sqli] https://target.com/products?cat=1 AND 1=1 -- Boolean-based SQL Injection
[HIGH] [xss]  https://target.com/feedback?msg=<img/src=x> -- Reflected XSS
[MED]  [csrf] https://target.com/profile/update -- Missing CSRF token
[VULN] [ssrf] https://target.com/fetch?url=http://169.254.169.254 -- SSRF (AWS metadata)
[LOW]  [misc] https://target.com -- Missing CSP header

[INF] [scanner] scan completed in 47s | 42 endpoints | 5 vulnerabilities found
```

## Templates

```yaml
id: cve-2024-example
info:
  name: Example CVE
  severity: critical
requests:
  - method: GET
    path:
      - "{{BaseURL}}/vulnerable-endpoint"
    matchers:
      - type: word
        words:
          - "vulnerable"
```

## Contributing

1. Fork the repo
2. Create a feature branch
3. Add your module with tests
4. Submit a PR

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).

---

**sxel** is maintained by [SentinelX Official](https://github.com/SentinelXofficial).
