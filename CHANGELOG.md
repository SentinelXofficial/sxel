# Changelog

All notable changes to sxel will be documented in this file.

## [1.2.4] — Accuracy & Reliability Fixes (2026-08-23)

### Scanner accuracy — false positive/negative fixes
- **Update check**: version comparison now segment-aware (`1.2.10` vs `1.3.0` no longer
  misordered; self-update can no longer offer downgrades)
- **Template engine**: a single `need: all` sign no longer flips the whole sign group to
  AND — independent signs are OR-ed; group AND applies only when every sign needs all
  (preserves Nuclei `matchers-condition: and` conversion); signs with `status` lists but
  missing `on: status` now classify correctly
- **WAF detection**: cookie signatures with `^` anchors are matched per-cookie instead of
  against the joined jar, so Incapsula/Barracuda/F5 APM cookies are detected even when not
  the first Set-Cookie; duplicate F5/Kona signatures removed; ThreatX body pattern unanchored
- **XXE**: `/etc/hostname` detection requires the whole page text to be a bare hostname
  (was matching any `<tag>word</tag>` fragment → CRITICAL false positives); base64 hostname
  branch now actually works
- **NoSQLi**: a status drift on the payload request (e.g., WAF 403) is no longer reported as
  boolean-based injection
- **Directory scan severity**: sensitive paths (`.env`, `.git`, …) are HIGH only on HTTP 200;
  HTTP 403 now reports MEDIUM
- **Command injection (blind)**: timed payloads require a confirmation pass so a single
  network jitter spike cannot fabricate a CRITICAL finding
- **Blind SQLi**: ratio fallback in `confirmed()` gains an absolute floor
- **GraphQL**: introspection finding requires real schema data (`data.__schema.queryType`),
  not just the literal string echoed by hardened servers' error pages
- **403 bypass**: `./path` and `..;/path` variants keep a leading slash so probes stay on
  the target host
- **Clutch**: burst size scales down only — small `--threads` no longer amplifies bursts

### Engine & infrastructure reliability
- **Checkpoint**: flushes on SIGINT/SIGTERM (findings from the last seconds survive Ctrl-C);
  data race in `Flush()` fixed; unsaved state flushed before checkpoint deletion
- **Retry layers**: rate-limit exhaustion and context cancellation are no longer retried by
  the outer retryablehttp layer (~9 attempts → 3)
- **Crawler**: visited-map compaction keeps in-flight URLs (no re-fetch duplicates)
- **PoC runner**: nil rules error cleanly instead of panicking; PoC requests inherit proxy/
  TLS settings from the scanner transport chain
- **JWT module**: token tests use a jar-less client — session jar no longer replays the
  original cookie alongside the modified one
- **Auth**: session verification fails on HTTP ≥4xx verify responses; dashboards embedding a
  change-password form no longer count as "still on login page"
- **Chain SSRF probe** keeps target path/query and URL-encodes payloads
- **burp-gamma**: original headers (Content-Type, Authorization, cookies) preserved in
  converted PoCs
- **HTTP API mode**: scans use the standard client construction; finished jobs evicted
  (bounded memory)
- **Misc**: file-upload fetch-back status shadowing; smuggling TE.TE evidence `%d` formatting;
  breach/gRPC double-slash probes on root targets; multiline `<title>` extraction; SARIF URI
  escaping; config validation for negative numeric values; LiteSpeed fingerprint case;
  predictable headless-shell temp filename; `toBool("false")`; deserialization payload slice
  aliasing; VulnApp nav link `/tools/ping` → `/tools`; JS-crawl render waits for document
  readyState (fixes flaky discovery under load)

### Testing
- New regression tests: version comparison, template sign semantics, WAF multi-cookie,
  XXE hostname, NoSQLi status-drift FP, nil-rule PoC, dirscan severity matrix, checkpoint
  concurrency, dirscan recursive race (all green under `-race`)
- Full suite passes with `-race -count=1`

## [1.2.0] — Major Update: Accuracy + VulnApp Lab (2026-08-16)

### Scanner accuracy — false-positive fixes
- **XSS**: entity-encoded reflection in inert (non-executable) contexts no longer
  triggers LOW "Reflected input"; genuine attribute-context breakout is still detected
- **SSRF**: probe markers that are substrings of the probe URL itself no longer match
  when the server simply echoes parameters (previously CRITICAL false positives)

### VulnApp — local testing lab (new)
- Deliberately vulnerable PHP 8 + MariaDB shop (DVWA-style) for realistic scanning practice
- Vulnerabilities: SQLi (error/union/boolean/time), reflected + stored XSS, blind command
  injection, JWT (weak secret + alg none), LFI, SSRF, open redirect, IDOR, CSRF,
  unrestricted file upload, sensitive-file demo, admin panel
- Packaging: Docker Compose (web + mariadb:11, healthcheck, auto-seed) or native apt setup
- Seeded demo data (users, products, posts, comments) — credentials: admin/admin, alice/alice123

### Integration testing overhaul
- Test harness now boots the real lab: `php -S` + local MariaDB with automatic DB seed;
  tests auto-skip when PHP/MariaDB are not installed
- 17 integration tests, including 9 live scans against VulnApp covering SQLi
  (error/union/boolean/time), XSS, command injection, JWT, LFI, and open redirect

### CI
- Integration step in GitHub Actions: `mariadb:11` service container +
  `shivammathur/setup-php` for the integration suite

### Docs
- README: new VulnApp lab section; version refresh

## [1.0.0] — Initial Release

### Core Scanner (36 attack modules)
- SQL Injection: error-based, time-based blind, boolean-based blind
- NoSQL Injection: MongoDB operators ($gt, $ne, $regex, $where)
- Command Injection: response-based + blind time-based
- XSS: reflected via URL params, forms, headers, cookies, JSON, WebSocket
- SSTI: Jinja2, FreeMarker, ERB, Liquid, Spring EL detection
- SSRF: 12 probe targets including AWS/GCP/Azure metadata
- XXE: 6 payload types, 6 content-type variants
- Path Traversal: 15+ payload patterns (Unix + Windows)
- LFI/RFI: 18 LFI payloads, 5 RFI payloads, log poisoning
- File Upload: 9 bypass techniques (double ext, null byte, MIME spoof)
- JWT Attacks: alg:none, RS256→HS256 confusion, weak secret, empty signature
- IDOR: numeric ID walk, path segment detection
- CRLF Injection, Host Header Injection, Open Redirect
- WebSocket scanning, GraphQL probing (5 checks)
- CSRF detection + enforcement testing
- Cookie Security Audit: Secure, HttpOnly, SameSite, Domain, MaxAge
- Prototype Pollution: __proto__ + constructor.prototype
- Insecure Deserialization: PHP/Java/Python/.NET markers
- HTTP Request Smuggling: CL.TE, TE.CL, TE.TE via raw TCP
- Web Cache Poisoning: 12+ unkeyed headers
- Race Condition / TOCTOU detection
- OAuth 2.0 / SAML misconfiguration probing
- gRPC reflection + REST gateway detection
- Directory Brute Force: 190+ built-in wordlist
- Sensitive Files: 47 config/backup/debug paths
- Security Headers: HSTS, CSP, XFO, CORS, etc.
- HTTP Methods: PUT/DELETE/TRACE detection
- Subdomain Enumeration: crt.sh + DNS brute-force
- Subdomain Takeover: 25+ vulnerable cloud services
- WAF Detection: 12 vendors, auto-bypass
- Rate Limit Testing
- TLS/SSL Handshake probing

### Advanced Engines (19 engines)
- YAML Blueprint Engine (template system)
- OOB Detection Server (HTTP + DNS callback)
- Smart Mutation Fuzzer (12 strategies)
- Multi-Step Auth Profiles (OAuth2, form, bearer)
- Flow Engine (DAG vulnerability chaining)
- Verdict Engine (Clues + Pickers signal detection)
- Mold Engine (16-function template variable engine)
- Wire Engine (raw HTTP for smuggling)
- Strobe Pipeline (adaptive deep-dive)
- Prove Engine (auto-demonstrate impact)
- Tally Engine (composite risk scoring)
- Delve Engine (auto-escalation)
- Vault Engine (credential classification)
- Drift Engine (differential testing)
- Chain Engine (11 compound attack patterns)
- Pulse Engine (session health + auto-renewal)
- Mirror Engine (request/response cache)
- Sieve Engine (parameter mining from 7 sources)
- Forge Engine (adaptive payloads per tech stack)

### Output & Integration
- HTML, JSON, CSV, Markdown, Console reports
- SARIF v2.1.0 for GitHub Code Scanning
- CI/CD exit codes (0=clean, 3=critical)
- Webhook notifications (Slack, Discord, Telegram)
- Scan diff (compare two result sets)
- Bug bounty ZIP bundler with Markdown + PoC
- PoC exploit generator (curl, python, HTML)
- Community blueprint sync engine
- Interactive scan wizard
- Checkpoint / resume for long-running scans

### Templates
- 118 YAML blueprints across 16 categories
- Nuclei-compatible YAML syntax subset
- Variable interpolation, 3 payload fan-out modes

### Documentation
- 10-language README: EN, ID, ZH, RU, AR, ES, JA, PT, FR, HI, KO
- Full architecture doc, flag reference, project structure

### Stats
- 46 Go packages, 79 source files
- 18,802 lines of Go, 2,267 lines of YAML
- Single 15MB binary, zero runtime dependencies
- Build: `go build -o sxel ./cmd/sxel`
