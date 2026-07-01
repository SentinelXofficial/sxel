# Changelog

All notable changes to sxsc will be documented in this file.

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
- Build: `go build -o sxsc ./cmd/sxsc`
