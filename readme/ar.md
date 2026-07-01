# sxsc -- SentinelX Scanner

Single-target deep-dive web vulnerability scanner. **46 packages. 79 Go files. 118 YAML blueprints. 15MB binary. 36 attack modules. 17 engines.**

## Quick Start

```bash
go install github.com/SentinelXofficial/sxsc/cmd/sxsc@latest
sxsc -u "http://testphp.vulnweb.com/listproducts.php?cat=1"
sxsc -u "http://target.com" --deep --all --prove --delve --vault --rank
sxsc -u "http://target.com" --all --sarif results.sarif --ci
sxsc --strike results.json
sxsc --bundle results.json --bundle-out ./submission/
sxsc --diff yesterday.json today.json
sxsc -u "http://target.com" --all --hook https://hooks.slack.com/xxx
```

## Modules (36)

**Injection:** SQLi, NoSQLi, CMDI, SSTI, CRLF, Host Header, Header/Cookie, JSON
**Cross-Site:** XSS, CSRF, CORS, Open Redirect, Proto Pollution
**File/Path:** Path Traversal, LFI/RFI, File Upload, XXE, SSRF
**Auth/Session:** JWT, Cookie Audit, IDOR
**Infrastructure:** Security Headers, HTTP Methods, Sensitive Files, Dir Brute, GraphQL, WAF, Rate Limit, TLS
**Recon:** Subdomain Enum, Subdomain Takeover, WebSocket, JS Endpoints, robots.txt
**Advanced:** HTTP Smuggling, Cache Poisoning, Deserialization, Race Condition, OAuth/SAML, gRPC

## Engines (17)

Blueprint | OOB | Fuzzer | Auth | Flow | Verdict | Mold | Wire | Strobe | Prove | Tally | Delve | Vault | Drift | Chain | Pulse | Mirror

## YAML Blueprints (118)

16 categories: cves, misconfig, exposures, technologies, panels, cloud, api, cms, files, devops, network, frameworks, auth, backups, iot, defaults

## Flags

`-u`, `-l`, `--crawl`, `--deep`, `--all`, `--template`, `--template-dir`, `--oob`, `--fuzz`, `--flow`, `--prove`, `--delve`, `--rank`, `--vault`, `--drift`, `--mirror`, `--live`, `--json-output`, `--html-output`, `--sarif`, `--bundle`, `--hook`, `--strike`, `--diff`, `--ci`, `--interact`, `--sync`

## Docs

[English](../README.md) | [ID](id.md) | [ZH](zh.md) | [RU](ru.md) | [AR](ar.md) | [ES](es.md) | [JA](ja.md) | [PT](pt.md) | [FR](fr.md) | [HI](hi.md) | [KO](ko.md)

## Build

```bash
git clone https://github.com/SentinelXofficial/sxsc
cd sxsc && go mod tidy && go build -o sxsc ./cmd/sxsc
```

## Author

**WildanDev** -- [@SentinelXofficial](https://github.com/SentinelXofficial)
