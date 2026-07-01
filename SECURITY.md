# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest (main branch) | Fully supported |
| tagged releases | Security patches provided |
| older than 2 minor versions | Best-effort only |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability in sxsc itself (not a vulnerability found by sxsc on a target), please report it privately:

- GitHub: Use the **"Report a vulnerability"** button under the Security tab of this repository
- Email: **sentinelxgit@gmail.com** (for sensitive disclosures)

### What to include

- Description of the vulnerability
- Steps to reproduce
- Affected version(s)
- Any potential impact

### Response timeline

- Acknowledgment within 48 hours
- Initial assessment within 5 business days
- Fix timeline depends on severity:
  - Critical: 3-5 days
  - High: 1-2 weeks
  - Medium: Next release cycle
  - Low: Backlog

### Disclosure policy

- We follow coordinated disclosure
- Reporter credited in release notes (unless you prefer anonymity)
- 30-day embargo before public disclosure (extendable by mutual agreement)

## Responsible Use

sxsc is a security testing tool. By using it, you agree to:

1. Only test systems you own or have explicit written authorization to test
2. Comply with all applicable laws and regulations
3. Not use sxsc for unauthorized access, denial of service, or any illegal activity

The maintainers assume no liability for misuse of this software.

## Bug Bounty

We welcome reports of vulnerabilities in sxsc itself through our security contact. At this time we do not offer a paid bug bounty program, but we will publicly acknowledge your contribution in:
- The release notes
- A dedicated "Security Researchers" section in our README
- GitHub Advisory credit

## Dependency Scanning

This project's dependencies are scanned via:
- `go mod tidy` on every build
- `go vet` on every build
- `govulncheck` in CI

If you find a vulnerable dependency, please report it.
