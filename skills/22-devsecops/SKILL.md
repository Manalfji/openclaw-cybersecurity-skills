---
name: "devsecops"
description: "Scan CI/CD pipelines for secrets, vulnerable dependencies, and static code issues."
---

# DevSecOps Pipeline Security Scanner

## When to Use
A code repository or CI/CD pipeline needs security validation before deployment — detect exposed secrets, outdated dependencies, and basic static code vulnerabilities.

## Workflow
1. Clone or point the scanner at a target repository.
2. Run **Secret Detection** — scan files for hardcoded API keys, tokens, passwords, and private keys.
3. Run **Dependency Scanning** — check manifest files (requirements.txt, package.json, etc.) for known CVEs via OSV.
4. Run **SAST Basics** — flag dangerous patterns (eval, exec, SQL injection sinks, SSRF, insecure crypto).
5. Aggregate findings into a JSON or terminal report.
6. Exit with non-zero code if critical issues found (CI/CD gate).

## Scripts
- `scripts/devsecops_scanner.py` — Unified scanner covering secrets, dependencies, and SAST.

## Output
- Terminal summary with severity breakdown
- Per-category findings (secrets, dependencies, SAST)
- JSON export for CI/CD integration
- Exit codes: 0 = pass, 1 = critical findings

## Prerequisites
- Python 3.9+
- `pip install -r requirements.txt` (requests)
- Internet access for OSV dependency checks

## Compliance Mappings
- **Secrets:** OWASP Top 10 A07:2021 — Identification and Authentication Failures
- **Dependencies:** OWASP Top 10 A06:2021 — Vulnerable and Outdated Components
- **SAST:** OWASP Top 10 A03:2021 — Injection, A10:2021 — Server-Side Request Forgery