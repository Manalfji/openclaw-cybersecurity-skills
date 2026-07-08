---
name: "web-security"
description: "Web application vulnerability testing, OWASP scanning, and API security checks."
---

# Web Application Security

## When to Use
Testing web applications and APIs for common vulnerabilities during authorized assessments.

## Workflow
1. Scope the target URLs/endpoints and confirm authorization.
2. Run `owasp_scanner.py` for automated baseline checks.
3. Test API endpoints with `api_security_tester.py`.
4. Validate findings manually and rank by severity.
5. Document with remediation steps.

## Scripts
- `scripts/owasp_scanner.py` — Check security headers, TLS, CORS, and exposed sensitive paths.
- `scripts/api_security_tester.py` — JWT validation, input injection, rate-limit checks, and REST/GraphQL endpoint probing.

## Usage
```bash
# OWASP baseline scan
python scripts/owasp_scanner.py --url https://target.com --output findings.json

# API security tests
python scripts/api_security_tester.py --spec api_spec.json --base-url https://api.target.com --output api_findings.json
```

## Output
- JSON findings with severity, category, description, and remediation.
