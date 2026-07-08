# Security Policy

## Supported Versions

| Version | Supported |
|:--------|:----------|
| 1.0.x   | ✅ Yes    |

## Reporting Security Issues

If you discover a security vulnerability in these skills or scripts:

1. **Do not open a public issue**
2. Email the maintainer directly (see repository owner)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

Response time: Within 7 days. Critical issues within 48 hours.

## Security Audit History

| Date | Auditor | Result |
|:-----|:--------|:-------|
| 2026-07-08 | Automated + Manual | All 33 scripts passed — 0 threats found |

### Known False Positives

Two scripts triggered automated security scans but are **legitimate security tools:**

1. **`payload_generator.py`** (Exploit Development)
   - Contains `eval()` and `exec()` **strings** (not calls)
   - These are **payload templates** output as text, never executed
   - Tool requires `--type` and `--lhost` flags + includes disclaimers

2. **`report_generator.py`** (CSOC Automation)
   - Matched `| sh` pattern in template text
   - No actual shell execution occurs
   - Pure Markdown generation for SOC reports

## Safe Usage Guidelines

### Authorization Requirements

These skills require explicit authorization:

| Skill | Required Authorization |
|:------|:-----------------------|
| Recon & OSINT | Written authorization for target scope |
| Exploit Development | Legal penetration testing agreement |
| Red Team Operations | Rules of engagement, scope document |
| Network Security | Network owner consent |
| Web Security | Application owner consent |
| Mobile Security | Device/application owner consent |
| Malware Analysis | Isolate in sandbox, handle with care |
| Incident Response | Incident commander authorization |

### Never Use Without Authorization

- Scanning networks you don't own
- Testing applications without permission
- Generating payloads for unauthorized targets
- Analyzing devices you don't have rights to access

### Safe Defaults

- All scripts default to **read-only** operations
- No automatic exploitation or payload delivery
- Network tools default to localhost/127.0.0.1
- Output is logged, not silently executed

## Script Security Checklist

Before running any script:

- [ ] I have authorization for the target scope
- [ ] I understand what the script does
- [ ] I've reviewed the script source code
- [ ] I'm running in an isolated/sandboxed environment if needed
- [ ] I have a rollback plan
- [ ] Output is being logged for review

## Disclaimer

These tools are for authorized security professionals. Unauthorized use may violate:

- Computer Fraud and Abuse Act (US)
- General Data Protection Regulation (EU)
- Local computer crime laws
- Terms of service agreements

Always obtain written authorization before testing systems you do not own or administer.
