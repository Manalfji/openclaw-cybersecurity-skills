---
name: "crypto-analysis"
description: "SSL/TLS auditing, cipher suite analysis, hash algorithm identification, encryption implementation review, and cryptographic weakness detection."
---

# Cryptographic Analysis & Assessment

## When to Use
Assessing cryptographic security: TLS configuration, cipher suites, hash algorithms, encryption code review, key management, and post-quantum migration planning.

## Workflow
1. Audit TLS configuration of a server using openssl, sslyze, or testssl.sh.
2. Evaluate cipher suite strength and compare against ratings table.
3. Identify hash algorithms from values or code and assess password hash security.
4. Review code for cryptographic anti-patterns (hardcoded keys, ECB mode, static IVs, weak hashes).
5. Assess key lengths, rotation schedules, and post-quantum cryptography readiness.

## Scripts
- `scripts/tls_auditor.py` — Python TLS/SSL configuration auditor. Checks certificate, protocol support, cipher suites, security headers, and assigns a grade (A–F).

## Output
- TLS audit JSON with grade, vulnerabilities, certificate details, and protocol/cipher assessments.
- Recommended nginx/Apache TLS configuration aligned with Mozilla Modern Profile.
- Code review checklist for encryption, certificate handling, and randomness.

## Prerequisites
```bash
pip install cryptography requests pyOpenSSL
```

**Recommended tools:** sslyze, testssl.sh, openssl, Wireshark, certbot

## References
- Mozilla SSL Configuration Generator
- NIST SP 800-52 Rev. 2 — TLS Guidelines
- SSL Labs Grading Criteria
- NIST Post-Quantum Cryptography Standards
- OWASP Cryptographic Failures
- OWASP Cryptographic Storage Cheat Sheet
- NIST Password Storage Guidelines
