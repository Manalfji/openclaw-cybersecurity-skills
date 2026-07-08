---
name: "recon-osint"
description: "Network reconnaissance, subdomain enumeration, DNS analysis, and OSINT correlation."
---

# Reconnaissance & OSINT

## When to Use
Target enumeration for authorized security assessments: passive and active recon, subdomain discovery, DNS analysis, and technology fingerprinting.

Requires written authorization for the target scope before proceeding.

## Workflow
1. Identify target domain(s) and confirm authorization.
2. Run DNS reconnaissance with `dns_recon.py`.
3. Enumerate subdomains with `subdomain_enum.py`.
4. Fingerprint discovered web services with `tech_fingerprint.py`.
5. Correlate findings into an asset map.

## Scripts
- `scripts/dns_recon.py` — DNS record enumeration, zone transfer check, email security analysis.
- `scripts/subdomain_enum.py` — CT log queries, DNS brute-force, wildcard detection.
- `scripts/tech_fingerprint.py` — HTTP header analysis, CMS/framework detection, security header scoring.

## Usage
```bash
# Full DNS recon
python scripts/dns_recon.py --domain target.com --output dns_report.json

# Subdomain enumeration
python scripts/subdomain_enum.py --domain target.com --wordlist wordlist.txt --threads 20 --output subs.json

# Technology fingerprinting
python scripts/tech_fingerprint.py --url https://target.com --output tech_report.json
```

## Output
- JSON reports per script with resolved hosts, technologies, and misconfigurations.
- Structured asset map for downstream testing.
