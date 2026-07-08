---
name: "phishing-analysis"
description: "Analyze .eml files for phishing indicators and malicious IOCs."
---

# Phishing Email Analysis

## When to Use
A suspicious email (.eml) needs triage — extract IOCs, validate authentication headers, and assess risk.

## Workflow
1. Parse headers (From, Reply-To, Received, Authentication-Results).
2. Extract URLs, attachments, and origin IP from body/headers.
3. Check SPF/DKIM/DMARC results for failures.
4. Enrich IOCs with VirusTotal (URLs) and AbuseIPDB (IP) if API keys are available.
5. Calculate risk score and generate HTML + terminal report.

## Scripts
- `scripts/phishing_analyzer.py` — Main analyzer: parses .eml, extracts IOCs, scores risk, generates reports.

## Output
- Terminal summary with risk level (LOW / MEDIUM / HIGH / CRITICAL)
- HTML report file for ticketing
- Extracted IOCs: URLs, sender IP, attachments

## Prerequisites
- Python 3.8+
- `pip install -r requirements.txt` (rich, requests)
- Optional: `VT_API_KEY` and `ABUSEIPDB_API_KEY` environment variables for threat-intel enrichment