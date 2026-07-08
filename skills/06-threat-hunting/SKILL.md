---
name: "threat-hunting"
description: "IOC extraction, MITRE ATT&CK mapping, and threat-hunting query generation."
---

# Threat Hunting

## When to Use
Extracting IOCs from reports, mapping behaviors to MITRE ATT&CK, and generating hunting queries for SIEM or EDR.

## Workflow
1. Parse threat reports, sandbox output, or incident artifacts.
2. Extract IOCs with `ioc_extractor.py`.
3. Map techniques to MITRE ATT&CK with `mitre_mapper.py`.
4. Generate platform-specific hunting queries (Splunk, KQL, Sigma).
5. Correlate across datasets for campaign identification.

## Scripts
- `scripts/ioc_extractor.py` — Extract hashes, IPs, domains, URLs, emails, registry keys, and file paths from text/PDF/JSON.
- `scripts/mitre_mapper.py` — Map technique names/IDs to ATT&CK tactics and generate hunting queries.

## Usage
```bash
# Extract IOCs from report
python scripts/ioc_extractor.py --input report.pdf --format json --output iocs.json

# Map to MITRE ATT&CK
python scripts/mitre_mapper.py --techniques T1055,T1059.001,T1003.001 --output hunt_plan.json
```

## Output
- Structured IOC lists (STIX/JSON/CSV).
- MITRE-mapped hunt plans with Splunk/KQL/Sigma queries.
