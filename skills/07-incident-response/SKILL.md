---
name: "incident-response"
description: "IR playbook execution, evidence collection, forensic timeline analysis, and post-incident reporting."
---

# Incident Response & Digital Forensics

## When to Use
- Creating incident response playbooks (ransomware, phishing, breach, BEC, insider threat).
- Collecting forensic evidence with chain of custody.
- Building forensic timelines from multiple log sources.
- Interpreting memory forensics (Volatility) output.
- Generating post-incident reports for management or compliance.

## Workflow
1. **Prepare** — Verify tools, comms, and access before an incident occurs.
2. **Identify** — Confirm incident, scope, severity, and initial infection vector.
3. **Contain** — Isolate affected systems, block C2, revoke compromised credentials.
4. **Collect Evidence** — Run `scripts/evidence_collector.py` following order of volatility.
5. **Build Timeline** — Run `scripts/timeline_builder.py` to correlate events across sources.
6. **Eradicate & Recover** — Remove threats, patch, restore from verified backups.
7. **Report** — Document timeline, root cause, impact, and recommendations.

## Scripts
- `scripts/evidence_collector.py` — Collect volatile and non-volatile evidence from live Linux/Windows systems with SHA-256 hashing and chain-of-custody manifest.
- `scripts/timeline_builder.py` — Parse multiple log sources into a chronological forensic timeline (CSV, JSON, or HTML output).

## Output
- Evidence manifest with chain of custody and SHA-256 hashes.
- Chronological forensic timeline with severity classification.
- Post-incident report with root cause, impact, and remediation roadmap.

## References
- `references/ir-playbooks/` — Playbook templates for ransomware, phishing, BEC, and more.
- `references/volatility-cheatsheet.md` — Volatility 3 command quick-reference.
- `references/chain-of-custody-template.md` — Evidence custody form template.
