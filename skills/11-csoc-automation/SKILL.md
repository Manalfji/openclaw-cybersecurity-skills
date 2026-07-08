---
name: "csoc-automation"
description: "SOC alert triage, playbook automation, escalation workflows, shift reporting, and KPI tracking."
---

# CSOC Operations & Playbook Automation

## When to Use
Security Operations Center tasks: alert triage, playbook creation, escalation design, shift reporting, and metrics analysis.

## Workflow
1. Parse alert data from SIEM, EDR, WAF, IDS, or cloud audit logs.
2. Lookup asset criticality and enrich with threat intelligence (IP/hash/domain reputation, user risk).
3. Apply the triage matrix to determine severity, assigned tier, SLA, and recommended action.
4. Generate or adapt playbook YAML for SOAR platforms (Splunk SOAR, XSOAR, TheHive, ServiceNow).
5. Produce shift handover reports and monthly KPI dashboards (MTTD, MTTR, FPR, SLA compliance).

## Scripts
- `scripts/alert_triager.py` — Automated alert classification, prioritization, and tier assignment from JSON alert exports.
- `scripts/report_generator.py` — SOC shift handover and metrics report generator (Markdown/JSON).

## Output
- Triage results JSON with severity, assigned tier, SLA, and recommended actions.
- Playbook YAML compatible with Splunk SOAR, XSOAR, and TheHive.
- Shift handover Markdown reports and monthly KPI dashboards.

## Prerequisites
```bash
pip install pyyaml jinja2 requests python-dateutil
```

## References
- NIST Cybersecurity Framework
- SANS SOC Best Practices
- Splunk SOAR Playbooks
- Palo Alto XSOAR Documentation
- TheHive Project
- SOC Maturity Model (SOC-CMM)
