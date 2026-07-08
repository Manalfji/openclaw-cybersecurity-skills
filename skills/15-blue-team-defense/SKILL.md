---
name: "blue-team-defense"
description: "System hardening, detection engineering, baseline monitoring, and security posture improvement."
---

# Blue Team Defense & Hardening

## When to Use
- Hardening Linux or Windows servers against CIS benchmarks.
- Creating detection rules (Sigma, Splunk, KQL, YARA, Suricata).
- Establishing security baselines and monitoring drift.
- Patch management strategy and prioritization.
- Post-red-team or pentest remediation planning.

## Workflow
1. **Assess Current State** — Run `scripts/hardening_checker.py` to audit the system.
2. **Apply Hardening** — SSH/kernel/firewall configs, auditd/Sysmon, AppArmor/SELinux.
3. **Deploy Detection** — Write Sigma, Suricata, or YARA rules; ship to SIEM.
4. **Baseline & Monitor** — Capture normal behavior profiles and alert on drift.
5. **Patch & Validate** — Prioritize by CVSS + EPSS + CISA KEV; verify fixes.

## Scripts
- `scripts/hardening_checker.py` — Audit Linux systems against CIS-style benchmarks (SSH, firewall, sysctl, auditd, kernel modules).

## Output
- JSON hardening report with PASS/FAIL/WARN per check and remediation hints.
- Detection rules in Sigma, Suricata, or YARA format.
- Prioritized remediation roadmap.

## References
- `references/cis-checklists/` — Linux and Windows hardening checklists.
- `references/detection-templates/` — Sigma, Suricata, and YARA rule templates.
