---
name: "network-security"
description: "Network traffic analysis, IDS/IPS rules, firewall auditing, and anomaly detection."
---

# Network Security & Traffic Analysis

## When to Use
- Analyzing PCAP or PCAPNG files for suspicious activity.
- Creating Suricata or Snort detection rules.
- Writing Zeek scripts for network analysis.
- Auditing firewall rules (iptables, nftables, cloud security groups).
- Detecting C2 beaconing, DNS tunneling, or data exfiltration.

## Workflow
1. **Capture / Obtain Traffic** — Use `tcpdump`, tshark, or existing PCAP files.
2. **Quick Triage** — Protocol hierarchy, TCP conversations, IP endpoints via `tshark`.
3. **Automated Analysis** — Run `scripts/pcap_analyzer.py` for beaconing, DNS, and port-scan detection.
4. **Rule Creation** — Write Suricata/Snort rules or Zeek scripts based on findings.
5. **Firewall Audit** — Review iptables, AWS security groups, or nftables against checklists.

## Scripts
- `scripts/pcap_analyzer.py` — Parse PCAP files; detects beaconing, port scanning, DNS tunneling, and top talkers.

## Output
- JSON analysis report with protocol stats, beaconing alerts, and suspicious DNS domains.
- Suricata/Snort rules ready for deployment.
- Firewall audit findings with remediation steps.

## References
- `references/suricata-rules/` — Rule templates for common attack patterns.
- `references/firewall-checklists/` — iptables, AWS SG, and nftables audit checklists.
