---
name: "log-analysis"
description: "Security log parsing, anomaly detection, SIEM query building, and Sigma rule creation."
---

# Log Analysis & SIEM Integration

## When to Use
- Parsing Windows Event Logs, Linux syslog, or application logs.
- Building Splunk SPL, Elastic KQL/EQL, QRadar AQL, or Sentinel KQL queries.
- Creating Sigma rules for platform-agnostic detection.
- Detecting anomalies or attack patterns in log data.
- Building SIEM correlation rules for multi-event detection.

## Workflow
1. **Ingest Logs** — Paste, upload, or point to log files (syslog, auth.log, EVTX, Apache/Nginx).
2. **Parse & Normalize** — Run `scripts/log_parser.py` to structured JSON with auto-detected format.
3. **Detect Anomalies** — Run `scripts/anomaly_detector.py` for brute force, spikes, after-hours, and lateral movement.
4. **Write Detection Rules** — Convert findings to Sigma, then translate to target SIEM.
5. **Build Timeline** — Correlate events across sources for incident response.

## Scripts
- `scripts/log_parser.py` — Auto-detect and parse syslog, auth logs, Apache/Nginx access logs, and JSON logs into structured events.
- `scripts/anomaly_detector.py` — Statistical and heuristic anomaly detection (brute force, frequency spikes, after-hours, rare sources, privilege escalation, lateral movement).

## Output
- Normalized JSON events with security categorization.
- Anomaly report with severity-ranked findings.
- SIEM queries and Sigma rules.

## References
- `references/siem-queries/` — Splunk SPL, Sentinel KQL, and Elastic EQL examples.
- `references/sigma-templates/` — Portable detection rule templates.
