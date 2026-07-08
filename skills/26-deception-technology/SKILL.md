---
name: "deception-technology"
description: "Honeypots, honeytokens, canary tokens, and deception-based threat detection."
---

# Deception Technology & Honeypot Operations

## When to Use
- Deploying honeypots to detect unauthorized access
- Creating honeytokens to detect credential theft
- Setting up canary files for data exfiltration detection
- Analyzing attacker behavior through deception

## Workflow
1. **Honeypot Deployment** — Set up low-interaction honeypots (SSH, HTTP, DNS)
2. **Honeytoken Creation** — Generate fake credentials and tokens
3. **Canary Deployment** — Place deceptive files in sensitive locations
4. **Log Analysis** — Analyze honeypot logs for attacker behavior
5. **Alert Generation** — Generate alerts when deception is triggered

## Scripts
- `honeypot_log_analyzer.py` — Analyze honeypot logs for attacker behavior
- `honeytoken_generator.py` — Generate fake credentials and tokens
- `canary_deployer.py` — Deploy canary files and monitor access

## Output
- Honeypot interaction reports
- Honeytoken exposure alerts
- Canary access notifications

## Prerequisites
```bash
pip install pyyaml
```

## Important Notes
- Honeypots should be isolated from production networks
- Honeytokens should appear realistic but be non-functional
- Canary files should be named to appear valuable
- Monitor honeypots regularly for attacker behavior

## Safety
- Never deploy honeypots on production systems
- Ensure honeypots cannot be used as pivot points
- Honeytokens should not grant actual access
- Legal review recommended before deployment
