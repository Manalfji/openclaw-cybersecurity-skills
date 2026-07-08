---
name: "red-team-ops"
description: "Authorized red team engagement planning, C2 architecture design, attack methodology, lateral movement strategy, OPSEC, and professional reporting."
---

# Red Team Operations & Engagement Planning

## When to Use
Planning or executing authorized red team engagements, adversary simulations, C2 infrastructure design, and purple-team exercises.

## Workflow
1. Confirm authorization: signed SOW/ROE, scope, deconfliction contacts, and emergency abort procedure.
2. Design engagement plan with threat profile, kill chain phases, and success criteria.
3. Architect multi-tier C2 infrastructure (team server, redirectors, channels, domains).
4. Map AD attack paths with BloodHound; plan Kerberoasting, DCSync, lateral movement.
5. Maintain an attack log (timestamp, host, technique, ATT&CK ID, telemetry) for the purple-team debrief.
6. Produce executive and technical reports with detection gaps and prioritized recommendations.

## Scripts
- `scripts/engagement_planner.py` — Generates ATT&CK-aligned engagement plans with authorization section, RoE, OPSEC plan, and attack-log scaffold (JSON/Markdown).

## Output
- Engagement plan Markdown/JSON with authorization, RoE, kill chain, and success criteria.
- Attack timeline with detection analysis and MTTD metrics.
- Prioritized recommendations mapped to MITRE ATT&CK.

## Prerequisites
```bash
pip install pyyaml requests
```

**Tools for authorized operations:** Cobalt Strike / Sliver / Havoc, Metasploit, BloodHound/SharpHound, Impacket, CrackMapExec/NetExec, Responder, Mimikatz

## References
- MITRE ATT&CK Framework
- Sliver C2 Documentation
- BloodHound Documentation
- Red Team Field Manual (RTFM)
- PTES Technical Guidelines
- Cobalt Strike Documentation
