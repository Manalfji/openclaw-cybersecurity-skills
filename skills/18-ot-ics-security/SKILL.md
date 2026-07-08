---
name: "ot-ics-security"
description: "Operational Technology and ICS security — Purdue model segmentation, industrial protocol analysis, PLC/HMI exposure, IEC 62443 alignment, and MITRE ATT&CK for ICS."
---

# OT / ICS / SCADA Security

## When to Use
Assessing Operational Technology and Industrial Control System environments: PLCs, RTUs, HMIs, SCADA servers, historians, and field devices.

## Workflow
1. Map assets to Purdue/ISA-95 levels and assess IT/OT boundary controls (IDMZ, dual-homed hosts, remote vendor access).
2. Passively analyze industrial protocol traffic (Modbus, DNP3, S7comm, EtherNet/IP, OPC-UA, BACnet, IEC 61850/104) from PCAP exports.
3. Flag control/write operations and unexpected talkers.
4. Perform passive asset inventory and external exposure checks (Shodan/Censys dorks only — no active probing of production OT).
5. Map adversary paths to MITRE ATT&CK for ICS.
6. Align recommendations to IEC 62443 zones/conduits/Security Levels and NIST SP 800-82.
7. Design OT-aware detection: baseline normal talkers, alert on unexpected writes/program downloads, off-hours commands, and L4→L1 traffic.

## Scripts
- `scripts/ics_protocol_analyzer.py` — Passive ICS protocol summarizer from tshark JSON exports. Flags control/write operations and generates Shodan/Censys exposure dorks.

## Output
- OT/ICS security assessment with Purdue map, zone/conduit analysis, and top safety-relevant risks.
- IEC 62443 zone/SL recommendations.
- Protocol summary with flagged control operations.

## Prerequisites
```bash
pip install requests pyyaml
# Protocol libraries (lab use): pip install pymodbus scapy
```

**Optional:** Wireshark/tshark with ICS dissectors, nmap ICS NSE scripts (read-only, with care), GRASSMARLIN

## References
- MITRE ATT&CK for ICS
- NIST SP 800-82 Rev. 3
- IEC 62443 series
- CISA ICS Recommended Practices & Advisories
- NERC CIP Standards
