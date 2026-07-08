# OpenClaw CyberSecurity Skills

22 production-quality cybersecurity skills adapted for **OpenClaw** — covering offensive security, defensive operations, reverse engineering, threat hunting, CSOC automation, AI/LLM security, mobile, OT/ICS, GRC, phishing analysis, container security, and DevSecOps.

Originally from [Masriyan/Claude-Code-CyberSecurity-Skill](https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill) — adapted to OpenClaw's leaner skill format.

## Table of Contents

- [What Changed](#what-changed-claude-code--openclaw)
- [Skills Overview](#skills-overview)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
- [Skill Details](#skill-details)
- [Script Dependencies](#script-dependencies)
- [Skill Structure](#skill-structure)
- [Safety & Authorization](#safety--authorization)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [Credits](#credits)
- [License](#license)
- [Disclaimer](#disclaimer)

## What Changed (Claude Code → OpenClaw)

| Aspect | Claude Code | OpenClaw |
|---|---|---|
| **Frontmatter** | `name`, `description`, `version`, `author`, `tags` | `name`, `description` only (short, noun-phrase) |
| **Body** | Heavy Claude-specific phrasing | Lean workflow steps + script references |
| **Structure** | Dense capability docs | Minimal — deterministic scripts do the work |
| **Scripts** | Referenced inline, sometimes with hardcoded paths | Copied to `scripts/`, cleaned, standalone |

## Skills Overview

| # | Skill | Domain | Key Capabilities | Scripts |
|:---|:---|:---|:---|:---:|
| 01 | [Recon & OSINT](skills/01-recon-osint/) | Reconnaissance | Subdomain enum, DNS analysis, tech fingerprinting | 3 |
| 02 | [Vulnerability Scanner](skills/02-vulnerability-scanner/) | Assessment | Dependency audit, config review, CVSS scoring | 3 |
| 03 | [Exploit Development](skills/03-exploit-development/) | Offensive | PoC templates, payload generation | 1 |
| 04 | [Reverse Engineering](skills/04-reverse-engineering/) | Analysis | Binary triage, assembly, firmware RE | 1 |
| 05 | [Malware Analysis](skills/05-malware-analysis/) | Threat Analysis | Static analysis, YARA generation, IOC extraction | 2 |
| 06 | [Threat Hunting](skills/06-threat-hunting/) | Hunting | IOC extraction, ATT&CK mapping, Sigma rules | 2 |
| 07 | [Incident Response](skills/07-incident-response/) | IR & Forensics | PICERL playbooks, evidence collection, timeline | 2 |
| 08 | [Network Security](skills/08-network-security/) | Network | PCAP analysis, Suricata/Snort rules, firewall audit | 1 |
| 09 | [Web Security](skills/09-web-security/) | Web | OWASP Top 10, API security, JWT analysis | 2 |
| 10 | [Cloud Security](skills/10-cloud-security/) | Cloud | AWS/Azure/GCP audit, K8s hardening, IaC scanning | 2 |
| 11 | [CSOC Automation](skills/11-csoc-automation/) | SOC Ops | Alert triage, playbooks, KPI tracking | 2 |
| 12 | [Log Analysis & SIEM](skills/12-log-analysis/) | Log Analysis | Splunk/KQL/EQL queries, Sigma rules | 2 |
| 13 | [Cryptographic Analysis](skills/13-crypto-analysis/) | Crypto | TLS audit, cipher analysis, hash ID | 1 |
| 14 | [Red Team Operations](skills/14-red-team-ops/) | Red Team | Engagement planning, C2 design, OPSEC | 1 |
| 15 | [Blue Team Defense](skills/15-blue-team-defense/) | Blue Team | Hardening, detection engineering, baselines | 1 |
| 16 | [AI & LLM Security](skills/16-ai-llm-security/) | AI Security | Prompt injection, OWASP LLM Top 10, AI red teaming | 2 |
| 17 | [Mobile Security](skills/17-mobile-security/) | Mobile | Android/iOS testing, APK/IPA analysis | 1 |
| 18 | [OT / ICS / SCADA Security](skills/18-ot-ics-security/) | Industrial | Purdue model, Modbus/DNP3/S7 analysis | 1 |
| 19 | [GRC Compliance](skills/19-grc-compliance/) | Compliance | Control mapping, risk register, audit prep | 2 |
| 20 | [Phishing Analysis](skills/20-phishing-analysis/) | Email Security | `.eml` parsing, SPF/DKIM/DMARC checks, URL enrichment | 1 |
| 21 | [Container Security](skills/21-container-security/) | Containers | K8s pod security, RBAC, secrets, network policies | 1 |
| 22 | [DevSecOps](skills/22-devsecops/) | Pipeline | Secret detection, dependency CVE scanning, SAST | 1 |

**Total: 22 skills, 36 standalone scripts**

## Quick Start

See [QUICKSTART.md](QUICKSTART.md) for a 5-minute getting started guide.

```bash
# Clone all skills
git clone https://github.com/YOUR-USERNAME/openclaw-cybersecurity-skills.git ~/.openclaw/skills/openclaw-cybersecurity-skills

# Use in OpenClaw
"Analyze this PCAP for suspicious beaconing"        # → network-security
"Audit my server's hardening posture"                 # → blue-team-defense
"Build a timeline from these log files"             # → incident-response
"Scan my dependencies for CVEs"                       # → vulnerability-scanner
```

## Installation

### Option 1: Clone into your skills directory

```bash
# Global skills (all sessions)
git clone https://github.com/YOUR-USER/openclaw-cybersecurity-skills.git ~/.openclaw/skills/

# Project-specific skills (current session only)
git clone https://github.com/YOUR-USER/openclaw-cybersecurity-skills.git ./.openclaw/skills/
```

### Option 2: Copy individual skills

```bash
# Copy just what you need
cp -r skills/network-security ~/.openclaw/skills/
cp -r skills/blue-team-defense ~/.openclaw/skills/
```

### Option 3: Symlink for development

```bash
ln -s /path/to/openclaw-cybersecurity-skills/skills/* ~/.openclaw/skills/
```

## Usage

Skills are triggered by description matching. Reference them naturally:

- *"Analyze this PCAP file for suspicious beaconing"* → `network-security`
- *"Audit my server's hardening posture"* → `blue-team-defense`
- *"Generate a Sigma rule for this log pattern"* → `log-analysis`
- *"Review my Kubernetes manifests for security issues"* → `cloud-security`

See [QUICKSTART.md](QUICKSTART.md) for common activation patterns and workflows.

## Skill Details

For complete documentation on every skill — what it does, when to use it, expected output — see [SKILL_DETAILS.md](SKILL_DETAILS.md).

Quick reference:

| Skill | Use When You Need To... |
|:------|:------------------------|
| Recon & OSINT | Map attack surface, find subdomains, fingerprint tech |
| Vulnerability Scanner | Check dependencies, configs, calculate CVSS |
| Exploit Development | Generate authorized PoC payloads |
| Reverse Engineering | Analyze binaries, firmware, unknown executables |
| Malware Analysis | Examine suspicious files, extract IOCs, write YARA |
| Threat Hunting | Proactively search for compromise, map to ATT&CK |
| Incident Response | Respond to incidents, collect evidence, build timelines |
| Network Security | Analyze PCAP, write IDS rules, audit firewalls |
| Web Security | Test web apps/APIs for OWASP Top 10 |
| Cloud Security | Audit AWS/Azure/GCP configs, scan IaC templates |
| CSOC Automation | Triage alerts, generate SOC reports, track KPIs |
| Log Analysis | Parse logs, detect anomalies, write SIEM queries |
| Cryptographic Analysis | Audit TLS, check ciphers, prepare for PQC |
| Red Team Operations | Plan authorized adversary simulations |
| Blue Team Defense | Harden systems, build detections, set baselines |
| AI & LLM Security | Secure LLM apps, test for prompt injection |
| Mobile Security | Analyze mobile apps (Android/iOS) |
| OT / ICS Security | Secure industrial control systems |
| GRC Compliance | Map controls, manage risk, prepare for audits |

## Script Dependencies

Most scripts are Python 3 and require standard libraries. Some skills need additional tools:

```bash
# Network security
pip install scapy dpkt

# Recon & OSINT
pip install requests dnspython python-whois beautifulsoup4

# Malware analysis
pip install yara-python

# Log analysis
pip install pyyaml
```

See individual `SKILL.md` files for per-skill prerequisites.

## Skill Structure

```
skills/
├── skill-name/
│   ├── SKILL.md          # Skill definition (lean, OpenClaw format)
│   ├── scripts/          # Standalone Python/bash tools
│   ├── references/       # Docs, templates, checklists (optional)
│   └── assets/           # Output templates, media (optional)
```

## Safety & Authorization

- **Offensive skills** (exploit development, red team) include authorization gates — confirm legal scope before proceeding.
- **All skills** assume you have proper authorization for the target scope.
- **No warranty** — these are educational and professional tools; use responsibly.

See [SECURITY.md](SECURITY.md) for detailed security policy, safe usage guidelines, and vulnerability reporting.

## Documentation

| Document | Purpose |
|:---------|:--------|
| [README.md](README.md) | You're reading it — project overview |
| [QUICKSTART.md](QUICKSTART.md) | 5-minute getting started guide |
| [SKILL_DETAILS.md](SKILL_DETAILS.md) | Complete breakdown of every skill |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to add skills, report issues, submit PRs |
| [SECURITY.md](SECURITY.md) | Security policy, safe usage, vulnerability reporting |
| [CHANGELOG.md](CHANGELOG.md) | Version history and changes |

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for:

- How to report bugs
- Adding new skills
- Improving existing skills
- Security requirements for scripts
- Code style guidelines

## Credits

- **Original work:** [Masriyan/Claude-Code-CyberSecurity-Skill](https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill)
- **Adaptation:** OpenClaw community
- **License:** MIT (same as original)

## License

MIT License — see [LICENSE](LICENSE) file for details.

## Disclaimer

These skills are for authorized security professionals. Unauthorized use of reconnaissance, exploitation, or red team techniques may violate laws. Always obtain written authorization before testing systems you do not own.
