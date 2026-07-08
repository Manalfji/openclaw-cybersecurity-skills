# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2026-07-08

### Added
- Initial release with 19 cybersecurity skills adapted from Claude Code format to OpenClaw format
- 33 standalone Python scripts for security automation
- Security audit passed for all scripts (zero actual threats, 2 false positives on legitimate security tool patterns)
- Comprehensive README with installation and usage instructions
- SKILL_DETAILS.md with complete breakdown of every skill's purpose and capabilities

### Skills Included
| # | Skill | Scripts |
|---|-------|---------|
| 01 | Recon & OSINT | 3 |
| 02 | Vulnerability Scanner | 3 |
| 03 | Exploit Development | 1 |
| 04 | Reverse Engineering | 1 |
| 05 | Malware Analysis | 2 |
| 06 | Threat Hunting | 2 |
| 07 | Incident Response | 2 |
| 08 | Network Security | 1 |
| 09 | Web Security | 2 |
| 10 | Cloud Security | 2 |
| 11 | CSOC Automation | 2 |
| 12 | Log Analysis & SIEM | 2 |
| 13 | Cryptographic Analysis | 1 |
| 14 | Red Team Operations | 1 |
| 15 | Blue Team Defense | 1 |
| 16 | AI & LLM Security | 2 |
| 17 | Mobile Security | 1 |
| 18 | OT / ICS / SCADA Security | 1 |
| 19 | GRC Compliance | 2 |

### Changed
- Adapted all skills from Claude Code's verbose format to OpenClaw's lean format
- Removed all Claude-specific phrasing ("When the user asks...", "Claude should...")
- Simplified YAML frontmatter to `name` + `description` only
- Extracted inline scripts to standalone `scripts/` directories
- Cleaned scripts of hardcoded paths and Claude-specific references

### Security
- All 33 scripts reviewed for malicious code
- No actual threats found
- 2 false positives identified and documented (legitimate security tool patterns)
- Payload generator includes proper authorization disclaimers

## Original Source
- **Repository:** https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill
- **Version:** 3.0.0
- **License:** MIT
