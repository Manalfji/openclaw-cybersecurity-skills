# Quick Start Guide

Get up and running with OpenClaw CyberSecurity Skills in 5 minutes.

## Prerequisites

- Python 3.10+
- OpenClaw installed
- Git (optional, for cloning)

## Install Skills

### Option 1: Clone All Skills (Recommended)

```bash
# Global skills (available in all OpenClaw sessions)
git clone https://github.com/YOUR-USERNAME/openclaw-cybersecurity-skills.git ~/.openclaw/skills/openclaw-cybersecurity-skills

# Or symlink for easy updates
ln -s /path/to/openclaw-cybersecurity-skills/skills/* ~/.openclaw/skills/
```

### Option 2: Copy Individual Skills

```bash
# Only copy what you need
cp -r skills/network-security ~/.openclaw/skills/
cp -r skills/blue-team-defense ~/.openclaw/skills/
cp -r skills/incident-response ~/.openclaw/skills/
```

### Option 3: Project-Specific Skills

```bash
# Inside your project directory
cp -r /path/to/openclaw-cybersecurity-skills/skills/* ./.openclaw/skills/
```

## Verify Installation

```bash
# Check skills are recognized
openclaw skills list

# Or look in the skills directory
ls ~/.openclaw/skills/
```

## Your First Skill Trigger

Try these natural language prompts in OpenClaw:

### Network Security
```
"Analyze this PCAP file for suspicious beaconing"
"Check my firewall rules for misconfigurations"
"Write a Suricata rule for DNS tunneling detection"
```

### Blue Team Defense
```
"Audit my server's hardening against CIS benchmarks"
"Check for insecure file permissions"
"Review my SSH configuration"
```

### Incident Response
```
"Build a timeline from these log files"
"Collect evidence for incident INC-2024-001"
"Generate an incident response report"
```

### Vulnerability Scanner
```
"Scan my Python dependencies for CVEs"
"Review this config file for security issues"
"Calculate CVSS score for this finding"
```

## Run Scripts Directly

Skills include standalone scripts you can run without OpenClaw:

```bash
# Network analysis
cd skills/network-security/scripts
python3 pcap_analyzer.py --file capture.pcap --output analysis.json

# System hardening audit
cd skills/blue-team-defense/scripts
python3 hardening_checker.py --os linux --level 2

# Vulnerability scan
cd skills/vulnerability-scanner/scripts
python3 dependency_auditor.py --file requirements.txt --format json

# Log analysis
cd skills/log-analysis/scripts
python3 anomaly_detector.py --file /var/log/auth.log --sensitivity high
```

## Skill Activation Patterns

| Say This... | Triggers This Skill |
|:------------|:--------------------|
| "Scan for subdomains" | Recon & OSINT |
| "Check dependencies" | Vulnerability Scanner |
| "Generate a payload" | Exploit Development |
| "Analyze this binary" | Reverse Engineering |
| "Extract IOCs" | Malware Analysis |
| "Hunt for threats" | Threat Hunting |
| "Respond to incident" | Incident Response |
| "Analyze PCAP" | Network Security |
| "Test this API" | Web Security |
| "Audit AWS config" | Cloud Security |
| "Triage alerts" | CSOC Automation |
| "Parse logs" | Log Analysis |
| "Check TLS config" | Cryptographic Analysis |
| "Plan red team" | Red Team Operations |
| "Harden server" | Blue Team Defense |
| "Test LLM security" | AI & LLM Security |
| "Analyze APK" | Mobile Security |
| "Check ICS traffic" | OT / ICS Security |
| "Map controls" | GRC Compliance |

## Common Workflows

### Security Assessment Workflow

1. **Recon:** "Enumerate subdomains for example.com"
2. **Vulnerability Scan:** "Scan dependencies in this project"
3. **Web Security:** "Test login page for SQL injection"
4. **Network Security:** "Analyze this PCAP for C2 traffic"
5. **Report:** "Generate vulnerability report"

### Incident Response Workflow

1. **Detection:** "Analyze logs for this timeframe"
2. **Investigation:** "Build timeline from these events"
3. **Containment:** "Isolate this host"
4. **Evidence:** "Collect and hash evidence files"
5. **Report:** "Generate incident response report"

### Blue Team Hardening Workflow

1. **Audit:** "Audit system hardening"
2. **Vulnerability:** "Check for missing patches"
3. **Detection:** "Write Sigma rule for this behavior"
4. **Monitoring:** "Configure log forwarding"
5. **Verify:** "Re-audit after remediation"

## Troubleshooting

### Skill not triggering?
- Check skill is in `~/.openclaw/skills/` or `./.openclaw/skills/`
- Verify SKILL.md has valid YAML frontmatter
- Try more specific keywords from the skill description

### Script fails with import error?
```bash
# Install common dependencies
pip install requests dnspython beautifulsoup4 pyyaml

# For specific skills, see SKILL.md prerequisites
```

### Permission denied?
```bash
chmod +x skills/*/scripts/*.py
```

## Next Steps

- Read [SKILL_DETAILS.md](SKILL_DETAILS.md) for complete skill documentation
- Review [CONTRIBUTING.md](CONTRIBUTING.md) to add your own skills
- Check [SECURITY.md](SECURITY.md) for safe usage guidelines

## Getting Help

- Open an issue: https://github.com/YOUR-USERNAME/openclaw-cybersecurity-skills/issues
- Start a discussion: https://github.com/YOUR-USERNAME/openclaw-cybersecurity-skills/discussions
- Tag `@maintainers` for urgent issues
