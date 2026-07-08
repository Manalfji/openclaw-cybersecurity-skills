# Examples & Tutorials

Practical examples showing how to use OpenClaw cybersecurity skills.

## Table of Contents

- [Network Security: PCAP Analysis](#network-security-pcap-analysis)
- [Blue Team: System Hardening](#blue-team-system-hardening)
- [Cryptocurrency: Address Validation](#cryptocurrency-address-validation)
- [Incident Response: Timeline Building](#incident-response-timeline-building)
- [DevSecOps: Pipeline Scanning](#devsecops-pipeline-scanning)

---

## Network Security: PCAP Analysis

### Scenario
You have a PCAP file and want to check for suspicious beaconing.

### Using the Skill in OpenClaw
```
"Analyze this PCAP file for suspicious beaconing"
"Create a Suricata rule for DNS tunneling detection"
```

### Using the Script Directly
```bash
cd skills/08-network-security/scripts
python3 pcap_analyzer.py --file /path/to/capture.pcap --output analysis.json
```

### Expected Output
```json
{
  "protocol_distribution": {"TCP": 1200, "UDP": 450, "DNS": 380},
  "beaconing_detected": true,
  "suspicious_ips": ["192.168.1.100"],
  "dns_tunneling_score": 0.85
}
```

---

## Blue Team: System Hardening

### Scenario
Audit a new Linux server before production deployment.

### Using the Skill in OpenClaw
```
"Audit my server's hardening against CIS benchmarks"
"Check for insecure file permissions"
```

### Using the Script Directly
```bash
# Ubuntu/Debian
cd skills/15-blue-team-defense/scripts
python3 hardening_checker.py --os ubuntu --output report.json

# CentOS/RHEL
python3 hardening_checker.py --os centos --output report.json

# Auto-detect OS
python3 hardening_checker.py --os auto --output report.json
```

### Expected Output
```json
{
  "os": "Ubuntu",
  "total_checks": 34,
  "passed": 28,
  "failed": 6,
  "score_pct": 82.4,
  "findings": [
    {
      "id": "SSH-001",
      "severity": "HIGH",
      "title": "Password authentication enabled",
      "remediation": "Set PasswordAuthentication no in sshd_config"
    }
  ]
}
```

---

## Cryptocurrency: Address Validation

### Scenario
Verify a Bitcoin address before sending funds.

### Using the Skill in OpenClaw
```
"Validate this Bitcoin address"
"Check if this mnemonic phrase is valid"
```

### Using the Script Directly
```bash
cd skills/23-cryptocurrency-security/scripts

# Validate single address
python3 crypto_validator.py --address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

# Validate multiple addresses
python3 crypto_validator.py --address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh

# Validate Ethereum address
python3 crypto_validator.py --address 0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb

# Check mnemonic phrase
python3 crypto_validator.py --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

# Check file of addresses for entropy issues
python3 crypto_validator.py --check-entropy addresses.txt --output report.json
```

### Expected Output
```
============================================================
CRYPTOCURRENCY SECURITY VALIDATION REPORT
============================================================

Total checked: 1
Valid: 1 ✅
Invalid: 0 ❌
With issues: 0 ⚠️

------------------------------------------------------------

✅ VALID: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
  Type: bitcoin
  Format: P2PKH (Pay-to-Public-Key-Hash)
```

---

## Incident Response: Timeline Building

### Scenario
Build a timeline from log files during an active incident.

### Using the Skill in OpenClaw
```
"Build a timeline from these log files"
"Generate an incident response report"
```

### Using the Script Directly
```bash
cd skills/07-incident-response/scripts

# Build timeline from multiple log files
python3 timeline_builder.py --logs /var/log/auth.log /var/log/syslog --output timeline.json

# With specific timeframe
python3 timeline_builder.py --logs /var/log/*.log --start "2024-01-15 06:00" --end "2024-01-15 18:00" --output timeline.json
```

### Expected Output
```json
{
  "incident_id": "INC-2024-001",
  "timeline": [
    {
      "timestamp": "2024-01-15T06:05:00Z",
      "source": "auth.log",
      "event": "SSH brute force detected",
      "severity": "HIGH",
      "ip": "185.220.101.x"
    }
  ]
}
```

---

## DevSecOps: Pipeline Scanning

### Scenario
Scan a repository before committing to production.

### Using the Skill in OpenClaw
```
"Scan this repository for secrets"
"Check dependencies for CVEs"
```

### Using the Script Directly
```bash
cd skills/22-devsecops/scripts

# Full scan
python3 devsecops_scanner.py --repo /path/to/repo --output report.json

# Quick scan (secrets + deps only)
python3 devsecops_scanner.py --repo /path/to/repo --scope quick --output report.json

# CI/CD mode (fails on critical)
python3 devsecops_scanner.py --repo /path/to/repo --fail-on-critical --output report.json
```

### Expected Output
```json
{
  "scan_time": "2024-01-15T10:30:00Z",
  "repository": "/path/to/repo",
  "findings": {
    "secrets": [
      {
        "severity": "CRITICAL",
        "file": "config.py",
        "line": 42,
        "type": "AWS Access Key ID",
        "sample": "AKIAIOSFODNN7EXAMPLE"
      }
    ],
    "dependencies": [
      {
        "severity": "HIGH",
        "package": "requests",
        "version": "2.25.0",
        "cve": "CVE-2023-1234"
      }
    ]
  }
}
```

---

## Tips

### Running Skills Without OpenClaw
All scripts are standalone and can be run directly:
```bash
python3 skills/<skill-name>/scripts/<script>.py --help
```

### Getting Help
Each script supports `--help`:
```bash
python3 skills/23-cryptocurrency-security/scripts/crypto_validator.py --help
```

### Output Formats
Most scripts support `--output file.json` for machine-readable output.
