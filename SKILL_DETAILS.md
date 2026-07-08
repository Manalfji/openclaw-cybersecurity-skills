# Skill Details — What Each Skill Does

Complete breakdown of every skill, its purpose, when to use it, and what it produces.

---

## 01 — Recon & OSINT
**Purpose:** Gather intelligence on targets without (or with minimal) direct interaction.
**When to use:**
- Starting a security assessment — need to map the attack surface
- Investigating a domain or organization
- Finding subdomains, tech stacks, or exposed services

**What it does:**
- Enumerates subdomains via DNS brute force and certificate transparency logs
- Fingerprints web technologies (server, framework, CMS)
- Performs DNS reconnaissance (A, AAAA, MX, TXT, NS records)
- Harvests WHOIS data and registration info

**Scripts:**
- `subdomain_enum.py` — Find subdomains using wordlists and cert logs
- `dns_recon.py` — DNS record enumeration and zone transfer testing
- `tech_fingerprint.py` — Identify web server technologies

**Output:** JSON reports with domain lists, DNS records, and tech stacks.

---

## 02 — Vulnerability Scanner
**Purpose:** Identify security weaknesses in applications and infrastructure.
**When to use:**
- Auditing a codebase before deployment
- Checking dependencies for known CVEs
- Reviewing configuration files for security misconfigurations

**What it does:**
- Scans project dependencies for known vulnerabilities (CVE database)
- Audits configuration files for unsafe settings
- Calculates CVSS scores for findings
- Generates structured vulnerability reports

**Scripts:**
- `dependency_auditor.py` — Check requirements.txt, package.json, etc. for CVEs
- `config_auditor.py` — Review configs for security misconfigurations
- `cvss_calculator.py` — Calculate and classify CVSS v3.1 scores

**Output:** JSON vulnerability reports with severity ratings and remediation steps.

---

## 03 — Exploit Development
**Purpose:** Generate proof-of-concept payloads for authorized penetration testing.
**When to use:**
- Building a PoC for a vulnerability you've discovered
- Testing security controls with authorized payloads
- Teaching or demonstrating exploit techniques

**What it does:**
- Generates reverse shell, bind shell, and web shell payloads
- Creates XSS and SQL injection test payloads
- Outputs payloads in multiple languages (Python, Bash, PHP, PowerShell, etc.)
- Includes listener commands and usage instructions

**⚠️ Authorization Required:** This skill generates offensive payloads. Only use with written authorization.

**Scripts:**
- `payload_generator.py` — Generate reverse shells, web shells, XSS, SQLi payloads

**Output:** JSON files with payloads, listener commands, and metadata.

---

## 04 — Reverse Engineering
**Purpose:** Analyze compiled binaries, firmware, and unknown executables.
**When to use:**
- Investigating malware samples
- Understanding how a proprietary binary works
- Analyzing firmware images for IoT/embedded devices

**What it does:**
- Performs static analysis on binaries (strings, imports, sections)
- Identifies packers and obfuscation techniques
- Extracts metadata, certificates, and version info
- Generates function call graphs and cross-references

**Scripts:**
- `binary_analyzer.py` — Static analysis of ELF/PE/Mach-O binaries

**Output:** Analysis reports with file structure, suspicious indicators, and extracted strings.

---

## 05 — Malware Analysis
**Purpose:** Examine suspicious files to determine if they're malicious and how they behave.
**When to use:**
- A file was flagged by antivirus — need to verify
- Investigating a potential breach
- Building detection rules for future threats

**What it does:**
- Static analysis: file hashes, entropy, imports, strings
- Generates YARA rules for detection
- Extracts IOCs (IPs, domains, file paths, registry keys)
- Identifies packing, encryption, and obfuscation

**Scripts:**
- `static_analyzer.py` — Hash, entropy, import, and string analysis
- `yara_generator.py` — Create YARA rules from sample characteristics

**Output:** IOC lists, YARA rules, and behavioral indicators.

---

## 06 — Threat Hunting
**Purpose:** Proactively search for signs of compromise in your environment.
**When to use:**
- You suspect a breach but have no alerts
- Building hunt hypotheses based on threat intelligence
- Mapping observed behaviors to MITRE ATT&CK framework

**What it does:**
- Extracts IOCs from threat intelligence feeds
- Maps TTPs to MITRE ATT&CK techniques
- Generates Sigma rules for SIEM detection
- Creates hunt hypotheses with success criteria

**Scripts:**
- `ioc_extractor.py` — Parse threat intel and extract IOCs
- `mitre_mapper.py` — Map behaviors to ATT&CK techniques

**Output:** IOC lists, Sigma rules, hunt hypotheses, and ATT&CK mappings.

---

## 07 — Incident Response
**Purpose:** Respond to and investigate security incidents systematically.
**When to use:**
- Active security incident — need to contain and investigate
- Building IR playbooks and procedures
- Collecting evidence for legal or compliance purposes

**What it does:**
- Follows PICERL framework (Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned)
- Collects and preserves evidence (logs, memory, disk images)
- Builds incident timelines from multiple data sources
- Generates structured incident reports

**Scripts:**
- `evidence_collector.py` — Collect and hash evidence files
- `timeline_builder.py` — Build incident timelines from logs

**Output:** Evidence packages, timelines, and incident reports.

---

## 08 — Network Security
**Purpose:** Analyze network traffic and secure network infrastructure.
**When to use:**
- Investigating suspicious network activity
- Creating IDS/IPS rules for your SIEM
- Auditing firewall rules for misconfigurations

**What it does:**
- Parses PCAP files for protocol analysis, beaconing detection, and data exfiltration
- Generates Suricata/Snort detection rules
- Audits firewall configurations (iptables, nftables, cloud SGs)
- Detects C2 beaconing, DNS tunneling, and lateral movement

**Scripts:**
- `pcap_analyzer.py` — Automated PCAP analysis for threats

**Output:** JSON analysis reports, IDS rules, and firewall audit findings.

---

## 09 — Web Security
**Purpose:** Test and secure web applications and APIs.
**When to use:**
- Before deploying a web application
- After a code update that touches authentication or input handling
- Auditing third-party APIs your organization consumes

**What it does:**
- Tests for OWASP Top 10 vulnerabilities
- Analyzes API endpoints for authentication and authorization flaws
- Reviews JWT tokens for security issues
- Checks security headers and CORS configurations

**Scripts:**
- `owasp_scanner.py` — Scan for common web vulnerabilities
- `api_security_tester.py` — Test API endpoints for security flaws

**Output:** Vulnerability reports with severity, evidence, and remediation.

---

## 10 — Cloud Security
**Purpose:** Audit and secure cloud infrastructure (AWS, Azure, GCP).
**When to use:**
- Migrating workloads to the cloud
- Periodic security audits of cloud accounts
- Reviewing Infrastructure-as-Code before deployment

**What it does:**
- Audits AWS/Azure/GCP configurations for security misconfigurations
- Scans Terraform/CloudFormation templates for insecure defaults
- Reviews Kubernetes manifests for security issues
- Checks IAM policies, storage buckets, and network ACLs

**Scripts:**
- `cloud_auditor.py` — Audit cloud account configurations
- `iac_scanner.py` — Scan Terraform/CloudFormation for security issues

**Output:** Audit reports with misconfigurations and remediation steps.

---

## 11 — CSOC Automation
**Purpose:** Automate Security Operations Center workflows.
**When to use:**
- Triage alerts faster with consistent procedures
- Generate shift handover reports
- Track SOC metrics and KPIs

**What it does:**
- Triages alerts based on severity, category, and historical patterns
- Generates shift handover reports (Markdown or JSON)
- Tracks escalation workflows and open incidents
- Computes MTTR and other SOC metrics

**Scripts:**
- `alert_triager.py` — Automated alert triage with risk scoring
- `report_generator.py` — Generate SOC shift reports

**Output:** Triage decisions, shift reports, and metrics dashboards.

---

## 12 — Log Analysis & SIEM
**Purpose:** Parse, analyze, and query security logs.
**When to use:**
- Investigating a suspicious event in your logs
- Building detection rules for your SIEM
- Identifying anomalies in user or system behavior

**What it does:**
- Parses common log formats (syslog, JSON, CSV, Windows Event Logs)
- Detects anomalies using statistical and ML-based methods
- Generates SIEM queries (Splunk SPL, KQL, EQL)
- Creates Sigma rules for cross-platform detection

**Scripts:**
- `log_parser.py` — Parse and normalize various log formats
- `anomaly_detector.py` — Statistical anomaly detection on log data

**Output:** Parsed logs, anomaly alerts, and SIEM queries.

---

## 13 — Cryptographic Analysis
**Purpose:** Audit cryptographic implementations and configurations.
**When to use:**
- Reviewing TLS/SSL configurations on web servers
- Auditing applications that handle sensitive data
- Preparing for quantum-resistant cryptography migration

**What it does:**
- Audits TLS configurations (cipher suites, protocols, certificates)
- Identifies weak or deprecated cryptographic primitives
- Analyzes hash algorithms for collisions or weaknesses
- Provides guidance on post-quantum cryptography (PQC)

**Scripts:**
- `tls_auditor.py` — TLS/SSL configuration scanner

**Output:** TLS audit reports with cipher grades and recommendations.

---

## 14 — Red Team Operations
**Purpose:** Plan and execute authorized adversary simulations.
**When to use:**
- Preparing for a red team engagement
- Designing attack scenarios to test defenses
- Planning C2 infrastructure and OPSEC measures

**What it does:**
- Plans engagement scope, rules of engagement, and objectives
- Designs attack paths based on threat actor TTPs
- Documents OPSEC considerations and tradecraft
- Generates engagement reports with findings and recommendations

**⚠️ Authorization Required:** Red team operations require explicit written authorization.

**Scripts:**
- `engagement_planner.py` — Plan red team engagements with ATT&CK mapping

**Output:** Engagement plans, attack paths, and reports.

---

## 15 — Blue Team Defense
**Purpose:** Harden systems and build defensive capabilities.
**When to use:**
- Hardening a new server before deployment
- Building detection rules for your security stack
- Establishing security baselines for compliance

**What it does:**
- Audits Linux/Windows systems against security baselines (CIS, STIG)
- Checks for missing patches and insecure configurations
- Reviews file permissions, services, and network settings
- Generates hardening reports with prioritized remediation

**Scripts:**
- `hardening_checker.py` — System hardening audit against baselines

**Output:** Hardening reports with pass/fail status and remediation steps.

---

## 16 — AI & LLM Security
**Purpose:** Secure AI systems and applications using LLMs.
**When to use:**
- Deploying an AI-powered application
- Auditing an LLM integration for security flaws
- Testing for prompt injection and model manipulation

**What it does:**
- Tests for prompt injection vulnerabilities
- Reviews LLM application architecture for security flaws
- Audits model supply chain (training data, weights, dependencies)
- Maps findings to OWASP LLM Top 10

**Scripts:**
- `prompt_injection_tester.py` — Automated prompt injection testing
- `model_supply_chain.py` — Audit ML model dependencies and provenance

**Output:** Security assessment reports with LLM-specific vulnerabilities.

---

## 17 — Mobile Security
**Purpose:** Test and secure mobile applications (Android/iOS).
**When to use:**
- Releasing a mobile app that handles sensitive data
- Auditing third-party mobile SDKs
- Investigating mobile malware samples

**What it does:**
- Static analysis of APK/IPA files
- Checks for insecure storage, hardcoded credentials, and weak crypto
- Reviews Android manifests and iOS entitlements
- Tests for common mobile vulnerabilities (OWASP MASVS)

**Scripts:**
- `apk_analyzer.py` — Static analysis of Android APK files

**Output:** Security findings with MASVS mappings and remediation.

---

## 18 — OT / ICS / SCADA Security
**Purpose:** Secure operational technology and industrial control systems.
**When to use:**
- Auditing industrial networks (manufacturing, energy, utilities)
- Analyzing ICS protocol traffic for anomalies
- Preparing for IEC 62443 compliance assessments

**What it does:**
- Analyzes ICS protocols (Modbus, DNP3, S7, BACnet)
- Maps network topology to Purdue model levels
- Identifies insecure protocol configurations
- Checks for unauthorized devices on OT networks

**Scripts:**
- `ics_protocol_analyzer.py` — Parse and analyze ICS protocol traffic

**Output:** Protocol analysis reports and security findings.

---

## 19 — GRC Compliance
**Purpose:** Map controls, manage risk, and prepare for audits.
**When to use:**
- Preparing for a compliance audit (SOC 2, ISO 27001, PCI-DSS)
- Building a risk register for your organization
- Mapping security controls to frameworks

**What it does:**
- Maps security controls to frameworks (NIST CSF, ISO 27001, SOC 2, PCI-DSS)
- Maintains a risk register with risk scores and treatment plans
- Generates audit readiness reports
- Tracks control evidence and gap analysis

**Scripts:**
- `control_mapper.py` — Map controls across compliance frameworks
- `risk_register.py` — Maintain and report on risk register

**Output:** Control mappings, risk registers, and audit readiness reports.

---

## 20 — Phishing Analysis
**Purpose:** Analyze suspicious emails for phishing indicators.
**When to use:**
- Investigating a suspicious email received by a user
- SOC analyst needs to determine if an email is malicious
- Building a phishing triage workflow

**What it does:**
- Parses `.eml` files for headers, body, and attachments
- Checks SPF/DKIM/DMARC authentication results
- Extracts URLs and checks them for malicious indicators
- Enriches URLs via VirusTotal and IPs via AbuseIPDB (optional API keys)
- Calculates risk score (LOW → CRITICAL)
- Generates terminal report and optional HTML report

**Scripts:**
- `phishing_analyzer.py` — Parse and analyze phishing emails

**Output:** Terminal report + HTML report with risk scores and indicators.

---

## 21 — Container Security
**Purpose:** Audit Kubernetes clusters for security misconfigurations.
**When to use:**
- Auditing a Kubernetes deployment before production
- Checking container security posture
- Compliance validation for containerized workloads

**What it does:**
- 20 security checks across 6 categories:
  - Pod Security: root, privileged, privilege escalation, read-only FS, capabilities
  - Resource Management: CPU/memory limits, resource quotas
  - RBAC: overprivileged service accounts, default service accounts
  - Secrets: hardcoded secrets in env vars, secrets mounted as volumes
  - Network: network policies, exposed services, ingress security
  - General: container registry security, image pull policies
- Compliance mappings: CIS, PCI-DSS, NIST, GDPR, SOC2
- Generates JSON audit report

**Scripts:**
- `k8s_security_scanner.py` — Kubernetes security configuration scanner

**Output:** JSON audit report with pass/fail status per check.

---

## 22 — DevSecOps
**Purpose:** Scan CI/CD pipelines and repositories for security issues.
**When to use:**
- Pre-commit security checks
- CI/CD pipeline integration
- Auditing repositories for secrets and vulnerabilities

**What it does:**
- Secret detection: API keys, passwords, database URLs, JWTs, bearer tokens via regex
- Dependency scanning: Parses requirements.txt, package.json, go.mod and queries OSV API for known CVEs
- SAST basics: 9 rules covering eval/exec, SQL injection, insecure deserialization, SSRF, weak crypto (MD5/SHA1), insecure randomness, debug mode, dangerous subprocess calls
- Per-category reporting with severity breakdown
- JSON export + CI/CD exit codes (`--fail-on-critical`)

**Scripts:**
- `devsecops_scanner.py` — Pipeline security scanner

**Output:** JSON report with findings categorized by severity and type.

---

## Quick Reference

| Skill | Use When You Need To... |
|:---|:---|
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
| Phishing Analysis | Analyze suspicious emails, check SPF/DKIM/DMARC |
| Container Security | Audit Kubernetes for security misconfigurations |
| DevSecOps | Scan pipelines for secrets, CVEs, and SAST issues |
