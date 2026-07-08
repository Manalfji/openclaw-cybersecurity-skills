---
name: "supply-chain-security"
description: "Supply chain security, SBOM generation, dependency confusion detection, and software provenance verification."
---

# Supply Chain & Software Security

## When to Use
- Generating SBOMs for compliance (EO 14028, etc.)
- Detecting dependency confusion attacks
- Verifying software provenance and integrity
- Auditing third-party dependencies for supply chain risks

## Workflow
1. **SBOM Generation** — Create Software Bill of Materials from projects
2. **Dependency Analysis** — Check for known vulnerabilities in dependencies
3. **Confusion Detection** — Identify dependency confusion vulnerabilities
4. **Provenance Verification** — Verify SLSA provenance attestations
5. **Reporting** — Generate compliance reports

## Scripts
- `sbom_generator.py` — Generate SBOMs in SPDX and CycloneDX formats
- `dependency_confusion_detector.py` — Detect dependency confusion vulnerabilities
- `slsa_assessor.py` — Verify SLSA provenance levels

## Output
- SPDX/CycloneDX SBOM files (JSON/XML)
- Dependency confusion vulnerability reports
- SLSA provenance assessment reports

## Prerequisites
```bash
pip install packageurl-python
```

## Important Notes
- SBOMs should be generated for every release
- Dependency confusion is a critical attack vector (see PyPI, npm incidents)
- SLSA provenance helps verify build integrity

## Safety
- This skill performs analysis only — no modifications to code or packages
- Works offline where possible
- Does not upload sensitive data to external services
