---
name: "grc-compliance"
description: "Governance, risk, and compliance — risk assessment, control mapping across NIST CSF 2.0 / ISO 27001:2022 / SOC 2 / CIS Controls v8, gap analysis, and policy generation."
---

# GRC & Compliance

## When to Use
Quantifying risk, mapping controls across frameworks, running gap analyses, preparing audit evidence, and drafting security policies.

## Workflow
1. Assess risk: identify assets, threats, vulnerabilities; score Likelihood × Impact → inherent risk; apply controls → residual risk.
2. Crosswalk controls across NIST CSF 2.0, ISO/IEC 27001:2022, SOC 2, NIST SP 800-53 Rev.5, PCI DSS 4.0, and CIS Controls v8.
3. Run gap analysis: assess each control as Implemented/Partial/Not Implemented/N/A with evidence references.
4. Build audit evidence index and draft control narratives.
5. Generate tailored security policies with mapped controls (Information Security, Access Control, Data Classification, Incident Response, AI Use, etc.).
6. Assess third-party/vendor risk: tier by criticality, review SIG/CAIQ or vendor certs, track findings and re-assessment cadence.

## Scripts
- `scripts/risk_register.py` — Score and rank a risk list (YAML/CSV). Computes inherent/residual severity and optional quantitative ALE. Outputs ranked register + heat-map summary.
- `scripts/control_mapper.py` — Cross-framework control crosswalk. Given a control concept or NIST CSF subcategory, shows corresponding requirements across ISO 27001, SOC 2, NIST 800-53, CIS v8, and PCI DSS.

## Output
- Risk register JSON with severity distribution and 5×5 heat map.
- Gap analysis / Statement of Applicability with coverage percentage.
- Control crosswalk JSON.
- Tailored security policy drafts.

## Prerequisites
```bash
pip install pyyaml
```

## References
- NIST Cybersecurity Framework (CSF) 2.0
- ISO/IEC 27001:2022
- AICPA SOC 2 — Trust Services Criteria
- NIST SP 800-53 Rev. 5
- CIS Controls v8
- PCI DSS 4.0
- FAIR — Factor Analysis of Information Risk
