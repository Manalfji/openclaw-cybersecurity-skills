---
name: "cloud-security"
description: "Cloud security auditing for AWS/Azure/GCP, container hardening, and IaC scanning."
---

# Cloud Security & Container Hardening

## When to Use
Auditing cloud accounts (AWS, Azure, GCP), reviewing Kubernetes/Docker configurations, and scanning Terraform/CloudFormation templates.

## Workflow
1. Identify cloud provider and authenticate with appropriate CLI.
2. Run `cloud_auditor.py` for account-level misconfigurations.
3. Scan IaC files with `iac_scanner.py`.
4. Review Dockerfile and Kubernetes manifests against hardening checklists.
5. Prioritize findings by blast radius and provide exact fixes.

## Scripts
- `scripts/cloud_auditor.py` — AWS IAM/S3/EC2/CloudTrail, Azure NSG/Security Center, and GCP IAM/storage checks.
- `scripts/iac_scanner.py` — Terraform, Dockerfile, and Kubernetes manifest security scanning.

## Usage
```bash
# AWS audit
python scripts/cloud_auditor.py --provider aws --profile default --region us-east-1 --output aws_findings.json

# GCP audit
python scripts/cloud_auditor.py --provider gcp --project my-project-id --output gcp_findings.json

# IaC scan
python scripts/iac_scanner.py --path ./terraform/ --output iac_findings.json

# Kubernetes manifests
python scripts/iac_scanner.py --path ./k8s/ --type kubernetes --output k8s_findings.json
```

## Output
- JSON findings per provider with severity, resource, description, and remediation.
- IaC scan results with file-level references.
