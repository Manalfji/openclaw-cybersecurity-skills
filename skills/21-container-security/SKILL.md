---
name: "container-security"
description: "Scan Kubernetes clusters for security misconfigurations and compliance violations."
---

# Kubernetes Container Security Scanner

## When to Use
A Kubernetes cluster or workload needs security hardening review — check for root users, privileged containers, missing resource limits, exposed secrets, and compliance gaps.

## Workflow
1. Connect to the cluster via kubeconfig.
2. Discover pods in the target namespace(s).
3. Run 20 security scanners across 6 categories (pod security, resources, images, secrets, network, RBAC).
4. Score findings and map to compliance frameworks (CIS, PCI-DSS, NIST, GDPR, SOC2).
5. Output a terminal report or JSON for CI/CD gates.

## Scripts
- `scripts/k8s_security_scanner.py` — Unified CLI scanner with all checks built-in.

## Output
- Terminal summary with severity breakdown (CRITICAL / HIGH / MEDIUM / LOW)
- Security score (0-100) with letter grade
- Compliance status per framework
- JSON export for CI/CD integration
- Optional: per-pod score tables

## Prerequisites
- Python 3.9+
- `pip install -r requirements.txt` (kubernetes, click, colorama)
- kubectl configured with valid `~/.kube/config`

## Compliance Mappings
Each finding references one or more frameworks:
- CIS Kubernetes Benchmark
- PCI-DSS
- NIST 800-190
- GDPR Article 32
- SOC 2 CC6.1