#!/usr/bin/env python3
"""
Kubernetes Security Scanner
Scans K8s clusters for security misconfigurations.
Standalone, OpenClaw-adapted from https://github.com/adityaupasani2/k8s-security-scanner
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime
from typing import Any, Dict, List


def print_banner():
    banner = """
╔══════════════════════════════════════════════════════════╗
║        KUBERNETES SECURITY SCANNER v1.0                  ║
║     Detect security misconfigurations in K8s clusters    ║
╚══════════════════════════════════════════════════════════╝
"""
    print(banner)


# ─── Base Scanner ─────────────────────────────────────────────────

class BaseScanner:
    def __init__(self):
        self.findings: List[Dict[str, Any]] = []

    def create_finding(self, severity, pod_name, namespace, container_name, issue, description, remediation, compliance=None):
        return {
            "scanner": self.__class__.__name__,
            "severity": severity,
            "pod_name": pod_name,
            "namespace": namespace,
            "container_name": container_name,
            "issue": issue,
            "description": description,
            "remediation": remediation,
            "compliance": compliance or [],
            "category": self._get_category(),
        }

    def _get_category(self):
        return "security"


# ─── Individual Scanners ──────────────────────────────────────────

class RootUserScanner(BaseScanner):
    def _get_category(self): return "pod_security"
    def scan(self, pod) -> List[Dict]:
        findings = []
        for c in pod.spec.containers:
            sc = c.security_context
            uid = getattr(sc, "run_as_user", None) if sc else None
            if uid == 0:
                findings.append(self.create_finding(
                    "CRITICAL", pod.metadata.name, pod.metadata.namespace, c.name,
                    "Container running as root user",
                    f"Container '{c.name}' runs as UID 0 (root). Root in containers allows full host compromise if escaped.",
                    "Set runAsUser to a non-zero UID and runAsGroup to a non-zero GID in the container securityContext.",
                    ["CIS-5.2.1", "NIST-800-190-4.1.1"]
                ))
        return findings


class PrivilegedScanner(BaseScanner):
    def _get_category(self): return "pod_security"
    def scan(self, pod) -> List[Dict]:
        findings = []
        for c in pod.spec.containers:
            sc = c.security_context
            if sc and getattr(sc, "privileged", False):
                findings.append(self.create_finding(
                    "CRITICAL", pod.metadata.name, pod.metadata.namespace, c.name,
                    "Container running in privileged mode",
                    f"Container '{c.name}' is privileged. It has full host device access and can escape to the host.",
                    "Remove 'privileged: true'. Use specific capabilities instead if elevated access is needed.",
                    ["CIS-5.2.1", "NIST-800-190-4.1.3"]
                ))
        return findings


class PrivilegeEscalationScanner(BaseScanner):
    def _get_category(self): return "pod_security"
    def scan(self, pod) -> List[Dict]:
        findings = []
        for c in pod.spec.containers:
            sc = c.security_context
            if sc and getattr(sc, "allow_privilege_escalation", None) is not False:
                findings.append(self.create_finding(
                    "HIGH", pod.metadata.name, pod.metadata.namespace, c.name,
                    "Privilege escalation not blocked",
                    f"Container '{c.name}' does not set allowPrivilegeEscalation: false. Processes can gain additional privileges.",
                    "Set 'allowPrivilegeEscalation: false' in the container securityContext.",
                    ["CIS-5.2.1", "NIST-800-190-4.1.5"]
                ))
        return findings


class ReadOnlyFilesystemScanner(BaseScanner):
    def _get_category(self): return "pod_security"
    def scan(self, pod) -> List[Dict]:
        findings = []
        for c in pod.spec.containers:
            sc = c.security_context
            if not (sc and getattr(sc, "read_only_root_filesystem", False)):
                findings.append(self.create_finding(
                    "MEDIUM", pod.metadata.name, pod.metadata.namespace, c.name,
                    "Writable root filesystem",
                    f"Container '{c.name}' has a writable root filesystem. Attackers can modify binaries and config files.",
                    "Set 'readOnlyRootFilesystem: true' in the container securityContext. Use emptyDir volumes for writable paths.",
                    ["CIS-5.2.1", "NIST-800-190-4.1.7"]
                ))
        return findings


class MissingSecurityContextScanner(BaseScanner):
    def _get_category(self): return "pod_security"
    def scan(self, pod) -> List[Dict]:
        findings = []
        for c in pod.spec.containers:
            if not c.security_context:
                findings.append(self.create_finding(
                    "MEDIUM", pod.metadata.name, pod.metadata.namespace, c.name,
                    "Missing security context",
                    f"Container '{c.name}' has no securityContext defined. No security controls are enforced.",
                    "Add a securityContext with runAsUser, runAsGroup, allowPrivilegeEscalation, and readOnlyRootFilesystem.",
                    ["CIS-5.2.1", "NIST-800-190-4.1.1"]
                ))
        return findings


class CapabilitiesScanner(BaseScanner):
    DANGEROUS = {"NET_ADMIN", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "SYS_RAWIO", "SYS_BOOT", "SYS_TIME", "KILL", "CHOWN"}
    def _get_category(self): return "pod_security"
    def scan(self, pod) -> List[Dict]:
        findings = []
        for c in pod.spec.containers:
            sc = c.security_context
            caps = getattr(sc, "capabilities", None) if sc else None
            if caps and caps.add:
                added = set(caps.add)
                dangerous = added & self.DANGEROUS
                if dangerous:
                    findings.append(self.create_finding(
                        "HIGH", pod.metadata.name, pod.metadata.namespace, c.name,
                        f"Dangerous capabilities added: {', '.join(dangerous)}",
                        f"Container '{c.name}' adds dangerous Linux capabilities that expand attack surface.",
                        "Drop ALL capabilities and add only the minimum required set explicitly.",
                        ["CIS-5.2.8", "NIST-800-190-4.1.4"]
                    ))
        return findings


class SeccompScanner(BaseScanner):
    def _get_category(self): return "pod_security"
    def scan(self, pod) -> List[Dict]:
        findings = []
        sc = pod.spec.security_context
        seccomp = getattr(sc, "seccomp_profile", None) if sc else None
        if not seccomp or getattr(seccomp, "type", "") != "RuntimeDefault":
            findings.append(self.create_finding(
                "LOW", pod.metadata.name, pod.metadata.namespace, "-",
                "Missing seccomp profile",
                "Pod does not use a seccomp profile. Syscalls are unrestricted.",
                "Set 'seccompProfile: { type: RuntimeDefault }' in the pod securityContext.",
                ["CIS-5.7.2", "NIST-800-190-4.1.8"]
            ))
        return findings


class AppArmorSELinuxScanner(BaseScanner):
    def _get_category(self): return "pod_security"
    def scan(self, pod) -> List[Dict]:
        findings = []
        for c in pod.spec.containers:
            sc = c.security_context
            if not (sc and getattr(sc, "se_linux_options", None)):
                findings.append(self.create_finding(
                    "LOW", pod.metadata.name, pod.metadata.namespace, c.name,
                    "Missing AppArmor/SELinux profile",
                    f"Container '{c.name}' has no SELinux/AppArmor profile applied.",
                    "Apply an AppArmor or SELinux profile to restrict file and process access.",
                    ["CIS-5.7.1", "NIST-800-190-4.1.9"]
                ))
        return findings


class CPULimitsScanner(BaseScanner):
    def _get_category(self): return "resource_management"
    def scan(self, pod) -> List[Dict]:
        findings = []
        for c in pod.spec.containers:
            limits = getattr(c.resources, "limits", None) if c.resources else None
            if not (limits and limits.get("cpu")):
                findings.append(self.create_finding(
                    "HIGH", pod.metadata.name, pod.metadata.namespace, c.name,
                    "Missing CPU limit",
                    f"Container '{c.name}' has no CPU limit. It can consume all available CPU.",
                    "Add 'resources.limits.cpu' to the container spec.",
                    ["CIS-5.2.3", "NIST-800-190-4.2.1"]
                ))
        return findings


class MemoryLimitsScanner(BaseScanner):
    def _get_category(self): return "resource_management"
    def scan(self, pod) -> List[Dict]:
        findings = []
        for c in pod.spec.containers:
            limits = getattr(c.resources, "limits", None) if c.resources else None
            if not (limits and limits.get("memory")):
                findings.append(self.create_finding(
                    "HIGH", pod.metadata.name, pod.metadata.namespace, c.name,
                    "Missing memory limit",
                    f"Container '{c.name}' has no memory limit. It can consume all available memory and trigger OOM.",
                    "Add 'resources.limits.memory' to the container spec.",
                    ["CIS-5.2.3", "NIST-800-190-4.2.1"]
                ))
        return findings


class ResourceRequestsScanner(BaseScanner):
    def _get_category(self): return "resource_management"
    def scan(self, pod) -> List[Dict]:
        findings = []
        for c in pod.spec.containers:
            reqs = getattr(c.resources, "requests", None) if c.resources else None
            if not (reqs and reqs.get("cpu") and reqs.get("memory")):
                findings.append(self.create_finding(
                    "MEDIUM", pod.metadata.name, pod.metadata.namespace, c.name,
                    "Missing resource requests",
                    f"Container '{c.name}' lacks CPU or memory requests. Scheduler cannot place pods optimally.",
                    "Add 'resources.requests.cpu' and 'resources.requests.memory' to the container spec.",
                    ["CIS-5.2.3", "NIST-800-190-4.2.1"]
                ))
        return findings


class LatestTagScanner(BaseScanner):
    def _get_category(self): return "image_security"
    def scan(self, pod) -> List[Dict]:
        findings = []
        for c in pod.spec.containers:
            image = c.image or ""
            if image.endswith(":latest") or ":" not in image.split("/")[-1]:
                findings.append(self.create_finding(
                    "MEDIUM", pod.metadata.name, pod.metadata.namespace, c.name,
                    "Image uses :latest tag",
                    f"Container '{c.name}' uses image '{image}'. The :latest tag is mutable and unpredictable.",
                    "Pin images to a specific digest or semantic version tag (e.g., myimage:1.2.3).",
                    ["CIS-5.5.1", "NIST-800-190-4.3.1"]
                ))
        return findings


class UntaggedImageScanner(BaseScanner):
    def _get_category(self): return "image_security"
    def scan(self, pod) -> List[Dict]:
        findings = []
        for c in pod.spec.containers:
            image = c.image or ""
            if ":" not in image.split("/")[-1]:
                findings.append(self.create_finding(
                    "MEDIUM", pod.metadata.name, pod.metadata.namespace, c.name,
                    "Untagged image",
                    f"Container '{c.name}' uses image '{image}' with no tag. Behavior is unpredictable.",
                    "Add an explicit version tag to the image reference.",
                    ["CIS-5.5.1", "NIST-800-190-4.3.1"]
                ))
        return findings


class ImageRegistryScanner(BaseScanner):
    TRUSTED = {"docker.io", "gcr.io", "registry.k8s.io", "quay.io", "mcr.microsoft.com", "ghcr.io", "public.ecr.aws"}
    def _get_category(self): return "image_security"
    def scan(self, pod) -> List[Dict]:
        findings = []
        for c in pod.spec.containers:
            image = c.image or ""
            parts = image.split("/")
            registry = parts[0] if "." in parts[0] or ":" in parts[0] else "docker.io"
            if registry not in self.TRUSTED:
                findings.append(self.create_finding(
                    "MEDIUM", pod.metadata.name, pod.metadata.namespace, c.name,
                    "Untrusted image registry",
                    f"Container '{c.name}' uses image from '{registry}'. Consider using a verified registry.",
                    "Pull images only from approved, trusted registries. Scan images before deployment.",
                    ["CIS-5.5.1", "NIST-800-190-4.3.2"]
                ))
        return findings


class SecretsInEnvScanner(BaseScanner):
    SECRET_PATTERNS = {"PASSWORD", "PASSWD", "PWD", "SECRET", "API_KEY", "APIKEY", "TOKEN", "AUTH", "CREDENTIAL", "PRIVATE_KEY", "PRIV_KEY", "ACCESS_KEY", "SECRET_KEY", "DATABASE_URL", "DB_PASSWORD", "ENCRYPTION_KEY", "CIPHER_KEY"}
    SAFE_PATTERNS = {"PATH", "HOME", "SHELL", "LANG", "TZ", "TERM", "USER", "HOSTNAME", "PORT", "HOST", "REPLICAS"}
    def _get_category(self): return "secrets_management"
    def _mask(self, value: str) -> str:
        return value[:2] + "..." + value[-2:] if len(value) > 4 else "****"
    def scan(self, pod) -> List[Dict]:
        findings = []
        for c in pod.spec.containers:
            if not c.env:
                continue
            for ev in c.env:
                name_upper = ev.name.upper()
                if any(s in name_upper for s in self.SAFE_PATTERNS):
                    continue
                if any(s in name_upper for s in self.SECRET_PATTERNS):
                    if ev.value and not ev.value_from:
                        findings.append(self.create_finding(
                            "CRITICAL", pod.metadata.name, pod.metadata.namespace, c.name,
                            f"Hardcoded secret in environment variable: {ev.name}",
                            f"Container '{c.name}' has hardcoded secret in env var '{ev.name}'. Value: {self._mask(ev.value)}",
                            "Use Kubernetes Secrets (valueFrom.secretKeyRef) or an external secret manager.",
                            ["CIS-5.4.3", "PCI-DSS-3.4", "GDPR-Article-32", "SOC2-CC6.1"]
                        ))
        return findings


class HostNetworkScanner(BaseScanner):
    def _get_category(self): return "network_security"
    def scan(self, pod) -> List[Dict]:
        findings = []
        if getattr(pod.spec, "host_network", False):
            findings.append(self.create_finding(
                "HIGH", pod.metadata.name, pod.metadata.namespace, "-",
                "Pod using host network",
                "Pod shares the host's network namespace. It can bind to host ports and sniff traffic.",
                "Set 'hostNetwork: false' in the pod spec. Use services and ingress for network access.",
                ["CIS-5.2.4", "NIST-800-190-4.4.1"]
            ))
        return findings


class HostPathScanner(BaseScanner):
    def _get_category(self): return "network_security"
    def scan(self, pod) -> List[Dict]:
        findings = []
        for vol in getattr(pod.spec, "volumes", []) or []:
            if getattr(vol, "host_path", None):
                findings.append(self.create_finding(
                    "HIGH", pod.metadata.name, pod.metadata.namespace, "-",
                    "Host path volume mounted",
                    f"Pod mounts host path '{vol.host_path.path}'. It can read/write host filesystem.",
                    "Remove hostPath volumes. Use PVCs or emptyDir for storage needs.",
                    ["CIS-5.2.4", "NIST-800-190-4.4.2"]
                ))
        return findings


class HostNamespacesScanner(BaseScanner):
    def _get_category(self): return "network_security"
    def scan(self, pod) -> List[Dict]:
        findings = []
        if getattr(pod.spec, "host_pid", False):
            findings.append(self.create_finding(
                "MEDIUM", pod.metadata.name, pod.metadata.namespace, "-",
                "Pod using host PID namespace",
                "Pod shares the host PID namespace. It can see and interact with host processes.",
                "Set 'hostPID: false' in the pod spec.",
                ["CIS-5.2.4", "NIST-800-190-4.4.1"]
            ))
        if getattr(pod.spec, "host_ipc", False):
            findings.append(self.create_finding(
                "MEDIUM", pod.metadata.name, pod.metadata.namespace, "-",
                "Pod using host IPC namespace",
                "Pod shares the host IPC namespace. It can access shared memory of host processes.",
                "Set 'hostIPC: false' in the pod spec.",
                ["CIS-5.2.4", "NIST-800-190-4.4.1"]
            ))
        return findings


class DefaultServiceAccountScanner(BaseScanner):
    def _get_category(self): return "rbac"
    def scan(self, pod) -> List[Dict]:
        findings = []
        sa = getattr(pod.spec, "service_account_name", "") or ""
        if sa == "default" or not sa:
            findings.append(self.create_finding(
                "MEDIUM", pod.metadata.name, pod.metadata.namespace, "-",
                "Using default service account",
                "Pod uses the 'default' service account. It may have unnecessary permissions.",
                "Create a dedicated service account with minimal RBAC permissions and reference it in the pod spec.",
                ["CIS-5.1.5", "NIST-800-190-4.5.1"]
            ))
        return findings


class AutomountTokenScanner(BaseScanner):
    def _get_category(self): return "rbac"
    def scan(self, pod) -> List[Dict]:
        findings = []
        if getattr(pod.spec, "automount_service_account_token", True) is not False:
            findings.append(self.create_finding(
                "MEDIUM", pod.metadata.name, pod.metadata.namespace, "-",
                "Service account token automounted",
                "Pod automounts the service account token. If compromised, it can be used to access the API server.",
                "Set 'automountServiceAccountToken: false' in the pod spec unless the pod needs API access.",
                ["CIS-5.1.6", "NIST-800-190-4.5.2"]
            ))
        return findings


# ─── Scanner Manager ──────────────────────────────────────────────

SCANNERS = [
    RootUserScanner(), PrivilegedScanner(), PrivilegeEscalationScanner(),
    ReadOnlyFilesystemScanner(), MissingSecurityContextScanner(),
    CapabilitiesScanner(), SeccompScanner(), AppArmorSELinuxScanner(),
    CPULimitsScanner(), MemoryLimitsScanner(), ResourceRequestsScanner(),
    LatestTagScanner(), UntaggedImageScanner(), ImageRegistryScanner(),
    SecretsInEnvScanner(), HostNetworkScanner(), HostPathScanner(),
    HostNamespacesScanner(), DefaultServiceAccountScanner(), AutomountTokenScanner(),
]


class ScannerManager:
    def __init__(self):
        self.scanners = SCANNERS

    def scan_pod(self, pod) -> List[Dict]:
        findings = []
        for scanner in self.scanners:
            findings.extend(scanner.scan(pod))
        return findings

    def scan_pods(self, pods) -> Dict[str, Any]:
        all_findings = []
        for pod in pods:
            all_findings.extend(self.scan_pod(pod))
        by_sev = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
        for f in all_findings:
            sev = f.get("severity", "LOW")
            by_sev.setdefault(sev, []).append(f)
        return {"total_findings": len(all_findings), "findings_by_severity": by_sev, "all_findings": all_findings}

    def get_scanner_count(self) -> int:
        return len(self.scanners)


# ─── Scoring ──────────────────────────────────────────────────────

class SecurityScorer:
    SEVERITY_WEIGHTS = {"CRITICAL": 15, "HIGH": 8, "MEDIUM": 3, "LOW": 1}
    ISSUE_MULTIPLIERS = {"Hardcoded secret": 1.5, "Container running as root": 1.3, "Container running in privileged mode": 1.3, "Pod using host network": 1.2}

    def calculate_pod_score(self, findings: List[Dict]) -> Dict:
        if not findings:
            return {"score": 100, "grade": "A+", "total_deductions": 0, "findings_count": 0, "risk_level": "MINIMAL", "severity_breakdown": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}}
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        deductions = 0.0
        for f in findings:
            sev = f.get("severity", "LOW")
            issue = f.get("issue", "")
            d = self.SEVERITY_WEIGHTS.get(sev, 1)
            mult = 1.0
            for itype, m in self.ISSUE_MULTIPLIERS.items():
                if itype.lower() in issue.lower():
                    mult = m
                    break
            deductions += d * mult
            counts[sev] = counts.get(sev, 0) + 1
        score = max(0, 100 - int(deductions))
        grade = self._grade(score)
        return {"score": score, "grade": grade, "total_deductions": int(deductions), "findings_count": len(findings), "risk_level": self._risk(counts), "severity_breakdown": counts}

    def _grade(self, score):
        if score >= 95: return "A+"
        if score >= 90: return "A"
        if score >= 85: return "A-"
        if score >= 80: return "B+"
        if score >= 75: return "B"
        if score >= 70: return "B-"
        if score >= 65: return "C+"
        if score >= 60: return "C"
        if score >= 55: return "C-"
        if score >= 50: return "D"
        return "F"

    def _risk(self, counts):
        if counts["CRITICAL"] >= 3: return "CRITICAL"
        if counts["CRITICAL"] >= 1 or counts["HIGH"] >= 5: return "HIGH"
        if counts["HIGH"] >= 2 or counts["MEDIUM"] >= 8: return "MODERATE"
        if counts["MEDIUM"] >= 3 or counts["LOW"] >= 10: return "LOW"
        return "MINIMAL"

    def get_recommendations(self, score, counts):
        recs = []
        if counts["CRITICAL"] > 0:
            recs.append(f"URGENT: Fix {counts['CRITICAL']} CRITICAL issue(s) immediately")
        if counts["HIGH"] > 0:
            recs.append(f"HIGH Priority: Address {counts['HIGH']} HIGH severity issue(s)")
        if score < 50:
            recs.append("Pod is extremely vulnerable - consider blocking deployment")
        elif score < 70:
            recs.append("Pod has significant security issues - remediate before production")
        elif score < 85:
            recs.append("Pod meets minimum security - improvements recommended")
        else:
            recs.append("Pod has good security posture - minor improvements possible")
        return recs


# ─── Compliance ───────────────────────────────────────────────────

class ComplianceMapper:
    FRAMEWORKS = {"CIS": "CIS Kubernetes Benchmark", "PCI-DSS": "PCI Data Security Standard", "NIST": "NIST 800-190 Container Security", "GDPR": "General Data Protection Regulation", "SOC2": "SOC 2 Type II", "HIPAA": "Health Insurance Portability and Accountability Act"}

    def analyze_compliance(self, findings: List[Dict]) -> Dict:
        from collections import defaultdict
        fv = defaultdict(list)
        for f in findings:
            for ref in f.get("compliance", []):
                fw = ref.split("-")[0] if "-" in ref else ref
                fv[fw].append({"reference": ref, "issue": f["issue"], "severity": f["severity"], "pod": f["pod_name"]})
        scores = {}
        for fw, violations in fv.items():
            critical = sum(1 for v in violations if v["severity"] == "CRITICAL")
            high = sum(1 for v in violations if v["severity"] == "HIGH")
            if critical > 0:
                pct = max(0, 60 - critical * 10 - high * 5)
            elif high > 0:
                pct = max(0, 80 - high * 5)
            else:
                pct = 90
            scores[fw] = {"compliance_percentage": pct, "total_violations": len(violations), "critical_violations": critical, "high_violations": high, "status": self._status(pct)}
        return {"framework_scores": scores, "framework_violations": dict(fv), "total_frameworks_affected": len(fv)}

    def _status(self, pct):
        if pct >= 90: return "COMPLIANT"
        if pct >= 70: return "MOSTLY_COMPLIANT"
        if pct >= 50: return "PARTIALLY_COMPLIANT"
        return "NON_COMPLIANT"

    def get_framework_name(self, code):
        return self.FRAMEWORKS.get(code, code)


# ─── Reporters ────────────────────────────────────────────────────

def generate_json_report(all_findings, pod_scores, overall_score, compliance_data, namespace, total_pods):
    return {
        "metadata": {
            "scan_date": datetime.utcnow().isoformat() + "Z",
            "scanner_version": "1.0.0",
            "namespace": namespace,
            "total_pods_scanned": total_pods,
        },
        "summary": overall_score,
        "findings": all_findings,
        "pod_scores": pod_scores,
        "compliance": compliance_data,
    }


def print_results(findings_by_severity, total_pods, overall_score, scorer):
    total = sum(len(v) for v in findings_by_severity.values())
    print("=" * 60)
    print("SCAN RESULTS")
    print("=" * 60)
    print(f"Total pods scanned: {total_pods}")
    print(f"Total issues found: {total}\n")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        items = findings_by_severity[sev]
        if items:
            print(f"{sev} Issues: {len(items)}")
            for it in items[:3]:
                print(f"  - {it['pod_name']}/{it['container_name']}: {it['issue']}")
            if len(items) > 3:
                print(f"  ... and {len(items) - 3} more")
            print()
    score = overall_score["score"]
    grade = overall_score["grade"]
    risk = overall_score["risk_level"]
    print("=" * 60)
    print(f"Security Score: {score}/100 (Grade: {grade})")
    print(f"Risk Level: {risk}")
    print("=" * 60)
    for r in scorer.get_recommendations(score, overall_score["severity_breakdown"]):
        print(f"  - {r}")


# ─── CLI ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Kubernetes Security Scanner")
    parser.add_argument("--namespace", "-n", default="default", help="Namespace to scan")
    parser.add_argument("--all-namespaces", "-A", action="store_true", help="Scan all namespaces")
    parser.add_argument("--output", "-o", choices=["table", "json"], default="table", help="Output format")
    parser.add_argument("--save", "-s", help="Save report to file")
    parser.add_argument("--fail-on-critical", action="store_true", help="Exit 1 if CRITICAL found")
    parser.add_argument("--min-score", type=int, default=0, help="Minimum score threshold")
    args = parser.parse_args()

    if args.output != "json":
        print_banner()

    try:
        from kubernetes import client, config
        config.load_kube_config()
        v1 = client.CoreV1Api()
    except Exception as e:
        print(f"Could not load Kubernetes config: {e}")
        sys.exit(1)

    scanner_mgr = ScannerManager()
    scorer = SecurityScorer()

    if args.output != "json":
        print(f"Loaded {scanner_mgr.get_scanner_count()} security scanners\n")

    namespaces = [ns.metadata.name for ns in v1.list_namespace().items] if args.all_namespaces else [args.namespace]

    all_results = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    total_pods = 0
    pod_scores = []

    for ns in namespaces:
        try:
            pods = v1.list_namespaced_pod(namespace=ns)
            if not pods.items:
                continue
            total_pods += len(pods.items)
            if args.output != "json":
                print(f"Found {len(pods.items)} pods in namespace '{ns}'")
            results = scanner_mgr.scan_pods(pods.items)
            for pod in pods.items:
                pf = scanner_mgr.scan_pod(pod)
                pod_score = scorer.calculate_pod_score(pf)
                pod_scores.append({"name": pod.metadata.name, "namespace": ns, **pod_score})
            for sev in all_results:
                all_results[sev].extend(results["findings_by_severity"][sev])
        except Exception as e:
            if args.output != "json":
                print(f"Error accessing namespace '{ns}': {e}")

    all_findings = all_results["CRITICAL"] + all_results["HIGH"] + all_results["MEDIUM"] + all_results["LOW"]
    overall_score = scorer.calculate_pod_score(all_findings)
    mapper = ComplianceMapper()
    compliance_data = mapper.analyze_compliance(all_findings)

    if args.output == "json":
        report = generate_json_report(all_findings, pod_scores, overall_score, compliance_data, args.namespace if not args.all_namespaces else "all", total_pods)
        out = json.dumps(report, indent=2)
        print(out)
        if args.save:
            with open(args.save, "w") as f:
                f.write(out)
    else:
        print_results(all_results, total_pods, overall_score, scorer)
        if args.save:
            with open(args.save, "w") as f:
                f.write(json.dumps(generate_json_report(all_findings, pod_scores, overall_score, compliance_data, args.namespace if not args.all_namespaces else "all", total_pods), indent=2))
            print(f"\nReport saved to {args.save}")

    if args.fail_on_critical and len(all_results["CRITICAL"]) > 0:
        print("Exiting with code 1 (CRITICAL issues found)")
        sys.exit(1)
    if args.min_score > 0 and overall_score["score"] < args.min_score:
        print(f"Exiting with code 1 (score {overall_score['score']} < {args.min_score})")
        sys.exit(1)


if __name__ == "__main__":
    main()
