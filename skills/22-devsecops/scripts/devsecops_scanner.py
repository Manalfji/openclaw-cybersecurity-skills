#!/usr/bin/env python3
"""
DevSecOps Pipeline Security Scanner
Scans repositories for secrets, vulnerable dependencies, and static code issues.
"""

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

import requests


# ─── Secret Detection ─────────────────────────────────────────────

SECRET_PATTERNS = [
    ("AWS Access Key ID", re.compile(r'AKIA[0-9A-Z]{16}'), "CRITICAL"),
    ("AWS Secret Access Key", re.compile(r'["\']?[Aa][Ww][Ss][_\s]?[Ss][Ee][Cc][Rr][Ee][Tt][_\s]?[Aa][Cc][Cc][Ee][Ss][Ss][_\s]?[Kk][Ee][Yy]["\']?\s*[:=]\s*["\']?[a-zA-Z0-9/+=]{40}["\']?'), "CRITICAL"),
    ("GitHub Token", re.compile(r'ghp_[a-zA-Z0-9]{36}'), "CRITICAL"),
    ("GitHub OAuth", re.compile(r'gho_[a-zA-Z0-9]{36}'), "CRITICAL"),
    ("Slack Token", re.compile(r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}(-[a-zA-Z0-9]{24})?'), "CRITICAL"),
    ("Generic API Key", re.compile(r'[Aa][Pp][Ii][_\-]?[Kk][Ee][Yy]\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{32,64}["\']?'), "HIGH"),
    ("Generic Secret", re.compile(r'[Ss][Ee][Cc][Rr][Ee][Tt]\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{16,64}["\']?'), "HIGH"),
    ("Private Key", re.compile(r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'), "CRITICAL"),
    ("Password", re.compile(r'[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]\s*[:=]\s*["\']?[^"\'\s]{8,}["\']?'), "HIGH"),
    ("Database URL", re.compile(r'(postgres|mysql|mongodb|redis)://[^\s"\']+'), "HIGH"),
    ("JWT Token", re.compile(r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'), "MEDIUM"),
    ("Bearer Token", re.compile(r'[Bb][Ee][Aa][Rr][Ee][Rr]\s+[a-zA-Z0-9_\-\.]{20,}'), "HIGH"),
    ("Base64 High Entropy", re.compile(r'[A-Za-z0-9+/]{40,}={0,2}'), "LOW"),
]

EXCLUDED_PATHS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".tox", ".pytest_cache", ".mypy_cache", "build", "dist"}
EXCLUDED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".avi", ".pdf", ".zip", ".tar", ".gz", ".rar", ".exe", ".dll", ".so", ".dylib", ".bin"}


def scan_secrets(repo_path: str) -> List[Dict]:
    findings = []
    repo = Path(repo_path)
    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_PATHS]
        for fname in files:
            if any(fname.lower().endswith(ext) for ext in EXCLUDED_EXTENSIONS):
                continue
            fpath = Path(root) / fname
            try:
                text = fpath.read_text(errors="ignore")
            except Exception:
                continue
            for name, pattern, severity in SECRET_PATTERNS:
                for match in pattern.finditer(text):
                    line_num = text[:match.start()].count("\n") + 1
                    snippet = text[max(0, match.start()-20):match.end()+20].replace("\n", " ")
                    findings.append({
                        "category": "secrets",
                        "severity": severity,
                        "file": str(fpath.relative_to(repo)),
                        "line": line_num,
                        "finding": name,
                        "snippet": snippet,
                        "remediation": "Remove hardcoded secrets. Use environment variables, secret managers (Vault, AWS Secrets Manager), or encrypted storage.",
                    })
    return findings


# ─── Dependency Scanning (OSV) ──────────────────────────────────────

MANIFEST_MAP = {
    "requirements.txt": "PyPI",
    "package.json": "npm",
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "go.mod": "Go",
    "Cargo.toml": "crates.io",
    "pom.xml": "Maven",
    "build.gradle": "Maven",
    "Gemfile": "RubyGems",
    "composer.json": "Packagist",
}


def parse_requirements_txt(content: str) -> List[Dict]:
    pkgs = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # pkg==1.0.0
        m = re.match(r'^([A-Za-z0-9_.\-]+)==([A-Za-z0-9_.+\-]+)', line)
        if m:
            pkgs.append({"name": m.group(1), "version": m.group(2)})
    return pkgs


def parse_package_json(content: str) -> List[Dict]:
    try:
        data = json.loads(content)
        deps = {}
        deps.update(data.get("dependencies", {}))
        deps.update(data.get("devDependencies", {}))
        return [{"name": k, "version": v.lstrip("^>=<~")} for k, v in deps.items()]
    except Exception:
        return []


def parse_go_mod(content: str) -> List[Dict]:
    pkgs = []
    for line in content.splitlines():
        m = re.match(r'^\s*([^\s]+)\s+v([\d\.\w+\-]+)', line)
        if m:
            pkgs.append({"name": m.group(1), "version": m.group(2)})
    return pkgs


def query_osv(ecosystem: str, name: str, version: str) -> List[Dict]:
    url = "https://api.osv.dev/v1/query"
    payload = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
    try:
        resp = requests.post(url, json=payload, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            vulns = data.get("vulns", [])
            return [
                {
                    "id": v.get("id", "UNKNOWN"),
                    "summary": v.get("summary", "No summary"),
                    "severity": "HIGH" if v.get("severity") == "HIGH" or v.get("severity") == "CRITICAL" else (v.get("severity") or "MEDIUM"),
                }
                for v in vulns
            ]
    except Exception:
        pass
    return []


def scan_dependencies(repo_path: str) -> List[Dict]:
    findings = []
    repo = Path(repo_path)
    for manifest, ecosystem in MANIFEST_MAP.items():
        fpath = repo / manifest
        if not fpath.exists():
            continue
        try:
            content = fpath.read_text(errors="ignore")
        except Exception:
            continue
        if manifest == "requirements.txt":
            pkgs = parse_requirements_txt(content)
        elif manifest in ("package.json",):
            pkgs = parse_package_json(content)
        elif manifest == "go.mod":
            pkgs = parse_go_mod(content)
        else:
            continue
        for pkg in pkgs:
            vulns = query_osv(ecosystem, pkg["name"], pkg["version"])
            for v in vulns:
                findings.append({
                    "category": "dependencies",
                    "severity": v["severity"],
                    "file": manifest,
                    "finding": f"{pkg['name']}@{pkg['version']} — {v['id']}: {v['summary']}",
                    "package": pkg["name"],
                    "version": pkg["version"],
                    "vulnerability": v["id"],
                    "remediation": f"Upgrade {pkg['name']} to a patched version. Check https://osv.dev/{v['id']}",
                })
    return findings


# ─── SAST Basics ──────────────────────────────────────────────────

SAST_RULES = [
    {
        "name": "Dangerous eval/exec",
        "severity": "CRITICAL",
        "languages": {"py", "js", "ts", "rb", "php"},
        "pattern": re.compile(r'\b(eval|exec)\s*\('),
        "description": "Use of eval() or exec() allows arbitrary code execution.",
        "remediation": "Avoid eval/exec. Use safer alternatives like ast.literal_eval or parsed configuration.",
    },
    {
        "name": "SQL Injection (string concat)",
        "severity": "CRITICAL",
        "languages": {"py", "js", "ts", "php", "rb", "java"},
        "pattern": re.compile(r'["\']\s*[%+]\s*(request\.|req\.|params\.|args\[|query\.|form\.)', re.IGNORECASE),
        "description": "String concatenation with user input into SQL queries.",
        "remediation": "Use parameterized queries / prepared statements.",
    },
    {
        "name": "Hardcoded SQL query with formatting",
        "severity": "HIGH",
        "languages": {"py", "js", "ts", "php", "rb"},
        "pattern": re.compile(r'(SELECT|INSERT|UPDATE|DELETE)\s+.*%s|\.format\s*\(|f["\'].*\{.*\}.*["\'].*(SELECT|INSERT|UPDATE|DELETE)', re.IGNORECASE),
        "description": "SQL query built with string formatting.",
        "remediation": "Use ORM or parameterized queries.",
    },
    {
        "name": "Insecure deserialization",
        "severity": "HIGH",
        "languages": {"py", "js", "ts", "rb", "php", "java"},
        "pattern": re.compile(r'\b(pickle\.loads|yaml\.load\s*\(|JSON\.parse\s*\(|ObjectInputStream|unserialize\s*\()'),
        "description": "Insecure deserialization can lead to remote code execution.",
        "remediation": "Use safe deserialization methods (yaml.safe_load, json.loads with restrictions).",
    },
    {
        "name": "SSRF risk (raw URL open)",
        "severity": "HIGH",
        "languages": {"py", "js", "ts", "rb", "php", "java", "go"},
        "pattern": re.compile(r'(urllib\.request\.urlopen|requests\.get\s*\(|http\.Get\s*\(|fetch\s*\(|curl_exec\s*\()'),
        "description": "Direct URL fetching with user-controlled input can lead to SSRF.",
        "remediation": "Validate and sanitize URLs. Use an allowlist of permitted domains.",
    },
    {
        "name": "Weak cryptography (MD5/SHA1)",
        "severity": "MEDIUM",
        "languages": {"py", "js", "ts", "rb", "php", "java", "go", "c", "cpp"},
        "pattern": re.compile(r'\b(md5|sha1)\s*\('),
        "description": "MD5 and SHA1 are cryptographically broken.",
        "remediation": "Use SHA-256 or stronger hashing algorithms.",
    },
    {
        "name": "Insecure randomness",
        "severity": "MEDIUM",
        "languages": {"py", "js", "ts", "rb", "php", "java"},
        "pattern": re.compile(r'\b(random\.randint|random\.choice|Math\.random\(\))'),
        "description": "Standard random functions are not cryptographically secure.",
        "remediation": "Use secrets.token_hex, secrets.token_urlsafe, or crypto.getRandomValues.",
    },
    {
        "name": "Debug mode enabled",
        "severity": "HIGH",
        "languages": {"py", "js", "ts", "php", "rb"},
        "pattern": re.compile(r'(DEBUG\s*=\s*True|app\.run\s*\(.*debug\s*=\s*True|FLASK_DEBUG\s*=\s*1)'),
        "description": "Debug mode exposes stack traces and enables code execution in some frameworks.",
        "remediation": "Set DEBUG=False in production.",
    },
    {
        "name": "Dangerous subprocess call",
        "severity": "CRITICAL",
        "languages": {"py", "rb", "php", "go"},
        "pattern": re.compile(r'\b(os\.system|subprocess\.call|subprocess\.Popen)\s*\('),
        "description": "Subprocess calls with unsanitized input can lead to command injection.",
        "remediation": "Avoid shell=True. Pass arguments as lists, not strings.",
    },
]


def scan_sast(repo_path: str) -> List[Dict]:
    findings = []
    repo = Path(repo_path)
    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_PATHS]
        for fname in files:
            ext = Path(fname).suffix.lstrip(".").lower()
            fpath = Path(root) / fname
            try:
                text = fpath.read_text(errors="ignore")
            except Exception:
                continue
            for rule in SAST_RULES:
                if ext not in rule["languages"]:
                    continue
                for match in rule["pattern"].finditer(text):
                    line_num = text[:match.start()].count("\n") + 1
                    snippet = text[max(0, match.start()-30):match.end()+30].replace("\n", " ")
                    findings.append({
                        "category": "sast",
                        "severity": rule["severity"],
                        "file": str(fpath.relative_to(repo)),
                        "line": line_num,
                        "finding": rule["name"],
                        "description": rule["description"],
                        "snippet": snippet,
                        "remediation": rule["remediation"],
                    })
    return findings


# ─── Reporting ────────────────────────────────────────────────────

def print_report(all_findings: List[Dict]):
    categories = {}
    for f in all_findings:
        categories.setdefault(f["category"], []).append(f)

    total = len(all_findings)
    critical = sum(1 for f in all_findings if f["severity"] == "CRITICAL")
    high = sum(1 for f in all_findings if f["severity"] == "HIGH")
    medium = sum(1 for f in all_findings if f["severity"] == "MEDIUM")
    low = sum(1 for f in all_findings if f["severity"] == "LOW")

    print("=" * 60)
    print("DEVSECOPS PIPELINE SECURITY SCAN REPORT")
    print("=" * 60)
    print(f"Total findings: {total}")
    print(f"  CRITICAL: {critical} | HIGH: {high} | MEDIUM: {medium} | LOW: {low}")
    print()

    for cat, items in categories.items():
        print(f"--- {cat.upper()} ({len(items)} findings) ---")
        for it in items[:5]:
            loc = f"{it.get('file', '')}:{it.get('line', '-')}" if "file" in it else it.get("file", "-")
            print(f"  [{it['severity']}] {it['finding']} | {loc}")
            if "vulnerability" in it:
                print(f"      Package: {it['package']}@{it['version']} | CVE: {it['vulnerability']}")
        if len(items) > 5:
            print(f"  ... and {len(items) - 5} more")
        print()

    if critical > 0:
        print("[!] CRITICAL findings detected — deployment blocked.")
    elif high > 0:
        print("[!] HIGH findings detected — review required.")
    else:
        print("[+] No critical or high findings. Pipeline may proceed.")


def generate_json_report(all_findings: List[Dict]) -> Dict:
    from datetime import datetime
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return {
        "metadata": {
            "scan_date": datetime.utcnow().isoformat() + "Z",
            "scanner_version": "1.0.0",
        },
        "summary": {
            "total_findings": len(all_findings),
            "severity_breakdown": counts,
            "passed": counts["CRITICAL"] == 0,
        },
        "findings": all_findings,
    }


# ─── CLI ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="DevSecOps Pipeline Security Scanner")
    parser.add_argument("repo", help="Path to the repository to scan")
    parser.add_argument("--output", "-o", choices=["table", "json"], default="table", help="Output format")
    parser.add_argument("--save", "-s", help="Save JSON report to file")
    parser.add_argument("--secrets-only", action="store_true", help="Only run secret detection")
    parser.add_argument("--deps-only", action="store_true", help="Only run dependency scanning")
    parser.add_argument("--sast-only", action="store_true", help="Only run SAST")
    parser.add_argument("--fail-on-critical", action="store_true", help="Exit with code 1 if CRITICAL found")
    args = parser.parse_args()

    if not os.path.isdir(args.repo):
        print(f"Error: '{args.repo}' is not a valid directory.")
        sys.exit(1)

    all_findings: List[Dict] = []

    run_all = not (args.secrets_only or args.deps_only or args.sast_only)

    if run_all or args.secrets_only:
        all_findings.extend(scan_secrets(args.repo))
    if run_all or args.deps_only:
        all_findings.extend(scan_dependencies(args.repo))
    if run_all or args.sast_only:
        all_findings.extend(scan_sast(args.repo))

    if args.output == "json":
        report = generate_json_report(all_findings)
        out = json.dumps(report, indent=2)
        print(out)
        if args.save:
            with open(args.save, "w") as f:
                f.write(out)
    else:
        print_report(all_findings)
        if args.save:
            with open(args.save, "w") as f:
                f.write(json.dumps(generate_json_report(all_findings), indent=2))
            print(f"\nReport saved to {args.save}")

    critical_count = sum(1 for f in all_findings if f["severity"] == "CRITICAL")
    if args.fail_on_critical and critical_count > 0:
        print("Exiting with code 1 (CRITICAL findings found)")
        sys.exit(1)


if __name__ == "__main__":
    main()
