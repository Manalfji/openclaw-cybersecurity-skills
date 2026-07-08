#!/usr/bin/env python3
"""
Dependency Confusion Detector
Detects dependency confusion vulnerabilities in package managers.

Usage:
    python3 dependency_confusion_detector.py --project /path/to/project
    python3 dependency_confusion_detector.py --packages requirements.txt
"""

import argparse
import json
import sys
from pathlib import Path


def check_pypi_package(package_name):
    """Check if package exists on PyPI (simulated)."""
    # In production, this would query PyPI API
    # For demo, we simulate common patterns
    internal_patterns = [
        'company-', 'internal-', 'private-',
        'mycompany-', 'corp-', 'org-'
    ]
    
    for pattern in internal_patterns:
        if package_name.lower().startswith(pattern):
            return {
                "package": package_name,
                "risk": "HIGH",
                "reason": f"Package name '{package_name}' follows internal naming pattern",
                "recommendation": "Register this package on PyPI to prevent squatting"
            }
    
    return None


def check_npm_package(package_name):
    """Check if package exists on npm (simulated)."""
    internal_patterns = [
        '@company/', '@internal/', '@private/',
        '@mycompany/', '@corp/', '@org/'
    ]
    
    for pattern in internal_patterns:
        if package_name.lower().startswith(pattern):
            return {
                "package": package_name,
                "risk": "HIGH",
                "reason": f"Scoped package '{package_name}' may be vulnerable",
                "recommendation": "Ensure scope is properly configured in .npmrc"
            }
    
    return None


def parse_requirements_txt(filepath):
    """Parse Python requirements.txt."""
    packages = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '==' in line:
                    name = line.split('==')[0].strip()
                elif '>=' in line:
                    name = line.split('>=')[0].strip()
                elif '<=' in line:
                    name = line.split('<=')[0].strip()
                else:
                    name = line.strip()
                packages.append(name)
    except Exception as e:
        print(f"Warning: Could not parse {filepath}: {e}")
    
    return packages


def parse_package_json(filepath):
    """Parse Node.js package.json."""
    packages = []
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        packages.extend(data.get("dependencies", {}).keys())
        packages.extend(data.get("devDependencies", {}).keys())
    except Exception as e:
        print(f"Warning: Could not parse {filepath}: {e}")
    
    return packages


def analyze_project(project_path):
    """Analyze project for dependency confusion vulnerabilities."""
    findings = []
    path = Path(project_path)
    
    # Check Python projects
    for req_file in path.glob("**/requirements.txt"):
        packages = parse_requirements_txt(req_file)
        for pkg in packages:
            result = check_pypi_package(pkg)
            if result:
                result["file"] = str(req_file)
                result["ecosystem"] = "PyPI"
                findings.append(result)
    
    # Check Node.js projects
    for pkg_file in path.glob("**/package.json"):
        packages = parse_package_json(pkg_file)
        for pkg in packages:
            result = check_npm_package(pkg)
            if result:
                result["file"] = str(pkg_file)
                result["ecosystem"] = "npm"
                findings.append(result)
    
    return findings


def generate_report(findings, output_file=None):
    """Generate dependency confusion report."""
    report = {
        "scan_time": datetime.now().isoformat() if 'datetime' in globals() else "N/A",
        "total_findings": len(findings),
        "risk_summary": {
            "HIGH": len([f for f in findings if f.get("risk") == "HIGH"]),
            "MEDIUM": len([f for f in findings if f.get("risk") == "MEDIUM"]),
            "LOW": len([f for f in findings if f.get("risk") == "LOW"])
        },
        "findings": findings,
        "recommendations": [
            "Register internal package names on public repositories",
            "Use private repositories with proper authentication",
            "Implement namespace verification in CI/CD",
            "Monitor for unauthorized package publications"
        ]
    }
    
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report saved to: {output_file}")
    else:
        print(json.dumps(report, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description="Dependency Confusion Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --project /path/to/project
  %(prog)s --packages requirements.txt --output report.json
        """
    )
    
    parser.add_argument("--project", "-p", help="Project directory to analyze")
    parser.add_argument("--packages", help="Package file to analyze")
    parser.add_argument("--output", "-o", help="Output JSON report")
    
    args = parser.parse_args()
    
    if not args.project and not args.packages:
        parser.error("Must specify --project or --packages")
    
    if args.project:
        print(f"[*] Analyzing project: {args.project}")
        findings = analyze_project(args.project)
    else:
        print(f"[*] Analyzing package file: {args.packages}")
        pkg_path = Path(args.packages)
        if pkg_path.name == "requirements.txt":
            packages = parse_requirements_txt(pkg_path)
            findings = []
            for pkg in packages:
                result = check_pypi_package(pkg)
                if result:
                    result["file"] = str(pkg_path)
                    result["ecosystem"] = "PyPI"
                    findings.append(result)
        elif pkg_path.name == "package.json":
            packages = parse_package_json(pkg_path)
            findings = []
            for pkg in packages:
                result = check_npm_package(pkg)
                if result:
                    result["file"] = str(pkg_path)
                    result["ecosystem"] = "npm"
                    findings.append(result)
        else:
            print(f"[!] Unsupported package file: {pkg_path.name}")
            return 1
    
    print(f"[*] Found {len(findings)} potential issues")
    
    generate_report(findings, args.output)
    
    return 0


if __name__ == "__main__":
    main()
