#!/usr/bin/env python3
"""
SBOM Generator
Generates Software Bill of Materials in SPDX and CycloneDX formats.

Usage:
    python3 sbom_generator.py --project /path/to/project --format spdx-json
    python3 sbom_generator.py --project /path/to/project --format cyclonedx-json
"""

import argparse
import json
import os
import subprocess
from datetime import datetime
from pathlib import Path


def detect_package_manager(project_path):
    """Detect package manager used in project."""
    path = Path(project_path)
    
    if (path / "requirements.txt").exists():
        return "pip"
    elif (path / "package.json").exists():
        return "npm"
    elif (path / "Cargo.toml").exists():
        return "cargo"
    elif (path / "go.mod").exists():
        return "go"
    elif (path / "pom.xml").exists():
        return "maven"
    else:
        return "unknown"


def parse_requirements_txt(filepath):
    """Parse Python requirements.txt."""
    packages = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # Handle various formats: package, package==version, package>=version
                if '==' in line:
                    name, version = line.split('==', 1)
                elif '>=' in line:
                    name, version = line.split('>=', 1)
                elif '<=' in line:
                    name, version = line.split('<=', 1)
                else:
                    name = line
                    version = "unknown"
                
                packages.append({
                    "name": name.strip(),
                    "version": version.strip(),
                    "type": "library",
                    "ecosystem": "PyPI"
                })
    except Exception as e:
        print(f"Warning: Could not parse requirements.txt: {e}")
    
    return packages


def parse_package_json(filepath):
    """Parse Node.js package.json."""
    packages = []
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        dependencies = data.get("dependencies", {})
        dev_dependencies = data.get("devDependencies", {})
        
        for name, version in dependencies.items():
            packages.append({
                "name": name,
                "version": version.replace('^', '').replace('~', ''),
                "type": "library",
                "ecosystem": "npm"
            })
        
        for name, version in dev_dependencies.items():
            packages.append({
                "name": name,
                "version": version.replace('^', '').replace('~', ''),
                "type": "library",
                "ecosystem": "npm",
                "scope": "development"
            })
    except Exception as e:
        print(f"Warning: Could not parse package.json: {e}")
    
    return packages


def generate_spdx_sbom(packages, project_name, project_path):
    """Generate SPDX JSON SBOM."""
    sbom = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{project_name}-sbom",
        "documentNamespace": f"https://example.com/sbom/{project_name}-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "creationInfo": {
            "created": datetime.now().isoformat(),
            "creators": ["Tool: openclaw-sbom-generator-1.0.0"]
        },
        "packages": []
    }
    
    for i, pkg in enumerate(packages):
        spdx_package = {
            "SPDXID": f"SPDXRef-Package-{i}",
            "name": pkg["name"],
            "versionInfo": pkg["version"],
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": f"pkg:{pkg.get('ecosystem', 'generic')}/{pkg['name']}@{pkg['version']}"
                }
            ]
        }
        sbom["packages"].append(spdx_package)
    
    return sbom


def generate_cyclonedx_sbom(packages, project_name):
    """Generate CycloneDX JSON SBOM."""
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{os.urandom(16).hex()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "tools": [
                {
                    "vendor": "OpenClaw",
                    "name": "sbom-generator",
                    "version": "1.0.0"
                }
            ]
        },
        "components": []
    }
    
    for pkg in packages:
        component = {
            "type": pkg.get("type", "library"),
            "name": pkg["name"],
            "version": pkg["version"],
            "purl": f"pkg:{pkg.get('ecosystem', 'generic')}/{pkg['name']}@{pkg['version']}"
        }
        if "scope" in pkg:
            component["scope"] = pkg["scope"]
        sbom["components"].append(component)
    
    return sbom


def main():
    parser = argparse.ArgumentParser(
        description="SBOM Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --project /path/to/python-project --format spdx-json
  %(prog)s --project /path/to/node-project --format cyclonedx-json
  %(prog)s --project /path/to/project --format spdx-json --output sbom.json
        """
    )
    
    parser.add_argument("--project", "-p", required=True, help="Project directory to analyze")
    parser.add_argument("--format", "-f", 
                       choices=["spdx-json", "cyclonedx-json"],
                       default="spdx-json",
                       help="SBOM format")
    parser.add_argument("--output", "-o", help="Output file (default: stdout)")
    
    args = parser.parse_args()
    
    project_path = Path(args.project)
    if not project_path.exists():
        print(f"Error: Project path not found: {args.project}")
        return 1
    
    # Detect package manager
    package_manager = detect_package_manager(project_path)
    print(f"[*] Detected package manager: {package_manager}")
    
    # Parse dependencies
    packages = []
    if package_manager == "pip":
        req_file = project_path / "requirements.txt"
        packages = parse_requirements_txt(req_file)
    elif package_manager == "npm":
        pkg_file = project_path / "package.json"
        packages = parse_package_json(pkg_file)
    else:
        print(f"[!] Package manager '{package_manager}' not fully supported yet")
        # Try to find any files
        for req_file in project_path.glob("**/requirements.txt"):
            packages.extend(parse_requirements_txt(req_file))
        for pkg_file in project_path.glob("**/package.json"):
            packages.extend(parse_package_json(pkg_file))
    
    print(f"[*] Found {len(packages)} dependencies")
    
    # Generate SBOM
    project_name = project_path.name
    if args.format == "spdx-json":
        sbom = generate_spdx_sbom(packages, project_name, str(project_path))
    else:
        sbom = generate_cyclonedx_sbom(packages, project_name)
    
    # Output
    sbom_json = json.dumps(sbom, indent=2)
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(sbom_json)
        print(f"[+] SBOM saved to: {args.output}")
    else:
        print(sbom_json)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
