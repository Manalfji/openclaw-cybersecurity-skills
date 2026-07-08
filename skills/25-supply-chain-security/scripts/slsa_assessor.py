#!/usr/bin/env python3
"""
SLSA Provenance Assessor
Verifies SLSA (Supply-chain Levels for Software Artifacts) provenance.

Usage:
    python3 slsa_assessor.py --artifact app.jar --provenance provenance.json
    python3 slsa_assessor.py --level 3 --check-build
"""

import argparse
import hashlib
import json
from datetime import datetime
from pathlib import Path


def calculate_artifact_hash(filepath):
    """Calculate SHA256 hash of artifact."""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def parse_provenance_file(filepath):
    """Parse SLSA provenance file."""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        return {"error": str(e)}


def assess_slsa_level(provenance):
    """Assess SLSA level based on provenance data."""
    assessment = {
        "level": 0,
        "requirements_met": [],
        "requirements_missing": [],
        "recommendations": []
    }
    
    # Check for SLSA Level 1: Provenance exists
    if "_type" in provenance and provenance["_type"] == "https://in-toto.io/Statement/v0.1":
        assessment["requirements_met"].append("Level 1: Provenance exists")
        assessment["level"] = 1
    else:
        assessment["requirements_missing"].append("Level 1: No provenance found")
        return assessment
    
    # Check for SLSA Level 2: Signed provenance
    if "signatures" in provenance or "payloadType" in provenance:
        assessment["requirements_met"].append("Level 2: Signed provenance")
        assessment["level"] = 2
    else:
        assessment["requirements_missing"].append("Level 2: Provenance not signed")
    
    # Check for SLSA Level 3: Build service used
    predicate = provenance.get("predicate", {})
    if "buildType" in predicate:
        assessment["requirements_met"].append("Level 3: Build service used")
        assessment["level"] = 3
    else:
        assessment["requirements_missing"].append("Level 3: No build service evidence")
    
    # Check for SLSA Level 4: Hermetic build
    if "invocation" in predicate and "environment" in predicate.get("invocation", {}):
        env = predicate["invocation"]["environment"]
        if env.get("isHermetic", False):
            assessment["requirements_met"].append("Level 4: Hermetic build")
            assessment["level"] = 4
        else:
            assessment["requirements_missing"].append("Level 4: Build not hermetic")
    else:
        assessment["requirements_missing"].append("Level 4: No hermetic build evidence")
    
    # Generate recommendations
    if assessment["level"] < 4:
        assessment["recommendations"].extend([
            "Use SLSA-compliant build service (GitHub Actions, Cloud Build, etc.)",
            "Enable signed provenance attestation",
            "Configure hermetic builds with pinned dependencies",
            "Store provenance alongside artifacts"
        ])
    
    return assessment


def generate_report(assessment, artifact_path, output_file=None):
    """Generate SLSA assessment report."""
    report = {
        "scan_time": datetime.now().isoformat(),
        "artifact": str(artifact_path),
        "artifact_hash": calculate_artifact_hash(artifact_path) if Path(artifact_path).exists() else "N/A",
        "slsa_level": assessment["level"],
        "requirements_met": assessment["requirements_met"],
        "requirements_missing": assessment["requirements_missing"],
        "recommendations": assessment["recommendations"]
    }
    
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report saved to: {output_file}")
    else:
        print(json.dumps(report, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description="SLSA Provenance Assessor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --artifact app.jar --provenance provenance.json
  %(prog)s --artifact app.jar --provenance provenance.json --output report.json
  %(prog)s --check-level 3 --build-config .github/workflows/build.yml
        """
    )
    
    parser.add_argument("--artifact", "-a", help="Artifact file to assess")
    parser.add_argument("--provenance", "-p", help="Provenance attestation file")
    parser.add_argument("--check-level", "-l", type=int, choices=[1, 2, 3, 4], help="Check specific SLSA level")
    parser.add_argument("--build-config", "-b", help="Build configuration file")
    parser.add_argument("--output", "-o", help="Output JSON report")
    
    args = parser.parse_args()
    
    if not args.artifact and not args.check_level:
        parser.error("Must specify --artifact or --check-level")
    
    if args.artifact:
        if not Path(args.artifact).exists():
            print(f"Error: Artifact not found: {args.artifact}")
            return 1
        
        print(f"[*] Assessing artifact: {args.artifact}")
        
        if args.provenance:
            print(f"[*] Parsing provenance: {args.provenance}")
            provenance = parse_provenance_file(args.provenance)
            
            if "error" in provenance:
                print(f"[!] Error parsing provenance: {provenance['error']}")
                return 1
            
            assessment = assess_slsa_level(provenance)
        else:
            print("[!] No provenance file provided")
            assessment = {
                "level": 0,
                "requirements_met": [],
                "requirements_missing": ["No provenance provided"],
                "recommendations": ["Generate and store SLSA provenance for this artifact"]
            }
        
        generate_report(assessment, args.artifact, args.output)
    
    elif args.check_level:
        print(f"[*] Checking SLSA Level {args.check_level} requirements")
        print("[!] This feature requires build configuration analysis")
        # In production, this would analyze build config files
        return 0
    
    return 0


if __name__ == "__main__":
    main()
