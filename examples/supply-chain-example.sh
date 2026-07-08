#!/bin/bash
# Supply Chain Security Example: SBOM Generation
# Shows how to use the supply-chain-security skill

echo "=== Supply Chain Security Example ==="
echo "Generating SBOMs and checking for vulnerabilities..."
echo ""

# Example 1: Generate SPDX SBOM
echo "1. Generate SPDX SBOM:"
echo "   python3 skills/25-supply-chain-security/scripts/sbom_generator.py --project /path/to/python-project --format spdx-json"
echo ""

# Example 2: Generate CycloneDX SBOM
echo "2. Generate CycloneDX SBOM:"
echo "   python3 skills/25-supply-chain-security/scripts/sbom_generator.py --project /path/to/node-project --format cyclonedx-json"
echo ""

# Example 3: Detect dependency confusion
echo "3. Check for Dependency Confusion:"
echo "   python3 skills/25-supply-chain-security/scripts/dependency_confusion_detector.py --project /path/to/project"
echo ""

# Example 4: Check specific package file
echo "4. Analyze Package File:"
echo "   python3 skills/25-supply-chain-security/scripts/dependency_confusion_detector.py --packages requirements.txt --output report.json"
echo ""

# Example 5: Verify SLSA provenance
echo "5. Verify SLSA Provenance:"
echo "   python3 skills/25-supply-chain-security/scripts/slsa_assessor.py --artifact app.jar --provenance provenance.json"
echo ""

echo "See skills/25-supply-chain-security/SKILL.md for full documentation"
