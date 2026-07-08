#!/bin/bash
# DevSecOps Example: Pipeline Security Scanning
# Shows how to use the devsecops skill

echo "=== DevSecOps Example ==="
echo "Scanning repository for security issues..."
echo ""

# Example 1: Full repository scan
echo "1. Full Repository Scan:"
echo "   python3 skills/22-devsecops/scripts/devsecops_scanner.py --repo /path/to/project"
echo ""

# Example 2: Quick scan (secrets + deps only)
echo "2. Quick Scan:"
echo "   python3 skills/22-devsecops/scripts/devsecops_scanner.py --repo /path/to/project --scope quick"
echo ""

# Example 3: CI/CD mode (fails on critical)
echo "3. CI/CD Integration:"
echo "   python3 skills/22-devsecops/scripts/devsecops_scanner.py --repo . --fail-on-critical --output ci-report.json"
echo ""

# Example 4: Specific checks
echo "4. Check Only Secrets:"
echo "   python3 skills/22-devsecops/scripts/devsecops_scanner.py --repo /path/to/project --check secrets"
echo ""

echo "See skills/22-devsecops/SKILL.md for full documentation"
