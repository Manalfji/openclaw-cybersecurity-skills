#!/bin/bash
# Blue Team Defense Example: System Hardening
# Shows how to use the blue-team-defense skill

echo "=== Blue Team Defense Example ==="
echo "Auditing system hardening..."
echo ""

# Example 1: Basic hardening audit
echo "1. Basic Hardening Audit:"
echo "   python3 skills/15-blue-team-defense/scripts/hardening_checker.py --os auto"
echo ""

# Example 2: Generate detailed report
echo "2. Detailed JSON Report:"
echo "   python3 skills/15-blue-team-defense/scripts/hardening_checker.py --os ubuntu --output hardening_report.json"
echo ""

# Example 3: Check specific areas
echo "3. Check SSH Configuration:"
echo "   python3 skills/15-blue-team-defense/scripts/hardening_checker.py --os auto --check ssh,firewall"
echo ""

# Example 4: Compare against baseline
echo "4. Compare Against CIS Baseline:"
echo "   python3 skills/15-blue-team-defense/scripts/hardening_checker.py --baseline cis-ubuntu-20.04"
echo ""

echo "See skills/15-blue-team-defense/SKILL.md for full documentation"
