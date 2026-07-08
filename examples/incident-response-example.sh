#!/bin/bash
# Incident Response Example: Timeline Building
# Shows how to use the incident-response skill

echo "=== Incident Response Example ==="
echo "Building incident timeline from logs..."
echo ""

# Example 1: Basic timeline from logs
echo "1. Basic Timeline:"
echo "   python3 skills/07-incident-response/scripts/timeline_builder.py --logs /var/log/auth.log"
echo ""

# Example 2: Multiple log sources with timeframe
echo "2. Multiple Sources + Timeframe:"
echo "   python3 skills/07-incident-response/scripts/timeline_builder.py --logs /var/log/*.log --start '2024-01-15 06:00' --end '2024-01-15 18:00'"
echo ""

# Example 3: Collect evidence
echo "3. Evidence Collection:"
echo "   python3 skills/07-incident-response/scripts/evidence_collector.py --source /var/log/ --case INC-2024-001 --output evidence.tar.gz"
echo ""

# Example 4: Generate full report
echo "4. Full Incident Report:"
echo "   python3 skills/07-incident-response/scripts/timeline_builder.py --logs /var/log/*.log --output incident_report.json"
echo ""

echo "See skills/07-incident-response/SKILL.md for full documentation"
