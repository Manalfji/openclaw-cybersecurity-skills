#!/bin/bash
# Digital Forensics Example: Evidence Analysis
# Shows how to use the digital-forensics skill

echo "=== Digital Forensics Example ==="
echo "Analyzing forensic evidence..."
echo ""

# Example 1: Build timeline from evidence directory
echo "1. Build Forensic Timeline:"
echo "   python3 skills/24-digital-forensics/scripts/forensic_timeline.py --directory /evidence/case001 --output timeline.json"
echo ""

# Example 2: Generate CSV timeline
echo "2. Generate CSV Timeline:"
echo "   python3 skills/24-digital-forensics/scripts/forensic_timeline.py --directory /evidence/case001 --csv timeline.csv"
echo ""

# Example 3: Analyze memory strings
echo "3. Analyze Memory Dump:"
echo "   strings -n 8 memory.dmp > memory_strings.txt"
echo "   python3 skills/24-digital-forensics/scripts/memory_hunter.py --strings memory_strings.txt --output memory_analysis.json"
echo ""

# Example 4: Parse Windows registry
echo "4. Parse Registry Hive:"
echo "   python3 skills/24-digital-forensics/scripts/registry_parser.py --hive NTUSER.DAT --artifacts usb --output usb_history.json"
echo ""

# Example 5: Full case analysis
echo "5. Full Case Analysis:"
echo "   python3 skills/24-digital-forensics/scripts/forensic_timeline.py --directory /evidence/case001 --case CASE-2024-001 --output case_report.json"
echo ""

echo "See skills/24-digital-forensics/SKILL.md for full documentation"
