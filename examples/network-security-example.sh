#!/bin/bash
# Network Security Example: PCAP Analysis
# Shows how to use the network-security skill

echo "=== Network Security Example ==="
echo "Analyzing PCAP file for suspicious activity..."
echo ""

# Example 1: Basic PCAP analysis
echo "1. Basic PCAP Analysis:"
echo "   python3 skills/08-network-security/scripts/pcap_analyzer.py --file suspicious.pcap"
echo ""

# Example 2: Extract specific protocols
echo "2. Extract DNS queries:"
echo "   python3 skills/08-network-security/scripts/pcap_analyzer.py --file capture.pcap --dns-only"
echo ""

# Example 3: Detect beaconing
echo "3. Detect C2 beaconing:"
echo "   python3 skills/08-network-security/scripts/pcap_analyzer.py --file traffic.pcap --beaconing"
echo ""

# Example 4: Generate Suricata rules
echo "4. Generate Suricata rule from findings:"
echo "   python3 skills/08-network-security/scripts/pcap_analyzer.py --file malware.pcap --generate-rules"
echo ""

echo "See skills/08-network-security/SKILL.md for full documentation"
