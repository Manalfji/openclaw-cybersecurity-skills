#!/bin/bash
# Deception Technology Example: Honeypots and Honeytokens
# Shows how to use the deception-technology skill

echo "=== Deception Technology Example ==="
echo "Deploying honeypots and honeytokens..."
echo ""

# Example 1: Generate AWS honeytokens
echo "1. Generate AWS Honeytokens:"
echo "   python3 skills/26-deception-technology/scripts/honeytoken_generator.py --type aws --count 5 --output aws_tokens.json"
echo ""

# Example 2: Generate GitHub tokens
echo "2. Generate GitHub Tokens:"
echo "   python3 skills/26-deception-technology/scripts/honeytoken_generator.py --type github --count 10 --output github_tokens.json"
echo ""

# Example 3: Deploy canary file
echo "3. Deploy Canary File:"
echo "   python3 skills/26-deception-technology/scripts/canary_deployer.py --deploy /shared/finance --name 'salaries_Q4.xlsx'"
echo ""

# Example 4: Deploy canary with custom content
echo "4. Deploy Custom Canary:"
echo "   python3 skills/26-deception-technology/scripts/canary_deployer.py --deploy /tmp --name credentials.csv --content 'fake credentials data'"
echo ""

# Example 5: Analyze honeypot logs
echo "5. Analyze Honeypot Logs:"
echo "   python3 skills/26-deception-technology/scripts/honeypot_log_analyzer.py --logs /var/log/honeypot/ --output honeypot_report.json"
echo ""

# Example 6: Check for canary access
echo "6. Check Canary Access:"
echo "   python3 skills/26-deception-technology/scripts/canary_deployer.py --check /var/log/audit.log --canaries /shared/finance/salaries_Q4.xlsx"
echo ""

echo "See skills/26-deception-technology/SKILL.md for full documentation"
