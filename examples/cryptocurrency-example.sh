#!/bin/bash
# Cryptocurrency Security Example: Address Validation
# Shows how to use the cryptocurrency-security skill

echo "=== Cryptocurrency Security Example ==="
echo "Validating crypto addresses..."
echo ""

# Example 1: Validate Bitcoin address
echo "1. Validate Bitcoin Address:"
echo "   python3 skills/23-cryptocurrency-security/scripts/crypto_validator.py --address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
echo ""

# Example 2: Validate Ethereum address
echo "2. Validate Ethereum Address:"
echo "   python3 skills/23-cryptocurrency-security/scripts/crypto_validator.py --address 0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb"
echo ""

# Example 3: Check multiple addresses
echo "3. Multiple Addresses:"
echo "   python3 skills/23-cryptocurrency-security/scripts/crypto_validator.py --address addr1 addr2 addr3"
echo ""

# Example 4: Validate mnemonic
echo "4. Validate Mnemonic Phrase:"
echo "   python3 skills/23-cryptocurrency-security/scripts/crypto_validator.py --mnemonic 'word1 word2 ... word12'"
echo ""

# Example 5: Check file of addresses
echo "5. Check Address File:"
echo "   python3 skills/23-cryptocurrency-security/scripts/crypto_validator.py --check-entropy addresses.txt --output report.json"
echo ""

echo "See skills/23-cryptocurrency-security/SKILL.md for full documentation"
