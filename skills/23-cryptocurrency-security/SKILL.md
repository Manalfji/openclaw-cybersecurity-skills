---
name: "cryptocurrency-security"
description: "Cryptocurrency address validation, transaction analysis, mnemonic validation, and wallet security checks."
---

# Cryptocurrency Security

## When to Use
- Validate Bitcoin, Ethereum, or other crypto addresses
- Check mnemonic phrases for correctness (BIP-39)
- Analyze transactions for suspicious patterns
- Verify wallet security (entropy, weak keys)
- Check for common cryptocurrency scams or phishing

## Workflow
1. **Address Validation** — Verify address format and checksum for Bitcoin, Ethereum, Litecoin, etc.
2. **Mnemonic Validation** — Validate BIP-39 seed phrases and derive addresses
3. **Transaction Analysis** — Check transaction patterns for suspicious activity
4. **Entropy Check** — Verify wallet generation has sufficient randomness
5. **Security Report** — Generate findings with recommendations

## Scripts
- `scripts/crypto_validator.py` — Multi-cryptocurrency address validator and security checker

## Output
- JSON report with validation results, security findings, and recommendations
- Terminal summary with color-coded risk levels

## Prerequisites
```bash
pip install base58 eth-hash[pycryptodome]
```

## Supported Cryptocurrencies
- Bitcoin (BTC)
- Ethereum (ETH)
- Litecoin (LTC)
- Bitcoin Cash (BCH)
- Dogecoin (DOGE)

## Safety Notes
- This tool performs offline validation only — no blockchain queries
- Never input private keys or full mnemonics into unfamiliar systems
- Use only for security analysis, not recovery or key generation
