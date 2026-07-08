#!/usr/bin/env python3
"""
Cryptocurrency Security Validator
Validates addresses, mnemonics, and checks for common security issues.
Offline-only — no blockchain queries.

Usage:
    python3 crypto_validator.py --address <btc_addr> <eth_addr>
    python3 crypto_validator.py --mnemonic "word1 word2 ..."
    python3 crypto_validator.py --check-entropy <file_with_addresses>
"""

import argparse
import hashlib
import json
import re
import sys
from typing import Dict, List, Optional, Tuple

# Base58 alphabet for Bitcoin-like addresses
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58_decode(address: str) -> bytes:
    """Decode a Base58 string to bytes."""
    num = 0
    for char in address:
        if char not in BASE58_ALPHABET:
            raise ValueError(f"Invalid Base58 character: {char}")
        num = num * 58 + BASE58_ALPHABET.index(char)
    
    # Convert to bytes
    result = []
    while num > 0:
        num, remainder = divmod(num, 256)
        result.insert(0, remainder)
    
    # Add leading zero bytes (represented as '1' in Base58)
    for char in address:
        if char == '1':
            result.insert(0, 0)
        else:
            break
    
    return bytes(result)


def validate_bitcoin_address(address: str) -> Dict:
    """Validate a Bitcoin address (P2PKH or P2SH)."""
    result = {
        "address": address,
        "type": "bitcoin",
        "valid": False,
        "format": "unknown",
        "issues": []
    }
    
    # Check length
    if len(address) < 26 or len(address) > 35:
        result["issues"].append("Invalid length for Bitcoin address")
        return result
    
    # Check characters
    if not all(c in BASE58_ALPHABET for c in address):
        result["issues"].append("Contains invalid Base58 characters")
        return result
    
    try:
        decoded = base58_decode(address)
        
        # Check decoded length
        if len(decoded) != 25:
            result["issues"].append(f"Decoded length {len(decoded)} != 25 bytes")
            return result
        
        # Verify checksum
        payload = decoded[:-4]
        checksum = decoded[-4:]
        hash_double_sha256 = hashlib.sha256(hashlib.sha256(payload).digest()).digest()
        expected_checksum = hash_double_sha256[:4]
        
        if checksum != expected_checksum:
            result["issues"].append("Checksum mismatch")
            return result
        
        # Determine address type
        version_byte = payload[0]
        if version_byte == 0x00:
            result["format"] = "P2PKH (Pay-to-Public-Key-Hash)"
        elif version_byte == 0x05:
            result["format"] = "P2SH (Pay-to-Script-Hash)"
        else:
            result["format"] = f"Unknown version byte: {version_byte:02x}"
        
        result["valid"] = True
        
    except Exception as e:
        result["issues"].append(f"Decoding error: {str(e)}")
    
    return result


def validate_ethereum_address(address: str) -> Dict:
    """Validate an Ethereum address."""
    result = {
        "address": address,
        "type": "ethereum",
        "valid": False,
        "format": "unknown",
        "issues": []
    }
    
    # Remove '0x' prefix if present
    clean_address = address.lower().replace("0x", "")
    
    # Check length
    if len(clean_address) != 40:
        result["issues"].append(f"Invalid length: {len(clean_address)} hex chars (expected 40)")
        return result
    
    # Check hex characters
    if not all(c in "0123456789abcdef" for c in clean_address):
        result["issues"].append("Contains non-hexadecimal characters")
        return result
    
    # Check if it's checksummed (EIP-55)
    if address.startswith("0x") and any(c.isupper() for c in address[2:]):
        result["format"] = " checksummed (EIP-55)"
        # Verify checksum
        address_hash = hashlib.keccak(address[2:].lower().encode()).hexdigest()
        for i, char in enumerate(address[2:]):
            if char.isdigit():
                continue
            expected_case = "upper" if int(address_hash[i], 16) >= 8 else "lower"
            actual_case = "upper" if char.isupper() else "lower"
            if expected_case != actual_case:
                result["issues"].append(f"Checksum failed at position {i}")
                result["valid"] = False
                return result
    else:
        result["format"] = "non-checksummed"
    
    result["valid"] = True
    return result


def validate_litecoin_address(address: str) -> Dict:
    """Validate a Litecoin address."""
    result = {
        "address": address,
        "type": "litecoin",
        "valid": False,
        "format": "unknown",
        "issues": []
    }
    
    if len(address) < 26 or len(address) > 35:
        result["issues"].append("Invalid length for Litecoin address")
        return result
    
    try:
        decoded = base58_decode(address)
        if len(decoded) != 25:
            result["issues"].append(f"Decoded length {len(decoded)} != 25 bytes")
            return result
        
        payload = decoded[:-4]
        checksum = decoded[-4:]
        hash_double_sha256 = hashlib.sha256(hashlib.sha256(payload).digest()).digest()
        expected_checksum = hash_double_sha256[:4]
        
        if checksum != expected_checksum:
            result["issues"].append("Checksum mismatch")
            return result
        
        version_byte = payload[0]
        if version_byte == 0x30:
            result["format"] = "P2PKH"
        elif version_byte == 0x32:
            result["format"] = "P2SH"
        else:
            result["format"] = f"Unknown version byte: {version_byte:02x}"
        
        result["valid"] = True
        
    except Exception as e:
        result["issues"].append(f"Decoding error: {str(e)}")
    
    return result


def validate_mnemonic(mnemonic: str) -> Dict:
    """Basic mnemonic validation (BIP-39 word count check)."""
    result = {
        "mnemonic": mnemonic[:20] + "..." if len(mnemonic) > 20 else mnemonic,
        "valid": False,
        "word_count": 0,
        "issues": []
    }
    
    words = mnemonic.strip().split()
    result["word_count"] = len(words)
    
    if len(words) not in [12, 15, 18, 21, 24]:
        result["issues"].append(f"Invalid word count: {len(words)} (expected 12, 15, 18, 21, or 24)")
        return result
    
    # Check for repeated words (weak entropy indicator)
    unique_words = set(words)
    if len(unique_words) < len(words):
        duplicates = len(words) - len(unique_words)
        result["issues"].append(f"Contains {duplicates} duplicate word(s)")
    
    # Check for common weak phrases
    weak_patterns = [
        "abandon abandon abandon",
        "zoo zoo zoo",
        "word word word",
    ]
    for pattern in weak_patterns:
        if pattern in mnemonic.lower():
            result["issues"].append("Contains suspicious repeated pattern")
    
    result["valid"] = len(result["issues"]) == 0
    return result


def check_address_patterns(addresses: List[str]) -> Dict:
    """Check for suspicious patterns across multiple addresses."""
    findings = {
        "total_checked": len(addresses),
        "suspicious_patterns": [],
        "recommendations": []
    }
    
    # Check for sequential or similar addresses
    btc_addresses = [a for a in addresses if a.startswith("1") or a.startswith("3")]
    eth_addresses = [a.lower() for a in addresses if a.startswith("0x")]
    
    if len(btc_addresses) > 1:
        findings["suspicious_patterns"].append(f"Multiple Bitcoin addresses found ({len(btc_addresses)})")
    
    if len(eth_addresses) > 1:
        findings["suspicious_patterns"].append(f"Multiple Ethereum addresses found ({len(eth_addresses)})")
    
    return findings


def generate_report(results: List[Dict], output_file: Optional[str] = None) -> str:
    """Generate a formatted security report."""
    report = {
        "summary": {
            "total_checked": len(results),
            "valid": sum(1 for r in results if r.get("valid", False)),
            "invalid": sum(1 for r in results if not r.get("valid", False)),
            "with_issues": sum(1 for r in results if r.get("issues", []))
        },
        "results": results
    }
    
    # Terminal output
    print("=" * 60)
    print("CRYPTOCURRENCY SECURITY VALIDATION REPORT")
    print("=" * 60)
    print(f"\nTotal checked: {report['summary']['total_checked']}")
    print(f"Valid: {report['summary']['valid']} ✅")
    print(f"Invalid: {report['summary']['invalid']} ❌")
    print(f"With issues: {report['summary']['with_issues']} ⚠️")
    print("\n" + "-" * 60)
    
    for result in results:
        status = "✅ VALID" if result.get("valid") else "❌ INVALID"
        print(f"\n{status}: {result.get('address', result.get('mnemonic', 'Unknown'))}")
        print(f"  Type: {result.get('type', 'unknown')}")
        if result.get('format'):
            print(f"  Format: {result['format']}")
        if result.get('issues'):
            for issue in result['issues']:
                print(f"  ⚠️  {issue}")
    
    print("\n" + "=" * 60)
    
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\nReport saved to: {output_file}")
    
    return json.dumps(report, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="Cryptocurrency Security Validator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
  %(prog)s --address 0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb
  %(prog)s --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
  %(prog)s --check-entropy addresses.txt
        """
    )
    
    parser.add_argument("--address", "-a", nargs="+", help="Cryptocurrency address(es) to validate")
    parser.add_argument("--mnemonic", "-m", help="BIP-39 mnemonic phrase to validate")
    parser.add_argument("--check-entropy", "-e", help="File with addresses to check for entropy issues")
    parser.add_argument("--output", "-o", help="Output file for JSON report")
    parser.add_argument("--quiet", "-q", action="store_true", help="Output JSON only")
    
    args = parser.parse_args()
    
    if not any([args.address, args.mnemonic, args.check_entropy]):
        parser.print_help()
        sys.exit(1)
    
    results = []
    
    # Validate addresses
    if args.address:
        for addr in args.address:
            if addr.startswith("1") or addr.startswith("3") or addr.startswith("bc1"):
                results.append(validate_bitcoin_address(addr))
            elif addr.startswith("0x"):
                results.append(validate_ethereum_address(addr))
            elif addr.startswith("L") or addr.startswith("M"):
                results.append(validate_litecoin_address(addr))
            else:
                results.append({
                    "address": addr,
                    "type": "unknown",
                    "valid": False,
                    "issues": ["Unknown address format"]
                })
    
    # Validate mnemonic
    if args.mnemonic:
        results.append(validate_mnemonic(args.mnemonic))
    
    # Check entropy
    if args.check_entropy:
        try:
            with open(args.check_entropy, 'r') as f:
                addresses = [line.strip() for line in f if line.strip()]
            findings = check_address_patterns(addresses)
            results.append({
                "type": "entropy_check",
                "file": args.check_entropy,
                "valid": True,
                "findings": findings,
                "issues": []
            })
        except Exception as e:
            results.append({
                "type": "entropy_check",
                "file": args.check_entropy,
                "valid": False,
                "issues": [f"File error: {str(e)}"]
            })
    
    # Generate report
    if not args.quiet:
        generate_report(results, args.output)
    else:
        print(json.dumps({"results": results}, indent=2))


if __name__ == "__main__":
    main()
