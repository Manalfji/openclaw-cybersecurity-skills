#!/usr/bin/env python3
"""
Honeytoken Generator
Creates fake credentials, tokens, and credentials for deception.

Usage:
    python3 honeytoken_generator.py --type aws --output tokens.json
    python3 honeytoken_generator.py --type github --count 5
"""

import argparse
import json
import secrets
import string
from datetime import datetime
from pathlib import Path


def generate_aws_credentials():
    """Generate fake AWS credentials."""
    return {
        "type": "aws",
        "access_key_id": f"AKIA{secrets.token_hex(8).upper()}",
        "secret_access_key": secrets.token_hex(32),
        "region": "us-east-1",
        "note": "HONEYTOKEN - Do not use"
    }


def generate_github_token():
    """Generate fake GitHub personal access token."""
    return {
        "type": "github",
        "token": f"ghp_{secrets.token_hex(18)}",
        "scopes": ["repo", "read:org"],
        "note": "HONEYTOKEN - Do not use"
    }


def generate_database_credentials():
    """Generate fake database credentials."""
    return {
        "type": "database",
        "username": f"honeyuser_{secrets.token_hex(4)}",
        "password": secrets.token_urlsafe(16),
        "host": "honeydb.internal.example.com",
        "port": 5432,
        "database": "production",
        "note": "HONEYTOKEN - Do not use"
    }


def generate_api_key():
    """Generate fake API key."""
    return {
        "type": "api_key",
        "key": secrets.token_urlsafe(32),
        "service": "internal-api",
        "permissions": ["read", "write"],
        "note": "HONEYTOKEN - Do not use"
    }


def generate_honeytokens(token_type, count=1):
    """Generate honeytokens of specified type."""
    generators = {
        "aws": generate_aws_credentials,
        "github": generate_github_token,
        "database": generate_database_credentials,
        "api": generate_api_key
    }
    
    if token_type not in generators:
        return {"error": f"Unknown token type: {token_type}. Supported: {', '.join(generators.keys())}"}
    
    tokens = []
    for _ in range(count):
        token = generators[token_type]()
        token["id"] = f"HT-{secrets.token_hex(4).upper()}"
        token["created"] = datetime.now().isoformat()
        token["status"] = "active"
        tokens.append(token)
    
    return tokens


def generate_deployment_guide(tokens, output_file=None):
    """Generate deployment guide for honeytokens."""
    guide = {
        "title": "Honeytoken Deployment Guide",
        "generated": datetime.now().isoformat(),
        "warnings": [
            "These tokens are DECEPTIVE and should not grant actual access",
            "Deploy in locations where unauthorized access would be suspicious",
            "Monitor for usage of these tokens via SIEM or logging",
            "Rotate tokens regularly"
        ],
        "deployment_suggestions": [
            "AWS credentials: ~/.aws/credentials (on shared systems)",
            "GitHub tokens: .env files in repositories",
            "Database credentials: config files, environment variables",
            "API keys: Mobile app binaries, client-side code"
        ],
        "tokens": tokens
    }
    
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(guide, f, indent=2)
        print(f"[+] Deployment guide saved to: {output_file}")
    else:
        print(json.dumps(guide, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description="Honeytoken Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --type aws --count 5 --output tokens.json
  %(prog)s --type database --output db_credentials.json
  %(prog)s --type github --count 10 --output github_tokens.json
        """
    )
    
    parser.add_argument("--type", "-t", 
                       choices=["aws", "github", "database", "api"],
                       required=True,
                       help="Type of honeytoken to generate")
    parser.add_argument("--count", "-c", type=int, default=1, help="Number of tokens to generate")
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--guide", "-g", action="store_true", help="Generate deployment guide")
    
    args = parser.parse_args()
    
    print(f"[*] Generating {args.count} {args.type} honeytoken(s)...")
    
    tokens = generate_honeytokens(args.type, args.count)
    
    if "error" in tokens:
        print(f"[ERROR] {tokens['error']}")
        return 1
    
    print(f"[+] Generated {len(tokens)} honeytoken(s)")
    
    if args.guide:
        generate_deployment_guide(tokens, args.output)
    else:
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(tokens, f, indent=2)
            print(f"[+] Tokens saved to: {args.output}")
        else:
            print(json.dumps(tokens, indent=2))
    
    print("\n[!] IMPORTANT: These tokens are DECEPTIVE and should not grant actual access")
    print("[!] Monitor for unauthorized usage via logging and SIEM")
    
    return 0


if __name__ == "__main__":
    main()
