#!/usr/bin/env python3
"""
Memory Hunter - Analyze memory dumps for suspicious processes and artifacts.

Usage:
    python3 memory_hunter.py --dump memory.dmp --output analysis.json
    python3 memory_hunter.py --strings memory_strings.txt --output report.json
"""

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path


def analyze_strings_file(strings_file):
    """Analyze strings extracted from memory dump."""
    findings = {
        "suspicious_processes": [],
        "network_indicators": [],
        "file_paths": [],
        "registry_keys": [],
        "api_calls": [],
        "timestamps": []
    }
    
    # Patterns to search for
    patterns = {
        "ip_addresses": re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
        "domains": re.compile(r'[a-zA-Z0-9-]+\.(?:com|net|org|io|top|xyz|click|download)'),
        "file_paths": re.compile(r'[C-Z]:\\(?:[^\\]+\\)*[^\\]+\.(?:exe|dll|bat|ps1|vbs)'),
        "registry_keys": re.compile(r'HKEY_[A-Z_]+\\[^\s]+'),
        "suspicious_apis": re.compile(r'(?:VirtualAlloc|WriteProcessMemory|CreateRemoteThread|NtUnmapViewOfSection)'),
        "timestamps": re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}')
    }
    
    try:
        with open(strings_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
            # Extract IP addresses
            ips = set(patterns["ip_addresses"].findall(content))
            for ip in list(ips)[:50]:  # Limit to first 50
                findings["network_indicators"].append({
                    "type": "ip_address",
                    "value": ip,
                    "context": "Found in memory strings"
                })
            
            # Extract file paths
            paths = set(patterns["file_paths"].findall(content))
            for path in list(paths)[:50]:
                findings["file_paths"].append({
                    "path": path,
                    "suspicious": any(kw in path.lower() for kw in ['temp', 'tmp', 'appdata', 'startup'])
                })
            
            # Extract registry keys
            reg_keys = set(patterns["registry_keys"].findall(content))
            for key in list(reg_keys)[:30]:
                findings["registry_keys"].append({
                    "key": key,
                    "hive": key.split('\\')[0] if '\\' in key else "Unknown"
                })
            
            # Extract suspicious API calls
            apis = set(patterns["suspicious_apis"].findall(content))
            for api in apis:
                findings["api_calls"].append({
                    "api": api,
                    "risk": "HIGH" if api in ['CreateRemoteThread', 'NtUnmapViewOfSection'] else "MEDIUM"
                })
            
            # Extract timestamps
            timestamps = set(patterns["timestamps"].findall(content))
            for ts in list(timestamps)[:20]:
                findings["timestamps"].append(ts)
    
    except Exception as e:
        findings["error"] = str(e)
    
    return findings


def generate_report(findings, output_file, case_id=None):
    """Generate forensic memory analysis report."""
    report = {
        "case_id": case_id or f"MEM-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        "generated": datetime.now().isoformat(),
        "tool": "memory_hunter.py",
        "version": "1.0.0",
        "summary": {
            "suspicious_processes": len(findings["suspicious_processes"]),
            "network_indicators": len(findings["network_indicators"]),
            "file_paths": len(findings["file_paths"]),
            "registry_keys": len(findings["registry_keys"]),
            "api_calls": len(findings["api_calls"])
        },
        "findings": findings
    }
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="Memory Hunter - Analyze memory dumps for suspicious artifacts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --strings memory_strings.txt --output analysis.json
  %(prog)s --dump memory.dmp --case CASE-001 --output report.json
        """
    )
    
    parser.add_argument("--strings", "-s", help="Strings file from memory dump")
    parser.add_argument("--dump", "-d", help="Memory dump file (requires volatility - placeholder)")
    parser.add_argument("--output", "-o", required=True, help="Output JSON report")
    parser.add_argument("--case", "-c", help="Case ID")
    
    args = parser.parse_args()
    
    if not args.strings and not args.dump:
        parser.error("Must specify --strings or --dump")
    
    if args.dump:
        print("[!] Full memory dump analysis requires Volatility 3")
        print("[!] Please extract strings first: strings -n 8 memory.dmp > strings.txt")
        print("[!] Falling back to strings analysis if available...")
        if not args.strings:
            print("[ERROR] No strings file provided")
            sys.exit(1)
    
    print(f"[*] Analyzing memory strings: {args.strings}")
    
    findings = analyze_strings_file(args.strings)
    
    if "error" in findings:
        print(f"[ERROR] {findings['error']}")
        sys.exit(1)
    
    generate_report(findings, args.output, args.case)
    
    print(f"[+] Analysis complete. Report saved to: {args.output}")
    print(f"[+] Network indicators found: {len(findings['network_indicators'])}")
    print(f"[+] File paths found: {len(findings['file_paths'])}")
    print(f"[+] Registry keys found: {len(findings['registry_keys'])}")
    print(f"[+] Suspicious API calls: {len(findings['api_calls'])}")


if __name__ == "__main__":
    main()
