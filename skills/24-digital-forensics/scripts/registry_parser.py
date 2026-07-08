#!/usr/bin/env python3
"""
Windows Registry Parser
Extracts forensic artifacts from Windows registry hives.

Usage:
    python3 registry_parser.py --hive NTUSER.DAT --output artifacts.json
    python3 registry_parser.py --hive SYSTEM --artifacts usb --output usb_history.json
"""

import argparse
import json
import struct
from datetime import datetime, timedelta
from pathlib import Path


def parse_windows_timestamp(timestamp):
    """Convert Windows FILETIME to datetime."""
    try:
        # Windows FILETIME is 100-nanosecond intervals since 1601-01-01
        return datetime(1601, 1, 1) + timedelta(microseconds=timestamp / 10)
    except:
        return None


def extract_registry_artifacts(hive_path, artifact_type="all"):
    """Extract forensic artifacts from registry hive."""
    artifacts = {
        "hive": str(hive_path),
        "extracted": datetime.now().isoformat(),
        "user_activity": [],
        "usb_devices": [],
        "network_connections": [],
        "persistence_mechanisms": [],
        "errors": []
    }
    
    try:
        with open(hive_path, 'rb') as f:
            # Check for valid registry hive signature
            header = f.read(4)
            if header != b'regf':
                artifacts["errors"].append("Invalid registry hive signature")
                return artifacts
            
            # Basic registry parsing (simplified for demonstration)
            # In production, use python-registry or similar library
            f.seek(0)
            data = f.read()
            
            # Search for common forensic patterns
            if artifact_type in ["all", "usb"]:
                # USB device history artifacts
                usb_patterns = [b'USBSTOR', b'USB\\VID_', b'Disk&Ven_']
                for pattern in usb_patterns:
                    if pattern in data:
                        artifacts["usb_devices"].append({
                            "indicator": pattern.decode('ascii', errors='ignore'),
                            "offset": data.index(pattern),
                            "note": "USB device connection indicator"
                        })
            
            if artifact_type in ["all", "network"]:
                # Network connection artifacts
                network_patterns = [b'MruPidlList', b'ProfileImagePath', b'Tcpip']
                for pattern in network_patterns:
                    if pattern in data:
                        artifacts["network_connections"].append({
                            "indicator": pattern.decode('ascii', errors='ignore'),
                            "offset": data.index(pattern),
                            "note": "Network configuration artifact"
                        })
            
            if artifact_type in ["all", "persistence"]:
                # Persistence mechanism artifacts
                persistence_patterns = [b'Run', b'RunOnce', b'Shell', b'Userinit']
                for pattern in persistence_patterns:
                    if pattern in data:
                        artifacts["persistence_mechanisms"].append({
                            "indicator": pattern.decode('ascii', errors='ignore'),
                            "offset": data.index(pattern),
                            "note": "Potential persistence mechanism"
                        })
            
            # Extract readable strings as potential evidence
            strings = extract_strings(data)
            artifacts["extracted_strings"] = strings[:50]  # Limit to first 50
            
    except Exception as e:
        artifacts["errors"].append(str(e))
    
    return artifacts


def extract_strings(data, min_length=4):
    """Extract readable ASCII strings from binary data."""
    strings = []
    current = ""
    
    for byte in data:
        if 32 <= byte <= 126:
            current += chr(byte)
        else:
            if len(current) >= min_length:
                strings.append(current)
            current = ""
    
    if len(current) >= min_length:
        strings.append(current)
    
    return strings


def generate_report(artifacts, output_file, case_id=None):
    """Generate forensic registry analysis report."""
    report = {
        "case_id": case_id or f"REG-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        "generated": datetime.now().isoformat(),
        "tool": "registry_parser.py",
        "version": "1.0.0",
        "summary": {
            "total_artifacts": len(artifacts["user_activity"]) + 
                             len(artifacts["usb_devices"]) + 
                             len(artifacts["network_connections"]) + 
                             len(artifacts["persistence_mechanisms"]),
            "errors": len(artifacts["errors"])
        },
        "artifacts": artifacts
    }
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="Windows Registry Forensic Parser",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --hive NTUSER.DAT --output artifacts.json
  %(prog)s --hive SYSTEM --artifacts usb --output usb_history.json
  %(prog)s --hive SOFTWARE --artifacts persistence --output persistence.json
        """
    )
    
    parser.add_argument("--hive", "-i", required=True, help="Registry hive file to analyze")
    parser.add_argument("--artifacts", "-a", 
                       choices=["all", "usb", "network", "persistence", "user"],
                       default="all",
                       help="Type of artifacts to extract")
    parser.add_argument("--output", "-o", required=True, help="Output JSON report")
    parser.add_argument("--case", "-c", help="Case ID")
    
    args = parser.parse_args()
    
    if not Path(args.hive).exists():
        print(f"[ERROR] Hive file not found: {args.hive}")
        sys.exit(1)
    
    print(f"[*] Analyzing registry hive: {args.hive}")
    print(f"[*] Artifact type: {args.artifacts}")
    
    artifacts = extract_registry_artifacts(args.hive, args.artifacts)
    
    if artifacts["errors"]:
        print(f"[!] Warnings: {len(artifacts['errors'])}")
        for error in artifacts["errors"]:
            print(f"    - {error}")
    
    generate_report(artifacts, args.output, args.case)
    
    print(f"[+] Analysis complete. Report saved to: {args.output}")
    print(f"[+] USB devices found: {len(artifacts['usb_devices'])}")
    print(f"[+] Network artifacts found: {len(artifacts['network_connections'])}")
    print(f"[+] Persistence mechanisms found: {len(artifacts['persistence_mechanisms'])}")
    print(f"[+] Extracted strings: {len(artifacts.get('extracted_strings', []))}")


if __name__ == "__main__":
    main()
