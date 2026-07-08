#!/usr/bin/env python3
"""
Honeypot Log Analyzer
Analyzes honeypot logs to identify attacker behavior and TTPs.

Usage:
    python3 honeypot_log_analyzer.py --logs /var/log/honeypot/ --output report.json
    python3 honeypot_log_analyzer.py --log auth.log --interactive
"""

import argparse
import json
import re
from datetime import datetime
from pathlib import Path
from collections import Counter, defaultdict


def parse_ssh_log(log_line):
    """Parse SSH honeypot log entries."""
    patterns = {
        "failed_password": re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)"),
        "accepted_password": re.compile(r"Accepted password for (\S+) from (\S+) port (\d+)"),
        "connection": re.compile(r"Connection from (\S+) port (\d+)"),
        "command": re.compile(r"Command: (.+)"),
    }
    
    for event_type, pattern in patterns.items():
        match = pattern.search(log_line)
        if match:
            return {
                "event_type": event_type,
                "timestamp": datetime.now().isoformat(),
                "details": match.groups()
            }
    
    return None


def parse_http_log(log_line):
    """Parse HTTP honeypot log entries."""
    # Simple HTTP log parsing
    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', log_line)
    path_match = re.search(r'"(?:GET|POST|PUT|DELETE) ([^"]+) HTTP', log_line)
    
    if ip_match:
        return {
            "event_type": "http_request",
            "timestamp": datetime.now().isoformat(),
            "ip": ip_match.group(1),
            "path": path_match.group(1) if path_match else "unknown",
            "raw": log_line.strip()
        }
    
    return None


def analyze_logs(log_directory):
    """Analyze honeypot logs for attacker behavior."""
    findings = {
        "scan_summary": {
            "total_events": 0,
            "unique_ips": set(),
            "unique_usernames": set(),
            "attack_types": Counter()
        },
        "attacker_behavior": [],
        "timelines": defaultdict(list),
        "recommendations": []
    }
    
    log_path = Path(log_directory)
    
    if not log_path.exists():
        return {"error": f"Log directory not found: {log_directory}"}
    
    # Process all log files
    for log_file in log_path.glob("*.log"):
        with open(log_file, 'r') as f:
            for line in f:
                findings["scan_summary"]["total_events"] += 1
                
                # Try SSH parsing first
                event = parse_ssh_log(line)
                if not event:
                    # Try HTTP parsing
                    event = parse_http_log(line)
                
                if event:
                    if "ip" in event:
                        findings["scan_summary"]["unique_ips"].add(event["ip"])
                    
                    if event["event_type"] == "failed_password":
                        username = event["details"][0]
                        findings["scan_summary"]["unique_usernames"].add(username)
                        findings["attack_types"]["brute_force"] += 1
                    
                    findings["attacker_behavior"].append(event)
    
    # Convert sets to lists for JSON serialization
    findings["scan_summary"]["unique_ips"] = list(findings["scan_summary"]["unique_ips"])
    findings["scan_summary"]["unique_usernames"] = list(findings["scan_summary"]["unique_usernames"])
    
    # Generate recommendations
    if findings["attack_types"]["brute_force"] > 10:
        findings["recommendations"].append("Consider blocking IPs with repeated failed passwords")
    
    if len(findings["scan_summary"]["unique_ips"]) > 5:
        findings["recommendations"].append("Distributed scan detected — consider rate limiting")
    
    return findings


def generate_report(findings, output_file=None):
    """Generate honeypot analysis report."""
    report = {
        "generated": datetime.now().isoformat(),
        "tool": "honeypot_log_analyzer.py",
        "version": "1.0.0",
        "summary": {
            "total_events": findings["scan_summary"]["total_events"],
            "unique_attackers": len(findings["scan_summary"]["unique_ips"]),
            "unique_usernames": len(findings["scan_summary"]["unique_usernames"]),
            "attack_types": dict(findings["attack_types"])
        },
        "attacker_behavior": findings["attacker_behavior"][:100],  # Limit to first 100
        "recommendations": findings["recommendations"]
    }
    
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report saved to: {output_file}")
    else:
        print(json.dumps(report, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description="Honeypot Log Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --logs /var/log/honeypot/ --output report.json
  %(prog)s --log /var/log/honeypot/auth.log --interactive
        """
    )
    
    parser.add_argument("--logs", "-l", help="Directory containing honeypot logs")
    parser.add_argument("--log", help="Single log file to analyze")
    parser.add_argument("--output", "-o", help="Output JSON report")
    parser.add_argument("--interactive", "-i", action="store_true", help="Interactive mode")
    
    args = parser.parse_args()
    
    if not args.logs and not args.log:
        parser.error("Must specify --logs or --log")
    
    log_source = args.logs or args.log
    
    print(f"[*] Analyzing honeypot logs: {log_source}")
    
    findings = analyze_logs(log_source)
    
    if "error" in findings:
        print(f"[ERROR] {findings['error']}")
        return 1
    
    print(f"[*] Total events: {findings['scan_summary']['total_events']}")
    print(f"[*] Unique attackers: {len(findings['scan_summary']['unique_ips'])}")
    print(f"[*] Unique usernames: {len(findings['scan_summary']['unique_usernames'])}")
    
    generate_report(findings, args.output)
    
    if args.interactive:
        print("\n[*] Interactive mode:")
        print(f"    Top usernames attempted: {findings['scan_summary']['unique_usernames'][:10]}")
        print(f"    Top attacker IPs: {findings['scan_summary']['unique_ips'][:10]}")
    
    return 0


if __name__ == "__main__":
    main()
