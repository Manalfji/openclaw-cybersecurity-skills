#!/usr/bin/env python3
"""
Canary Deployer
Deploys canary files and monitors for unauthorized access.

Usage:
    python3 canary_deployer.py --deploy /sensitive/path --name "salaries.xlsx"
    python3 canary_deployer.py --check /var/log/audit.log
"""

import argparse
import hashlib
import json
import os
from datetime import datetime
from pathlib import Path


def create_canary_file(filepath, content=None):
    """Create a canary file with deceptive content."""
    if content is None:
        content = f"""
CONFIDENTIAL - DO NOT DISTRIBUTE

Employee Salary Information - Q4 2024
======================================

This document contains sensitive financial information.
Unauthorized access is strictly prohibited and will be prosecuted.

NOTICE: This is a CANARY file for security monitoring.
Access to this file indicates unauthorized system access.
Alert ID: CANARY-{datetime.now().strftime('%Y%m%d-%H%M%S')}

Contact: security@example.com
"""
    
    try:
        with open(filepath, 'w') as f:
            f.write(content)
        
        # Set permissions to be readable but trackable
        os.chmod(filepath, 0o644)
        
        return {
            "status": "created",
            "path": str(filepath),
            "size": len(content),
            "hash": hashlib.sha256(content.encode()).hexdigest()
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


def create_canary_database_entry(db_config=None):
    """Create fake database entries that act as canaries."""
    if db_config is None:
        db_config = {
            "host": "db.internal.company.com",
            "database": "customers",
            "table": "credit_cards",
            "note": "CANARY - Do not use"
        }
    
    return {
        "type": "database",
        "config": db_config,
        "status": "created",
        "alert_on": ["SELECT", "INSERT", "UPDATE", "DELETE"]
    }


def check_canary_access(log_file, canary_files):
    """Check logs for unauthorized access to canary files."""
    alerts = []
    
    try:
        with open(log_file, 'r') as f:
            for line in f:
                for canary in canary_files:
                    if canary in line:
                        alerts.append({
                            "timestamp": datetime.now().isoformat(),
                            "canary": canary,
                            "log_entry": line.strip(),
                            "severity": "HIGH",
                            "message": f"Unauthorized access to canary file detected: {canary}"
                        })
    except FileNotFoundError:
        return {"error": f"Log file not found: {log_file}"}
    
    return alerts


def generate_deployment_report(deployments, output_file=None):
    """Generate canary deployment report."""
    report = {
        "generated": datetime.now().isoformat(),
        "tool": "canary_deployer.py",
        "version": "1.0.0",
        "total_canaries": len(deployments),
        "deployments": deployments,
        "monitoring_instructions": [
            "Monitor SIEM for access to these files",
            "Set up alerts for file read events",
            "Review access logs regularly",
            "Rotate canary files monthly"
        ]
    }
    
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report saved to: {output_file}")
    else:
        print(json.dumps(report, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description="Canary Deployer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --deploy /shared/finance --name "salaries_Q4.xlsx"
  %(prog)s --deploy /tmp --name "credentials.csv" --content "fake content"
  %(prog)s --check /var/log/audit.log --canaries /shared/finance/salaries_Q4.xlsx
        """
    )
    
    parser.add_argument("--deploy", "-d", help="Directory to deploy canary file")
    parser.add_argument("--name", "-n", default="confidential_data.xlsx", help="Canary filename")
    parser.add_argument("--content", "-c", help="Custom canary content")
    parser.add_argument("--check", help="Check logs for canary access")
    parser.add_argument("--canaries", nargs="+", help="List of canary files to monitor")
    parser.add_argument("--output", "-o", help="Output JSON report")
    
    args = parser.parse_args()
    
    deployments = []
    
    if args.deploy:
        deploy_path = Path(args.deploy)
        if not deploy_path.exists():
            print(f"[*] Creating directory: {args.deploy}")
            deploy_path.mkdir(parents=True, exist_ok=True)
        
        canary_path = deploy_path / args.name
        print(f"[*] Deploying canary: {canary_path}")
        
        result = create_canary_file(canary_path, args.content)
        deployments.append(result)
        
        if result["status"] == "created":
            print(f"[+] Canary deployed: {canary_path}")
            print(f"[+] SHA256: {result['hash']}")
            print(f"[!] Monitor for unauthorized access to this file")
        else:
            print(f"[ERROR] Failed to deploy: {result.get('error')}")
    
    if args.check and args.canaries:
        print(f"[*] Checking logs for canary access...")
        alerts = check_canary_access(args.check, args.canaries)
        
        if isinstance(alerts, dict) and "error" in alerts:
            print(f"[ERROR] {alerts['error']}")
            return 1
        
        print(f"[*] Found {len(alerts)} alert(s)")
        for alert in alerts:
            print(f"[!] ALERT: {alert['message']}")
            print(f"    Time: {alert['timestamp']}")
            print(f"    Log: {alert['log_entry'][:100]}...")
    
    if deployments:
        generate_deployment_report(deployments, args.output)
    
    return 0


if __name__ == "__main__":
    main()
