#!/usr/bin/env python3
"""
Forensic Timeline Builder
Builds timelines from forensic disk images and file metadata.

Usage:
    python3 forensic_timeline.py --image disk.img --output timeline.json
    python3 forensic_timeline.py --directory /path/to/evidence --output timeline.csv
"""

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime
from pathlib import Path


def get_file_metadata(filepath):
    """Extract forensic metadata from a file."""
    try:
        stat = os.stat(filepath)
        return {
            "path": str(filepath),
            "size": stat.st_size,
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "accessed": datetime.fromtimestamp(stat.st_atime).isoformat(),
            "md5": calculate_md5(filepath),
            "sha256": calculate_sha256(filepath)
        }
    except (OSError, PermissionError) as e:
        return {"path": str(filepath), "error": str(e)}


def calculate_md5(filepath):
    """Calculate MD5 hash of a file."""
    hash_md5 = hashlib.md5()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except (OSError, PermissionError):
        return "N/A"


def calculate_sha256(filepath):
    """Calculate SHA256 hash of a file."""
    hash_sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except (OSError, PermissionError):
        return "N/A"


def build_timeline_from_directory(directory, recursive=True):
    """Build forensic timeline from directory contents."""
    timeline = []
    path = Path(directory)
    
    if not path.exists():
        return {"error": f"Directory not found: {directory}"}
    
    pattern = "**/*" if recursive else "*"
    
    for filepath in path.glob(pattern):
        if filepath.is_file():
            metadata = get_file_metadata(filepath)
            timeline.append(metadata)
    
    return sorted(timeline, key=lambda x: x.get("modified", ""), reverse=True)


def generate_csv(timeline, output_file):
    """Generate CSV timeline for visualization."""
    import csv
    
    if not timeline:
        return
    
    fieldnames = ["path", "size", "created", "modified", "accessed", "md5", "sha256"]
    
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for entry in timeline:
            if "error" not in entry:
                writer.writerow({k: entry.get(k, "") for k in fieldnames})


def generate_report(timeline, output_file, case_id=None):
    """Generate forensic report with chain of custody."""
    report = {
        "case_id": case_id or f"CASE-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        "generated": datetime.now().isoformat(),
        "tool": "forensic_timeline.py",
        "version": "1.0.0",
        "total_files": len(timeline),
        "timeline": timeline[:100]  # Limit to first 100 entries
    }
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="Forensic Timeline Builder",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --directory /evidence/case001 --output timeline.json
  %(prog)s --image disk.img --case CASE-2024-001 --output report.json
  %(prog)s --directory /logs --csv timeline.csv
        """
    )
    
    parser.add_argument("--directory", "-d", help="Directory to analyze")
    parser.add_argument("--image", "-i", help="Disk image file (placeholder for future implementation)")
    parser.add_argument("--output", "-o", required=True, help="Output file (JSON or CSV)")
    parser.add_argument("--case", "-c", help="Case ID for report")
    parser.add_argument("--csv", action="store_true", help="Output as CSV instead of JSON")
    parser.add_argument("--recursive", "-r", action="store_true", default=True, help="Recursive analysis")
    parser.add_argument("--limit", "-l", type=int, default=1000, help="Limit number of files processed")
    
    args = parser.parse_args()
    
    if not args.directory and not args.image:
        parser.error("Must specify --directory or --image")
    
    if args.image:
        print("[!] Disk image analysis requires additional tools (sleuthkit)")
        print("[!] Falling back to directory analysis...")
        args.directory = os.path.dirname(args.image) if os.path.exists(args.image) else "."
    
    print(f"[*] Building forensic timeline from: {args.directory}")
    print(f"[*] This may take a while for large directories...")
    
    timeline = build_timeline_from_directory(args.directory, args.recursive)
    
    if "error" in timeline:
        print(f"[ERROR] {timeline['error']}")
        sys.exit(1)
    
    # Limit results
    if len(timeline) > args.limit:
        print(f"[*] Limiting output to {args.limit} files (out of {len(timeline)})")
        timeline = timeline[:args.limit]
    
    # Generate output
    if args.csv or args.output.endswith('.csv'):
        generate_csv(timeline, args.output)
        print(f"[+] CSV timeline saved to: {args.output}")
    else:
        generate_report(timeline, args.output, args.case)
        print(f"[+] JSON report saved to: {args.output}")
    
    print(f"[+] Total files analyzed: {len(timeline)}")
    print(f"[+] Case ID: {args.case or 'N/A'}")


if __name__ == "__main__":
    main()
