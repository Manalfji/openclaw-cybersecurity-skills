---
name: "reverse-engineering"
description: "Binary analysis, firmware reverse engineering, assembly interpretation, and protocol RE."
---

# Reverse Engineering & Binary Analysis

## When to Use
Analyzing ELF/PE/Mach-O binaries, firmware, embedded devices, or unknown protocols. Supports CTF reversing and malware deep-dive.

## Workflow
1. Triage the binary: file type, architecture, entropy, strings, imports.
2. Run `binary_analyzer.py` for automated static analysis.
3. Inspect disassembly/decompiler output for logic and vulnerabilities.
4. For firmware: extract with binwalk, inspect filesystem, locate credentials and keys.
5. For protocols: analyze packet structure, identify fields, build parser.

## Scripts
- `scripts/binary_analyzer.py` — ELF/PE static analysis, entropy calculation, string extraction, import/export enumeration, security feature detection.

## Usage
```bash
# Full analysis
python scripts/binary_analyzer.py --file malware.exe --output analysis.json

# Strings and imports only
python scripts/binary_analyzer.py --file binary --strings --imports

# Entropy check
python scripts/binary_analyzer.py --file firmware.bin --entropy
```

## Output
- JSON report with file metadata, section info, symbols, security features, and entropy assessment.
