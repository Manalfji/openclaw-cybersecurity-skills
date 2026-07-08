---
name: "digital-forensics"
description: "Digital forensics and evidence preservation for disk, memory, and log analysis."
---

# Digital Forensics & Evidence Preservation

## When to Use
- Investigating a security incident requiring legal admissibility
- Analyzing disk images for evidence of compromise
- Extracting forensic artifacts from memory dumps
- Preserving evidence chain-of-custody for regulatory investigations

## Workflow
1. **Evidence Identification** — Locate and catalog potential evidence sources
2. **Acquisition** — Create forensic images (dd, E01, AFF) with hash verification
3. **Analysis** — Extract timelines, registry artifacts, deleted files
4. **Memory Forensics** — Analyze RAM dumps for running processes, network connections
5. **Reporting** — Generate legally admissible reports with chain-of-custody

## Scripts
- `forensic_timeline.py` — Build forensic timelines from disk images
- `memory_hunter.py` — Analyze memory dumps for suspicious processes
- `registry_parser.py` — Extract Windows registry artifacts

## Output
- JSON forensic reports with timestamps and evidence hashes
- Timeline CSV files for visualization
- Chain-of-custody documentation

## Prerequisites
```bash
pip install python-registry
```

## Important Notes
- Always work on forensic copies, never original evidence
- Maintain chain-of-custody documentation
- Use write blockers when acquiring disk images
- Consult legal counsel before beginning forensic investigation

## Safety
- **Requires authorization** — Digital forensics may involve legal proceedings
- **Evidence integrity** — Any modification may compromise admissibility
- **Privacy considerations** — Handle personal data according to applicable laws
