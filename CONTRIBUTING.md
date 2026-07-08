# Contributing to OpenClaw CyberSecurity Skills

Thank you for your interest in contributing! This project aims to provide production-quality cybersecurity skills for the OpenClaw ecosystem.

## How to Contribute

### Reporting Issues

- **Skill not working?** Open an issue with:
  - Skill name and version
  - What you expected to happen
  - What actually happened (error messages, output)
  - Your environment (OS, Python version, OpenClaw version)

- **Script error?** Include:
  - The exact command you ran
  - Full error traceback
  - Sample input (if applicable)

- **Documentation unclear?** Tell us which part was confusing and what would help.

### Adding New Skills

1. **Create a new directory** under `skills/` with a descriptive name
2. **Write `SKILL.md`** following the format:
   ```markdown
   ---
   name: "skill-name"
   description: "Short noun-phrase description."
   ---

   # Skill Title

   ## When to Use
   Brief trigger description.

   ## Workflow
   1. Step one.
   2. Step two.

   ## Scripts
   - `scripts/script.py` — What it does.

   ## Output
   Expected artifacts.
   ```

3. **Add scripts** to `scripts/` — standalone, well-documented, no hardcoded paths
4. **Validate YAML:**
   ```bash
   python -c "import yaml; yaml.safe_load(open('SKILL.md').read().split('---',2)[1])"
   ```
5. **Test your scripts** — ensure they run without errors on sample data
6. **Security audit** — check for malicious patterns (see below)
7. **Submit a PR** with:
   - Description of the skill and its purpose
   - Test results
   - Any dependencies needed

### Improving Existing Skills

- **Fix bugs:** Open an issue first, then submit a PR
- **Add features:** Discuss in an issue before implementing
- **Improve documentation:** PRs welcome for clarity improvements
- **Add scripts:** Extend existing skills with new standalone tools

### Security Requirements

All scripts must pass this audit:

```python
# Check for dangerous patterns
SUSPICIOUS = ['os.system', 'os.popen', 'subprocess.call', 
              'eval(', 'exec(', '__import__', 'pickle.loads']
```

- No shell command execution via string interpolation
- No `eval()` or `exec()` on untrusted input
- No network calls to hardcoded IPs (use parameters)
- All file operations use safe paths (no `/tmp/` hardcoding)
- Proper authorization checks for offensive capabilities

### Code Style

- Python 3.10+ compatible
- Use type hints where practical
- Include docstrings for modules and functions
- Add logging, not print statements
- Use `argparse` for CLI scripts
- Handle errors gracefully with try/except

### Skill Naming

- Use lowercase with hyphens: `threat-hunting`, `cloud-security`
- Keep it descriptive: `log-analysis` not `logs`
- Avoid abbreviations: `incident-response` not `ir`

### Commit Messages

```
Add network-pcap-analyzer script
Fix false positive in subdomain_enum.py
Update blue-team-defense with Windows support
Document installation steps for macOS
```

## Development Setup

```bash
git clone https://github.com/YOUR-USER/openclaw-cybersecurity-skills.git
cd openclaw-cybersecurity-skills

# Validate all skill frontmatter
python -c "
import yaml
from pathlib import Path
for p in Path('skills').glob('*/SKILL.md'):
    fm = p.read_text().split('---',2)[1]
    yaml.safe_load(fm)
    print(f'✅ {p.parent.name}')
"

# Test scripts compile
python -m compileall skills/*/scripts/
```

## Questions?

- Open a discussion for general questions
- Open an issue for bugs or feature requests
- Tag with `@maintainers` if no response in 7 days

## Code of Conduct

- Be respectful and professional
- Assume good intent
- Focus on the work, not the person
- Help others learn

Thank you for contributing to the OpenClaw security community!
