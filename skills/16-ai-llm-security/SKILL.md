---
name: "ai-llm-security"
description: "LLM and AI application security testing, prompt injection, OWASP LLM Top 10, RAG and agent security, model supply chain, and AI red teaming."
---

# AI & LLM Security

## When to Use
Assessing security of AI/LLM-powered applications: chatbots, RAG pipelines, autonomous agents, tool-using systems, and model supply chains.

## Workflow
1. Threat model against OWASP LLM Top 10 (2025) and MITRE ATLAS — per-category exposure, evidence, severity, mitigation.
2. Test prompt injection (direct and indirect) and jailbreak resistance across multiple obfuscation families.
3. Review RAG pipeline: access control at retrieval, indirect injection surface, embedding inversion, chunk poisoning, citation integrity.
4. Review agent/tool-use security: least-privilege tools, human-in-the-loop gates, argument validation, MCP server hardening, memory poisoning.
5. Scan model artifacts for unsafe deserialization (pickle, .pt, .bin) and verify provenance.
6. Validate output handling: no raw LLM output into eval/SQL/shell/innerHTML; layered guardrails; strict schema validation.

## Scripts
- `scripts/prompt_injection_tester.py` — Authorized prompt-injection/jailbreak test harness. Sends a payload corpus to a chat endpoint and scores BLOCKED/PARTIAL/SUCCESS.
- `scripts/model_supply_chain.py` — Scan ML model files for load-time code execution risk (pickle opcodes, unsafe formats vs. safetensors). Maps to OWASP LLM03.

## Output
- AI security assessment with OWASP LLM Top 10 coverage table.
- Confirmed findings with ATLAS IDs, reproduction steps, impact, and mitigations.
- Guardrail bypass matrix.
- Model supply chain scan JSON.

## Prerequisites
```bash
pip install requests pyyaml rich
```

**Optional:** garak, promptfoo, modelscan, picklescan

## References
- OWASP Top 10 for LLM Applications (2025)
- MITRE ATLAS
- NIST AI Risk Management Framework (AI RMF 1.0) + Generative AI Profile
- OWASP Agentic AI — Threats and Mitigations
- Google SAIF — Secure AI Framework
- NVIDIA garak
