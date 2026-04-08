# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
Versioning: [Semantic Versioning](https://semver.org/)

---

## [Unreleased]

---

## [0.1.0] — 2026-04-07 — Initial Release

### Added

**Core scanner**
- Phase 1: Async endpoint discovery — 40+ known LLM API paths
- Phase 2: Provider ID — HTTP header + error body fingerprinting (8 providers)
- Phase 3: Model fingerprinting — behavioural probe scoring, 31 probes, 5 packs
- Phase 4: Capability enumeration — function calling, vision, JSON mode, streaming
- Phase 5: Safety guard detection — adversarial probe refusal rates, system prompt check
- Phase 6: Vulnerability scan — OWASP LLM Top 10 (LLM01, LLM02, LLM04, LLM06, LLM07)

**CLI (Nmap-style flags)**
- `-sn` `-sV` `-A` `--script` (guards/capabilities/vuln/extract/all)
- `-T0–5` timing templates (paranoid → insane)
- `-oN` `-oJ` `-oG` `-oX` `-oA` output formats
- `--api-key` `--model` `--probe-dir` `--list-probes` `-p` `--open` `-v/-vv`
- Auto-detection: localhost/private IPs → `http://`, cloud APIs → `https://`
- Binary installed as `llm-sneak` — no `python3` prefix needed

**Probe packs (YAML)**
- `quirks.yaml` — 11 universal behavioural quirk probes
- `openai.yaml` — 5 GPT family probes (gpt-4o, gpt-4-turbo, gpt-3.5, o1)
- `anthropic.yaml` — 6 Claude family probes (opus, sonnet, haiku)
- `google.yaml` — 4 Gemini family probes (gemini-2.0, 1.5-pro, 1.5-flash)
- `meta.yaml` — 5 LLaMA + Mistral probes (llama3, mistral, mixtral, phi)

**Vulnerability probes (Phase 6)**
- LLM01: 6 prompt injection probes (direct, indirect, role-switch, delimiter, markdown)
- LLM02: 4 output handling probes (XSS, SQL, path traversal, code execution)
- LLM04: 2 DoS probes (unbounded repetition, empty input)
- LLM06: 4 info disclosure probes (env vars, API keys, internal URLs, stack traces)
- LLM07: 2 tool abuse probes (SSRF via cloud metadata, filesystem read)

**Project / Community**
- MIT licence
- CONTRIBUTING.md with full probe pack authoring guide (no Python required)
- CREDITS.md with exhaustive attribution (Nmap, OWASP, Garak, PyRIT, 9 research papers)
- CODE_OF_CONDUCT.md (Contributor Covenant v2.1)
- SECURITY.md with responsible disclosure policy
- CHANGELOG.md
- GitHub CI workflow (pytest + ruff + probe pack validation on every PR)
- Issue templates: bug report, feature request, probe pack submission
- PR template
- TESTING.md — full test guide for Ollama, OpenAI, Anthropic, LM Studio
- install.sh one-liner installer with ASCII banner
- Makefile: `make install` / `make install-dev` / `make poetry` / `make test` / `make clean`
- pyproject.toml: pip + Poetry compatible

[Unreleased]: https://github.com/safellm/llm-sneak/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/safellm/llm-sneak/releases/tag/v0.1.0
