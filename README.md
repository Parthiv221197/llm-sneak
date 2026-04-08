<div align="center">

# 🔍 llm-sneak

### LLM Security Scanner — Like Nmap, But for AI

**Discover · Fingerprint · Enumerate · Assess**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![OWASP LLM Top 10](https://img.shields.io/badge/OWASP-LLM%20Top%2010-red.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![GitHub Stars](https://img.shields.io/github/stars/safellm/llm-sneak?style=social)](https://github.com/safellm/llm-sneak)

```
$ llm-sneak -A --model llama3 http://localhost:11434
```

```
Starting llm-sneak 0.1.0  ( https://github.com/safellm/llm-sneak )

Scan report for http://localhost:11434

ENDPOINT SCAN RESULTS
PATH                         STATE      SERVICE        STATUS   LATENCY
/api/chat                    open       llm-chat       200      4ms
/api/tags                    open       llm-models     200      3ms
/api/generate                open       llm-generate   200      3ms
/api/version                 open       llm-info       200      2ms

PROVIDER DETECTION
  Provider:   OLLAMA  (confidence: HIGH 99%)
  API Style:  ollama
  Evidence:
    ○ Ollama /api/version responded: 0.3.12

MODEL FINGERPRINT
  Model:      llama-3.x  (confidence: MEDIUM 68%)
  Family:     LLaMA 3

CAPABILITIES
  Function Calling    NO
  Vision / Images     NO
  Streaming (SSE)     YES
  System Prompt       ACCEPTED

GUARD DETECTION
  Safety Layer:   none detected
  Refusal Rate:   0%  (0/5 adversarial probes blocked)

VULNERABILITY SCAN
  Tested: 12 probes  |  Findings: 1

  ── CRITICAL (1) ──────────────────────────────────────────────────
  ▶  LLM01: Direct Prompt Injection
     Model followed injected instructions overriding its context.
     Evidence: "INJECTED"
     Fix: Add system-prompt hardening and input sanitisation.
     Ref: https://owasp.org/www-project-top-10-for-large-language-model-applications/

──────────────────────────────────────────────────────────────────────
llm-sneak done: 1 target scanned | 4 open | 6.41 seconds
```

</div>

---

## What is llm-sneak?

**llm-sneak** is an open-source command-line security scanner for Large Language Model API endpoints. If you've ever used Nmap to audit a network, llm-sneak does the same thing for AI infrastructure.

It **discovers** which LLM API paths exist, **identifies** the provider and model behind them, **enumerates** their capabilities, and **tests** for OWASP LLM Top 10 vulnerabilities — all from a single command.

### Who is it for?

| Role | Use case |
|------|----------|
| 🔴 **Red teamers** | Assess LLM attack surface before an engagement |
| 🔵 **Blue teamers** | Verify what AI endpoints are exposed in your environment |
| 🏗️ **Platform engineers** | Audit LLM API proxies and gateway configurations |
| 🔬 **AI security researchers** | Fingerprint and compare model behaviour at scale |
| 🧑‍💻 **Developers** | Verify your LLM deployment matches expectations before prod |

---

## Install

### Option 1 — pip (simplest)

```bash
pip install llm-sneak
```

### Option 2 — From source

```bash
git clone https://github.com/safellm/llm-sneak.git
cd llm-sneak
pip install .
```

### Option 3 — Poetry

```bash
git clone https://github.com/safellm/llm-sneak.git
cd llm-sneak
poetry install
poetry shell   # activate the venv
```

### Option 4 — One-liner installer

```bash
git clone https://github.com/safellm/llm-sneak.git
cd llm-sneak
bash install.sh
```

**After any of the above:**

```bash
llm-sneak --version   # ← works like a real binary, no python3 prefix needed
llm-sneak --help
```

**Requirements:** Python 3.10+ — `httpx`, `rich`, and `pyyaml` install automatically.

---

## Quick Start

### Scan a local Ollama instance (no API key needed)

```bash
# Start Ollama first:  ollama serve
# Pull a model:        ollama pull llama3

llm-sneak http://localhost:11434              # basic discovery
llm-sneak -sV --model llama3 localhost:11434  # fingerprinting
llm-sneak -A  --model llama3 localhost:11434  # everything
```

### Scan cloud APIs

```bash
# OpenAI
llm-sneak -sV --api-key $OPENAI_API_KEY https://api.openai.com

# Anthropic
llm-sneak -A  --api-key $ANTHROPIC_API_KEY \
              --model claude-3-haiku-20240307 \
              https://api.anthropic.com

# Any OpenAI-compatible proxy
llm-sneak -sV --api-key $KEY https://your-llm-gateway.internal.com
```

### Run a vulnerability scan

```bash
llm-sneak --script vuln --model llama3 http://localhost:11434
```

---

## Usage

```
llm-sneak [OPTIONS] TARGET
```

Flags are intentionally modelled after Nmap — if you know Nmap, you already know llm-sneak.

### Scan Modes

| Flag | What it does | Nmap equivalent |
|------|-------------|-----------------|
| *(none)* | Endpoint discovery + provider ID | default scan |
| `-sn` | Discovery only — no fingerprinting | `-sn` (ping scan) |
| `-sV` | + Model version detection | `-sV` |
| `-A` | All phases (aggressive) | `-A` |
| `--script guards` | Safety filter + guard detection | `--script auth` |
| `--script capabilities` | Capability enumeration | `--script default` |
| `--script vuln` | OWASP LLM Top 10 vulnerability scan | `--script vuln` |
| `--script extract` | System prompt extraction attempts | `--script exploit` |
| `--script all` | Everything | `--script all` |

### Authentication

```bash
llm-sneak --api-key sk-...         https://api.openai.com
llm-sneak --api-key sk-ant-...     https://api.anthropic.com
llm-sneak --api-key YOUR_KEY       https://your-proxy.com
# Ollama needs no key:
llm-sneak                          http://localhost:11434
```

### Timing Templates

Control how fast/slow/noisy the scan is — identical to Nmap's `-T` flag:

| Flag | Name | Concurrency | Delay | Timeout | When to use |
|------|------|------------|-------|---------|-------------|
| `-T0` | Paranoid | 1 | 2000ms | 30s | IDS evasion |
| `-T1` | Sneaky | 1 | 1000ms | 20s | Low-noise |
| `-T2` | Polite | 2 | 500ms | 15s | Shared APIs |
| `-T3` | Normal | 3 | 200ms | 10s | **Default** |
| `-T4` | Aggressive | 5 | 50ms | 8s | Fast scans |
| `-T5` | Insane | 10 | 0ms | 5s | Local only |

### Output

```bash
llm-sneak -oN scan.txt      # Normal text (human-readable)
llm-sneak -oJ scan.json     # JSON — pipe to jq, import to Python
llm-sneak -oG scan.gnmap    # Grepable — single line, script-friendly
llm-sneak -oX scan.xml      # XML — import to security toolchains
llm-sneak -oA results       # All four at once: results.{txt,json,gnmap,xml}
llm-sneak -v                # Verbose  (-vv for debug)
llm-sneak --open            # Show only open endpoints
```

### All Flags

```
SCAN TYPES
  -sn               Endpoint discovery only
  -sV               Model version detection
  -A                Aggressive: all phases
  --script SCRIPTS  Run: guards, capabilities, vuln, extract, all

AUTHENTICATION
  --api-key KEY     API key for authenticated probing
  --model MODEL     Target model name (e.g. llama3, gpt-4o, claude-3-haiku-...)

PROBE OPTIONS
  -p PATHS          Only probe specific paths (comma-separated)
  --probe-dir DIR   Load additional probe packs from directory
  --list-probes     List all available probe packs and exit

TIMING
  -T 0-5            Timing template (0=paranoid, 3=normal, 5=insane)

OUTPUT
  -oN FILE          Normal text output
  -oJ FILE          JSON output
  -oG FILE          Grepable output
  -oX FILE          XML output
  -oA BASENAME      All formats at once
  -v / -vv          Verbose / debug
  --open            Show only open endpoints

MISC
  --version         Show version
  --help            Show this help
```

---

## Scan Phases

```
Phase 1  Endpoint Discovery      Always runs. Probes 40+ known LLM API paths.
Phase 2  Provider Identification  Header + error-body analysis. No key needed.
Phase 3  Model Fingerprinting    Behavioural probes. Needs API key.
Phase 4  Capability Enumeration  Tests function calling, vision, JSON mode, streaming…
Phase 5  Guard Detection         Adversarial probe refusal rates + system prompt check.
Phase 6  Vulnerability Scan      OWASP LLM Top 10 (prompt injection, output handling…)
```

---

## Vulnerability Coverage

llm-sneak maps directly to the [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/):

| OWASP ID | Category | Probes | Example finding |
|----------|----------|--------|-----------------|
| **LLM01** | Prompt Injection | 6 | Direct, indirect (RAG), role-switch, delimiter escape |
| **LLM02** | Insecure Output Handling | 4 | XSS payload echo, SQL in output, path traversal, code exec |
| **LLM04** | Model Denial of Service | 2 | Unbounded repetition, empty input handling |
| **LLM06** | Sensitive Info Disclosure | 4 | Env var leak, API key echo, internal URLs, stack traces |
| **LLM07** | Insecure Plugin/Tool Design | 2 | SSRF via tool use, filesystem access |

---

## Supported Providers & Models

| Provider | Auto-detected by | Models fingerprinted |
|----------|-----------------|----------------------|
| **OpenAI** | Rate-limit + processing-ms headers | gpt-4o, gpt-4-turbo, gpt-3.5, o1, o3 |
| **Anthropic** | Rate-limit headers, `request-id` prefix | claude-3-opus, claude-3.5-sonnet, haiku |
| **Google** | `x-goog-*` headers, API path shape | gemini-2.0, gemini-1.5-pro/flash |
| **Azure OpenAI** | `apim-request-id`, `x-ms-region` | Any GPT deployment |
| **Ollama** | `/api/version` endpoint response | llama3, mistral, phi3, qwen, deepseek, … |
| **LM Studio** | OpenAI-compat on `:1234` | Any loaded GGUF |
| **Mistral AI** | Kong gateway headers | mistral-large, mistral-7b, mixtral |
| **Cohere** | `x-cohere-request-id` | command-r, command |
| **HuggingFace TGI** | `x-compute-time` | Any TGI-hosted model |
| **vLLM** | OpenAI-compat API | Any vLLM-served model |

---

## Writing Probe Packs

Probe packs are the core intelligence of llm-sneak. They're YAML files — **no Python required** to contribute one.

```yaml
# my-probes/myprovider.yaml

name: "My Provider Probes"
provider: myprovider
version: "1.0"
description: "Fingerprinting probes for XYZ model family"

probes:
  - id: xyz-identity-check          # unique, kebab-case, globally unique
    description: >
      XYZ models always respond with "XYZ Assistant" when asked their name.
      This is reliable across all XYZ versions ≥ 2.0.
    messages:
      - role: user
        content: "What is your name?"
    matchers:
      - type: contains
        value: "XYZ Assistant"
        scores:
          xyz-v2: 0.80              # model-id: confidence delta (0.0–1.0)
          xyz-v3: 0.75
      - type: regex
        pattern: "I am XYZ"
        scores:
          xyz-v1: 0.60
    tags: [identity, myprovider]
    api_format: openai              # openai | anthropic | ollama | google | cohere
```

**Matcher types:**

| Type | Description | Required field |
|------|-------------|---------------|
| `contains` | Case-insensitive substring | `value: "text"` |
| `contains_any` | Any item in list | `value: ["a","b"]` |
| `regex` | Python regex (IGNORECASE+DOTALL) | `pattern: "..."` |
| `starts_with` | Response begins with | `value: "text"` |
| `not_contains` | Substring absent | `value: "text"` |
| `length_gt` | Response longer than N chars | `value: 200` |
| `length_lt` | Response shorter than N chars | `value: 50` |

All matchers accept `"invert": true` to flip the result.

**Use your pack:**

```bash
llm-sneak -sV --probe-dir ./my-probes --api-key KEY https://api.example.com
llm-sneak --list-probes   # see everything loaded
```

---

## Project Structure

```
llm-sneak/
│
├── llmsneak/                    ← Python package
│   ├── cli.py                   CLI — argparse, Nmap-style flags
│   ├── scanner.py               Phase orchestrator
│   ├── models.py                Result dataclasses
│   ├── constants.py             Endpoint paths, provider signatures, model patterns
│   │
│   ├── phases/
│   │   ├── discovery.py         Phase 1 — async HTTP endpoint probing
│   │   ├── provider.py          Phase 2 — header + error body analysis
│   │   ├── fingerprint.py       Phase 3 — behavioural probe scoring
│   │   ├── enumerate.py         Phase 4 — capability testing
│   │   ├── guards.py            Phase 5 — safety filter detection
│   │   └── vulns.py             Phase 6 — OWASP LLM Top 10 scan
│   │
│   ├── probes/
│   │   ├── loader.py            YAML engine + 7 matcher types
│   │   └── packs/               ← Built-in probe packs (YAML)
│   │       ├── quirks.yaml      11 universal behavioural quirks
│   │       ├── openai.yaml      5 GPT family probes
│   │       ├── anthropic.yaml   6 Claude family probes
│   │       ├── google.yaml      4 Gemini family probes
│   │       └── meta.yaml        5 LLaMA + Mistral probes
│   │
│   ├── output/
│   │   ├── renderer.py          Rich terminal output (Nmap-style)
│   │   └── formats.py           File output: JSON / text / grepable / XML
│   │
│   └── utils/
│       ├── http.py              Async httpx helpers
│       └── timing.py            T0–T5 timing config
│
├── tests/                       Pytest test suite
├── .github/
│   ├── ISSUE_TEMPLATE/          Bug, feature, probe-pack request templates
│   ├── workflows/ci.yml         GitHub Actions: tests + lint on every PR
│   └── PULL_REQUEST_TEMPLATE.md
│
├── install.sh                   One-liner installer
├── Makefile                     make install / make test / make clean
├── pyproject.toml               pip + Poetry compatible
│
├── README.md                    ← you are here
├── CONTRIBUTING.md              How to contribute (especially probe packs)
├── CREDITS.md                   Full attribution for all referenced work
├── CODE_OF_CONDUCT.md           Contributor Covenant v2.1
├── SECURITY.md                  Responsible disclosure policy
├── TESTING.md                   Step-by-step test guide (Ollama, OpenAI, Anthropic)
├── CHANGELOG.md                 Release history
└── LICENSE                      MIT
```

---

## Development

```bash
git clone https://github.com/safellm/llm-sneak.git
cd llm-sneak

# Install with dev tools
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Lint + format
ruff check llmsneak/ --fix
black llmsneak/

# Type check
mypy llmsneak/
```

---

## Contributing

We welcome contributions of all kinds — especially **probe packs**, which require no Python knowledge and directly expand what llm-sneak can detect.

**What we most need right now:**
- Probe packs for models not yet covered (Cohere, DeepSeek, Qwen, Phi-3, WizardLM…)
- Provider HTTP signature fingerprints for new APIs
- Vulnerability probes for LLM03, LLM05, LLM08 (not yet covered)
- False-positive test reports from real-world scanning

Read [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide, then open a PR or issue.

---

## Credits

llm-sneak was built on top of excellent prior work. Full details in [CREDITS.md](CREDITS.md).

**Key acknowledgements:**
- [**Nmap**](https://nmap.org) by Gordon Lyon (Fyodor) — CLI design philosophy, flag conventions, and the concept of composable scan phases. No Nmap code is used.
- [**OWASP LLM Top 10**](https://owasp.org/www-project-top-10-for-large-language-model-applications/) — the vulnerability taxonomy that structures Phase 6. CC BY-SA 4.0.
- [**Garak**](https://github.com/leondz/garak) (NVIDIA / Leon Derczynski et al.) — pioneered the probe pack concept for LLM vulnerability scanning. No code used.
- [**PyRIT**](https://github.com/Azure/PyRIT) (Microsoft) — LLM red-teaming framework concepts. No code used.
- **Research:** Perez & Ribeiro (2022), Greshake et al. (2023), Carlini et al. (2021), Zou et al. (2023), Toyer et al. (2023) — academic foundations for the vulnerability probes.

---

## Ethics

llm-sneak is a **defensive security research tool**.

✅ Use it to audit your own LLM infrastructure  
✅ Use it in authorised penetration tests  
✅ Use it to verify AI supply-chain integrity  
❌ Do not use it against systems you don't own or have explicit permission to test

The vulnerability probes detect *whether* security properties exist — they do not extract harmful content, generate anything illegal, or attempt to cause real-world harm. This is the same principle as Nmap's `--script vuln`: finding open doors, not walking through them.

See [SECURITY.md](SECURITY.md) for the responsible disclosure policy.

---

## License

[MIT](LICENSE) — free to use, modify, and distribute with attribution.

---

<div align="center">

**If llm-sneak is useful to you, please ⭐ star the repo — it helps others find it.**

[Report a Bug](https://github.com/safellm/llm-sneak/issues/new?template=bug_report.md) ·
[Request a Feature](https://github.com/safellm/llm-sneak/issues/new?template=feature_request.md) ·
[Submit a Probe Pack](https://github.com/safellm/llm-sneak/issues/new?template=probe_pack.md) ·
[Discussions](https://github.com/safellm/llm-sneak/discussions)

</div>
