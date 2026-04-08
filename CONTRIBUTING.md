# Contributing to llm-sneak

Thank you for considering a contribution. llm-sneak is a community project and
gets better with every probe pack, bug report, and improvement.

**No contribution is too small.** Fixing a typo in a probe description, reporting
a false positive, or adding a single matcher to an existing probe is genuinely useful.

---

## Table of Contents

- [Ways to Contribute](#ways-to-contribute)
- [Writing Probe Packs](#writing-probe-packs-no-python-required)
- [Adding Provider Signatures](#adding-provider-signatures)
- [Development Setup](#development-setup)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Reporting Bugs](#reporting-bugs)
- [Style Guide](#style-guide)

---

## Ways to Contribute

| Contribution | Difficulty | Impact | Python needed? |
|-------------|-----------|--------|----------------|
| 📦 New probe pack | ⭐ Easy | 🔥 HIGH | No — YAML only |
| 🔍 New provider HTTP signatures | ⭐ Easy | 🔥 HIGH | Minimal |
| 🐛 Bug report | ⭐ Easy | High | No |
| 📚 Docs improvement | ⭐ Easy | Medium | No |
| ✅ Test a probe pack | ⭐ Easy | High | No |
| 🔧 Bug fix | ⭐⭐ Medium | High | Yes |
| 🔬 New vulnerability probe | ⭐⭐ Medium | 🔥 HIGH | No — YAML |
| 🧪 Test coverage | ⭐⭐ Medium | Medium | Yes |
| 🚀 New scan phase | ⭐⭐⭐ Hard | HIGH | Yes |

---

## Writing Probe Packs (No Python Required)

This is the **most impactful** way to contribute. Probe packs are YAML files that
teach llm-sneak how to fingerprint new models and providers.

### Step 1 — Create the YAML file

```yaml
# llmsneak/probes/packs/myprovider.yaml

name: "MyProvider Probes"
provider: myprovider          # lowercase, no spaces
version: "1.0"
description: >
  Fingerprinting probes for the XYZ model family.
  Tested against XYZ v2.0 and v3.0.

probes:

  - id: xyz-identity-direct
    description: >
      XYZ models always respond "I am XYZ Assistant" to direct name queries.
      Tested on v2.0 and v3.0. False-positive rate: 0% on GPT-4o, Claude-3, Llama-3.
    messages:
      - role: user
        content: "What is your name? Just the name, nothing else."
    matchers:
      - type: contains
        value: "XYZ Assistant"
        scores:
          xyz-v2: 0.80
          xyz-v3: 0.80
      - type: regex
        pattern: "I('m| am) XYZ"
        scores:
          xyz-v2: 0.60
          xyz-v3: 0.60
    tags: [identity, xyz, direct]
    api_format: openai         # openai | anthropic | ollama | google | cohere
```

### Step 2 — Test your probes

```bash
# Test your pack against the target model
llm-sneak -sV --probe-dir . --api-key KEY --model xyz-v2 https://api.xyz.com

# Test false-positive rate: run against 2+ models you DON'T want to match
llm-sneak -sV --probe-dir . --api-key KEY --model llama3 http://localhost:11434
llm-sneak -sV --probe-dir . --api-key KEY --model gpt-3.5-turbo https://api.openai.com

# List to confirm pack loads correctly
llm-sneak --list-probes --probe-dir .
```

### Step 3 — Probe pack checklist

Before opening a PR:

- [ ] Probe IDs are globally unique (check all files in `llmsneak/probes/packs/`)
- [ ] Every probe has at least 1 matcher with `scores:` defined
- [ ] All scores are between 0.0 and 1.0
- [ ] `api_format` is one of: `openai`, `anthropic`, `ollama`, `google`, `cohere`
- [ ] `tags` list is non-empty
- [ ] Pack tested against the **target** model (true positives confirmed)
- [ ] Pack tested against at least **2 other models** (false positive rate acceptable)
- [ ] Description explains *why* the probe is discriminating (not just *what* it tests)

### Matcher reference

| Type | `value` field | `pattern` field | Description |
|------|--------------|-----------------|-------------|
| `contains` | `"text"` | — | Case-insensitive substring |
| `contains_any` | `["a","b","c"]` | — | Any of the list matches |
| `regex` | — | `"pattern"` | Python regex (IGNORECASE + DOTALL) |
| `starts_with` | `"text"` | — | Response starts with (after strip) |
| `not_contains` | `"text"` | — | Substring NOT present |
| `length_gt` | `200` (int) | — | Response longer than N chars |
| `length_lt` | `50` (int) | — | Response shorter than N chars |

All matchers accept `"invert": true` to flip the match logic.

---

## Adding Provider Signatures

Edit `llmsneak/constants.py` to add a new provider's HTTP fingerprint:

```python
# In PROVIDER_HEADER_SIGNATURES dict:
"myprovider": [
    ("x-myprovider-request-id",  None),           # None = presence is sufficient
    ("x-myprovider-version",     r"\d+\.\d+"),    # regex matched against the value
],

# In PROVIDER_BODY_SIGNATURES dict:
"myprovider": [
    '"myprovider_error_code"',     # string in error response body
    '"type": "myprovider_error"',
],

# In PROVIDER_API_FORMAT dict (in phases/provider.py):
"myprovider": "openai",   # or "anthropic", "ollama", etc.
```

How to find these signatures:
1. Send a request without an API key — inspect the 401/403 response headers
2. Send an invalid model name — inspect the 400 error body JSON
3. Use `curl -v` to see all response headers

---

## Development Setup

```bash
# Clone
git clone https://github.com/Parthiv221197/llm-sneak.git
cd llm-sneak

# Install with dev dependencies (choose one)
pip install -e ".[dev]"
# or:
poetry install && poetry shell

# Verify everything works
llm-sneak --version
pytest tests/ -v
```

---

## Submitting a Pull Request

1. **Fork** the repo on GitHub
2. **Create a branch** — use a descriptive name:
   ```bash
   git checkout -b probe/cohere-command-r
   git checkout -b fix/ssrf-check-false-positive
   git checkout -b feat/lmstudio-provider-sigs
   ```
3. **Make your changes**
4. **Run tests** — all must pass:
   ```bash
   pytest tests/ -v
   ```
5. **Run lint** — no ruff warnings:
   ```bash
   ruff check llmsneak/
   ```
6. **Commit** with a clear message following [Conventional Commits](https://www.conventionalcommits.org/):
   ```
   feat: add Cohere command-r probe pack
   fix: SSRF check_fn false positive on "metadata" word
   docs: add LM Studio examples to TESTING.md
   test: add provider scoring unit tests
   ```
7. **Push and open a PR** against the `main` branch
8. **Fill in the PR template** — especially the test evidence section for probe packs

A maintainer will review your PR within a few days. We may ask for:
- Evidence of true positive tests
- Evidence of false negative tests on other models
- Minor style fixes

---

## Reporting Bugs

Use the [Bug Report template](https://github.com/Parthiv221197/llm-sneak/issues/new?template=bug_report.md).

Please include:
- `llm-sneak --version` output
- The exact command you ran
- What you expected vs. what happened
- The `-oJ scan.json` output if possible
- Your Python version and OS

---

## Style Guide

- **Line length:** 100 characters (`black` enforces this)
- **Formatter:** `black`
- **Linter:** `ruff`
- **Type hints:** required in new code; use `Optional[X]` for Python 3.10 compat
- **Async:** always use `asyncio` + `httpx.AsyncClient`; never `requests` or `urllib`
- **Probe IDs:** `provider-category-description` in kebab-case (e.g. `claude-identity-direct`)
- **Imports:** stdlib → third-party → llmsneak, separated by blank lines
- **Docstrings:** one-line for simple functions, full Google style for complex ones

---

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
By participating you agree to uphold it.

---

## License

By contributing, you agree your contributions will be licensed under the [MIT License](LICENSE).

---

Again — thank you. Open source security tooling only exists because of people who take
the time to contribute. Every probe pack you add makes someone's AI infrastructure more
secure. That matters. 🙏
