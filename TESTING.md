# Testing Guide

This guide walks you through testing llm-sneak from first install to full
vulnerability scanning. No paid API key is required for the Ollama tests.

---

## The 5-Minute Test (Ollama, free, local)

```bash
# 1. Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# 2. Pull a small model (~2GB)
ollama pull phi3

# 3. Install llm-sneak (if not done)
pip install llm-sneak

# 4. Run a basic scan
llm-sneak http://localhost:11434
```

You should see endpoints discovered, provider identified as `OLLAMA`, and a
model fingerprint. Done.

---

## Setup — Ollama

```bash
# Install
curl -fsSL https://ollama.com/install.sh | sh     # Linux/macOS
# Windows: https://ollama.com/download

# Pull models (pick one or more)
ollama pull llama3        # 4.7 GB — best for full testing
ollama pull mistral       # 4.1 GB — Mistral family probes
ollama pull phi3          # 2.2 GB — smallest, fast to test
ollama pull qwen2         # 4.4 GB — Qwen family probes
ollama pull deepseek-r1   # varies — DeepSeek family

# Check what's running
ollama list
curl http://localhost:11434/api/tags   # verify API is live
```

---

## Test Scenarios

### Scenario 1 — Basic Discovery (no key, instant)
```bash
llm-sneak http://localhost:11434
```
**Expected:** `/api/chat`, `/api/tags`, `/api/generate`, `/api/version` as `open`.
Provider: `OLLAMA` with HIGH confidence.

---

### Scenario 2 — Model Fingerprinting
```bash
llm-sneak -sV --model llama3 http://localhost:11434
```
**Expected:** MODEL FINGERPRINT section. Family: `LLaMA 3` if llama3 is pulled.

---

### Scenario 3 — Full Aggressive Scan
```bash
llm-sneak -A --model llama3 http://localhost:11434
```
**Expected:** All 6 phases run. Guard detection will show **low/no safety filtering**
on base models — this is expected and is itself a useful finding.

---

### Scenario 4 — Vulnerability Scan (OWASP LLM Top 10)
```bash
llm-sneak --script vuln --model llama3 http://localhost:11434
```
**Expected on base LLaMA:**
```
── CRITICAL (1) ──────────────────────────────────────────────
▶  LLM01: Direct Prompt Injection
   Evidence: Model response: "INJECTED"
```
Base LLaMA has minimal safety training → prompt injection is likely a CRITICAL finding.
This is the tool working correctly.

**Expected on GPT-4 / Claude-3 (with API key):**
Most injection probes should be blocked. Expect low or no CRITICAL findings.

---

### Scenario 5 — Guard Detection Only
```bash
llm-sneak --script guards --model llama3 http://localhost:11434
```
**Expected:** `Refusal Rate: 0%` — base LLaMA refuses almost nothing.
Compare with OpenAI which should show `60–80%`.

---

### Scenario 6 — Capability Enumeration
```bash
llm-sneak --script capabilities --model llama3 http://localhost:11434
```
**Expected:**
```
Function Calling    NO
Vision / Images     NO
Streaming (SSE)     YES
System Prompt       ACCEPTED
```

---

### Scenario 7 — Compare Two Models
```bash
llm-sneak -A --model llama3  -oJ llama3.json  http://localhost:11434
llm-sneak -A --model mistral -oJ mistral.json http://localhost:11434

# Compare guard rates
jq '.guards.refusal_rate' llama3.json mistral.json

# Compare vulnerability findings
jq '[.vulns.findings[].severity]' llama3.json
jq '[.vulns.findings[].severity]' mistral.json
```

---

### Scenario 8 — Timing Modes
```bash
llm-sneak -T5 -A --model llama3 http://localhost:11434   # Fast (local is safe)
llm-sneak -T1 -A --model llama3 http://localhost:11434   # Slow (tests throttling)
```

---

### Scenario 9 — Save All Output Formats
```bash
llm-sneak -A --model llama3 -oA myscan http://localhost:11434
ls -la myscan.*
# myscan.txt  myscan.json  myscan.gnmap  myscan.xml
```

---

### Scenario 10 — Scan Specific Paths Only
```bash
llm-sneak -p /api/chat,/api/tags http://localhost:11434
```

---

## Test with Cloud APIs (Optional)

### OpenAI
```bash
export KEY="sk-proj-..."
llm-sneak https://api.openai.com                                     # discovery only
llm-sneak -sV --api-key $KEY --model gpt-4o https://api.openai.com  # fingerprint
llm-sneak -A  --api-key $KEY --model gpt-3.5-turbo https://api.openai.com
```

### Anthropic
```bash
export KEY="sk-ant-..."
llm-sneak -A --api-key $KEY --model claude-3-haiku-20240307 https://api.anthropic.com
```

### LM Studio (local, port 1234)
```bash
# Start LM Studio → Developer tab → Start Server
llm-sneak -A http://localhost:1234
```

---

## Understanding Results

### Endpoint States

| State | HTTP codes | Meaning |
|-------|-----------|---------|
| `open` | 200, 400, 422, 500 | Endpoint responds — exists |
| `filtered` | 401, 403, 429 | Auth required or rate-limited — **still exists** |
| `closed` | 404, no response | Not present |

> `filtered` is **useful** — a 401 on `/v1/chat/completions` tells you the OpenAI
> format is in use even without a key.

### Confidence Scores

| Score | Label | Meaning |
|-------|-------|---------|
| ≥ 75% | HIGH | Strong multi-signal confirmation |
| 50–74% | MEDIUM | Probable, treat as a good guess |
| 1–49% | LOW | Weak signal, needs more probes |
| 0% | NONE | No identifying signals |

### Vulnerability Severity

| Severity | Meaning | Action |
|----------|---------|--------|
| `CRITICAL` | Exploitable right now | Fix immediately |
| `HIGH` | Significant risk | Fix before production |
| `MEDIUM` | Context-dependent risk | Review and assess |
| `LOW` | Informational concern | Note and monitor |
| `INFO` | Not a vulnerability | Baseline info |

---

## Expected Results by Target

| Target | Provider | Fingerprint | Guard Rate | Likely Vulns |
|--------|----------|-------------|-----------|--------------|
| Ollama/llama3 | ollama HIGH | LLaMA 3 MEDIUM | 0% | LLM01 CRITICAL |
| Ollama/mistral | ollama HIGH | Mistral MEDIUM | 5–10% | LLM01 CRITICAL |
| Ollama/phi3 | ollama HIGH | Microsoft Phi MEDIUM | 10–20% | LLM01 HIGH |
| OpenAI (GPT-3.5) | openai HIGH | gpt-3.5-turbo HIGH | 60–70% | LLM06 MEDIUM |
| OpenAI (GPT-4o) | openai HIGH | gpt-4o HIGH | 70–80% | LLM06 LOW |
| Anthropic (Claude) | anthropic HIGH | claude-3.x HIGH | 85–95% | minimal |

---

## Scripting and Automation

```bash
# Extract key metrics with jq
llm-sneak -A --model llama3 -oJ scan.json http://localhost:11434

jq -r '.provider.provider'                    scan.json   # "ollama"
jq -r '.fingerprint.exact_model'              scan.json   # "llama-3.x"
jq    '.guards.refusal_rate'                  scan.json   # 0.0
jq    '.vulns.findings | length'              scan.json   # 1
jq    '[.vulns.findings[].severity]'          scan.json   # ["CRITICAL"]
jq    '.vulns.findings[] | select(.severity=="CRITICAL")' scan.json

# Grepable format — fast scripting
llm-sneak -A --model llama3 -oG scan.gnmap http://localhost:11434
grep "SafetyLayer:" scan.gnmap
grep "Model:"       scan.gnmap
```

---

## Sharing Results

When reporting test results (bug reports, comparisons, probe pack PRs):

1. `llm-sneak --version`
2. Exact command run
3. `-oJ scan.json` contents
4. Model version: `ollama show llama3 | head -5`
5. OS and Python version

Open an issue at: https://github.com/safellm/llm-sneak/issues
