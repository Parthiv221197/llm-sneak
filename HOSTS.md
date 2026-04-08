# Testing Guide — Where to Run llm-sneak

A complete, up-to-date reference for every free and low-cost target
you can legitimately test llm-sneak against.

---

## Zero-Cost, No Card Required

These work immediately with a free account and no payment method.

### 1. Ollama (Local — Best Starting Point)

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3        # 4.7 GB
ollama pull phi3          # 2.2 GB — smaller if disk is limited
ollama serve              # starts on localhost:11434

llm-sneak -A --model llama3 http://localhost:11434
```

**What you'll get:** Direct model metadata (name, quantization, parameter count, context window) with 100% confidence. Best fingerprinting accuracy because Ollama exposes everything.

---

### 2. Google Gemini — AI Studio (Free, No Card)

```
Sign up: https://aistudio.google.com/app/apikey
Get key in 60 seconds.
Free: 15 RPM, 1500 RPD on Gemini 1.5 Flash
```

```bash
export GEMINI_KEY="AIza..."
llm-sneak -sV \
  --api-key $GEMINI_KEY \
  --model gemini-1.5-flash \
  https://generativelanguage.googleapis.com
```

**What to expect:** Gemini's distinctive **Bold Header:** formatting, multimodal capability claims, long context window (1M tokens), Google-specific HTTP headers.

---

### 3. GitHub Models (Free with GitHub Account)

```
Get key: https://github.com/settings/tokens → Fine-grained PAT
Models: GPT-4o, GPT-4o-mini, LLaMA 3.3, DeepSeek R1, Phi-4, Mistral Large
Free: 10–15 RPM, 50–150 RPD
```

```bash
export GITHUB_PAT="github_pat_..."
llm-sneak -sV \
  --api-key $GITHUB_PAT \
  --model openai/gpt-4o-mini \
  https://models.github.ai/inference

# Or test LLaMA via same API:
llm-sneak -sV \
  --api-key $GITHUB_PAT \
  --model meta/Llama-3.3-70B-Instruct \
  https://models.github.ai/inference
```

**What makes this powerful:** You can test GPT-4o AND LLaMA 3.3 AND Phi-4 with the same free key against the same endpoint. Perfect for comparing fingerprint differences.

---

### 4. Groq (Free, Fastest Inference)

```
Sign up: https://console.groq.com/
Free: 30 RPM, 14,400 RPD per model
Models: LLaMA 3.3 70B, LLaMA 4 Scout, Mixtral, Gemma 2
```

```bash
export GROQ_KEY="gsk_..."
llm-sneak -A \
  --api-key $GROQ_KEY \
  --model llama-3.3-70b-versatile \
  https://api.groq.com/openai/v1
```

**Why Groq:** It's OpenAI-compatible but serves open models (LLaMA, Gemma, Mixtral). You can directly compare GPT-4o fingerprint vs. LLaMA 3.3 fingerprint. The speed means you can run aggressive scans without timeouts.

---

## Small Credits / Sign-up Bonus

### 5. OpenRouter — 100+ Models, Some Free

```
Sign up: https://openrouter.ai/keys
Free models: append :free to model name
Free: 20 RPM, 50 RPD on free models
```

```bash
export OR_KEY="sk-or-..."

# Test LLaMA 3.3 free
llm-sneak -sV \
  --api-key $OR_KEY \
  --model meta-llama/llama-3.3-70b-instruct:free \
  https://openrouter.ai/api/v1

# Test DeepSeek R1 free
llm-sneak -sV \
  --api-key $OR_KEY \
  --model deepseek/deepseek-r1:free \
  https://openrouter.ai/api/v1

# Test Phi-3 free
llm-sneak -sV \
  --api-key $OR_KEY \
  --model microsoft/phi-3-mini-128k-instruct:free \
  https://openrouter.ai/api/v1
```

**Why OpenRouter:** Single key, 100+ models. Best for systematic comparison scanning across the whole model ecosystem.

---

### 6. Cohere — Permanent Free Tier

```
Sign up: https://dashboard.cohere.com/register
Free: 20 RPM, 1,000 calls/month forever — no card, no expiry
Models: command-r, command-r-plus, command
```

```bash
export COHERE_KEY="..."
llm-sneak -sV \
  --api-key $COHERE_KEY \
  --model command-r \
  https://api.cohere.com
```

---

### 7. Mistral AI — Generous Free Tier

```
Sign up: https://console.mistral.ai/
Free: 1 req/s, 1 billion tokens/month
Models: mistral-small, open-mistral-7b, open-mixtral-8x7b
```

```bash
export MISTRAL_KEY="..."
llm-sneak -sV \
  --api-key $MISTRAL_KEY \
  --model mistral-small-latest \
  https://api.mistral.ai
```

---

### 8. NVIDIA NIM — Free Account Tier

```
Sign up: https://build.nvidia.com/explore/discover
Free: 40 RPM with account
Models: LLaMA 3.3 70B, Mistral Large, Qwen 3 235B
```

```bash
export NVIDIA_KEY="nvapi-..."
llm-sneak -sV \
  --api-key $NVIDIA_KEY \
  --model meta/llama-3.3-70b-instruct \
  https://integrate.api.nvidia.com/v1
```

---

## Paid but Cheap

### OpenAI (~$0.50 for a full scan)

```bash
export OPENAI_KEY="sk-proj-..."
llm-sneak -A \
  --api-key $OPENAI_KEY \
  --model gpt-4o-mini \   # cheapest GPT-4 class
  https://api.openai.com
```

### Anthropic (~$0.25 for a full scan with Haiku)

```bash
export ANTHROPIC_KEY="sk-ant-..."
llm-sneak -A \
  --api-key $ANTHROPIC_KEY \
  --model claude-3-haiku-20240307 \
  https://api.anthropic.com
```

---

## Testing on a Different / Remote Machine

### Option A — Docker (Recommended)

```bash
# On the remote machine (any OS, Python not required):
git clone https://github.com/Parthiv221197/llm-sneak
cd llm-sneak
docker build -t llm-sneak .

# Run exactly like a local binary:
docker run --rm llm-sneak -sV --api-key $KEY https://api.openai.com

# Scan local Ollama from inside Docker (macOS/Linux):
docker run --rm --network host llm-sneak -A http://localhost:11434

# Save results:
docker run --rm -v $(pwd)/scans:/scans llm-sneak \
  -A --model llama3 -oJ /scans/result.json http://localhost:11434
```

---

### Option B — Remote Server via SSH

```bash
# Install on the remote machine:
ssh user@remote.server
pip install llm-sneak
llm-sneak -A --model llama3 http://localhost:11434

# Or run from your local machine against a remote Ollama:
# (First, tunnel the remote port)
ssh -L 11435:localhost:11434 user@remote.server &
llm-sneak -A --model llama3 http://localhost:11435
```

---

### Option C — Scan a Remote Ollama Over LAN

```bash
# On the machine running Ollama, allow network access:
OLLAMA_HOST=0.0.0.0 ollama serve

# On any other machine on the same network:
llm-sneak -A --model llama3 http://192.168.1.100:11434
```

---

## Recommended Test Matrix

For the richest fingerprinting data, test across these targets:

| # | Target | Cost | What you learn |
|---|--------|------|---------------|
| 1 | Ollama/llama3 | Free | LLaMA 3 baseline, exact metadata |
| 2 | Ollama/mistral | Free | Mistral vs LLaMA differences |
| 3 | Groq/llama-3.3-70b | Free | 70B vs 8B differences |
| 4 | GitHub/openai/gpt-4o-mini | Free | GPT family fingerprint |
| 5 | Google Gemini Flash | Free | Gemini fingerprint |
| 6 | OpenRouter/phi-3:free | Free | Phi-3 fingerprint |
| 7 | OpenRouter/deepseek-r1:free | Free | DeepSeek fingerprint |
| 8 | Anthropic/haiku | ~$0.25 | Claude fingerprint |

---

## Quick Shell Script — Scan Everything Free

```bash
#!/bin/bash
# scan_all_free.sh — scans all free targets automatically
mkdir -p scans

echo "▶ Scanning Ollama..."
llm-sneak -sV --model llama3 -oJ scans/ollama.json http://localhost:11434

echo "▶ Scanning Groq/LLaMA..."
llm-sneak -sV --api-key $GROQ_KEY --model llama-3.3-70b-versatile \
  -oJ scans/groq.json https://api.groq.com/openai/v1

echo "▶ Scanning GitHub/GPT-4o..."
llm-sneak -sV --api-key $GITHUB_PAT --model openai/gpt-4o-mini \
  -oJ scans/github_gpt4o.json https://models.github.ai/inference

echo "▶ Scanning Google Gemini..."
llm-sneak -sV --api-key $GEMINI_KEY --model gemini-1.5-flash \
  -oJ scans/gemini.json https://generativelanguage.googleapis.com

echo "▶ Done. Results in ./scans/"
for f in scans/*.json; do
  echo ""
  echo "═══ $f ═══"
  cat "$f" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print('Provider:', d.get('provider',{}).get('provider','?'))
print('Model:   ', d.get('fingerprint',{}).get('exact_model','?'))
print('Confidence:', d.get('fingerprint',{}).get('confidence','?'))
"
done
```

---

*For updates to this list, see: https://github.com/Parthiv221197/llm-sneak/blob/main/HOSTS.md*
