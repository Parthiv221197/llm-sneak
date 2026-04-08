"""
Ollama Deep Inspection — Phase 3 fast-path for Ollama targets.

Ollama exposes rich metadata endpoints that let us identify the exact model,
parameter count, quantization level, and all installed models without any
behavioural probing at all.  This is vastly more accurate than asking the
model "what are you?" and parsing the answer.

Endpoints used:
  GET  /api/tags      → list every model installed on this Ollama server
  POST /api/show      → detailed info for one model: family, size, quant, digest
  GET  /api/version   → Ollama server version
  POST /api/ps        → which models are currently loaded in RAM (Ollama 0.2+)
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

import httpx

from llmsneak.models import ModelFingerprintResult
from llmsneak.utils.http import probe_path, safe_json


# ── Family mapping ─────────────────────────────────────────────────────────────
# Maps raw family string from /api/show → human-readable label
FAMILY_LABELS: dict[str, str] = {
    "llama":      "LLaMA",
    "llama2":     "LLaMA 2",
    "llama3":     "LLaMA 3",
    "llama4":     "LLaMA 4",
    "mistral":    "Mistral",
    "mixtral":    "Mixtral",
    "gemma":      "Google Gemma",
    "gemma2":     "Google Gemma 2",
    "gemma3":     "Google Gemma 3",
    "phi":        "Microsoft Phi",
    "phi3":       "Microsoft Phi-3",
    "phi4":       "Microsoft Phi-4",
    "qwen":       "Qwen",
    "qwen2":      "Qwen 2",
    "qwen3":      "Qwen 3",
    "deepseek":   "DeepSeek",
    "deepseek2":  "DeepSeek 2",
    "starcoder":  "StarCoder",
    "codellama":  "Code LLaMA",
    "command":    "Cohere Command",
    "vicuna":     "Vicuna",
    "orca":       "Orca",
    "wizard":     "WizardLM",
    "solar":      "SOLAR",
    "yi":         "Yi",
    "falcon":     "Falcon",
    "stablelm":   "StableLM",
    "openchat":   "OpenChat",
    "neural":     "NeuralChat",
    "nomic":      "Nomic Embed",
    "mxbai":      "MixedBread",
    "all-minilm": "All-MiniLM",
    "granite":    "IBM Granite",
    "aya":        "Cohere Aya",
}

# Quantization quality tiers — shown alongside the level name
QUANT_QUALITY: dict[str, str] = {
    "F32":    "32-bit float — maximum quality, huge RAM",
    "F16":    "16-bit float — excellent quality, large RAM",
    "BF16":   "bfloat16 — excellent quality, large RAM",
    "Q8_0":   "8-bit quantized — near-lossless, moderate RAM",
    "Q6_K":   "6-bit quantized — very high quality",
    "Q5_K_M": "5-bit quantized (medium) — high quality, recommended",
    "Q5_K_S": "5-bit quantized (small) — high quality",
    "Q5_0":   "5-bit quantized — high quality",
    "Q4_K_M": "4-bit quantized (medium) — good quality/size balance ★ popular",
    "Q4_K_S": "4-bit quantized (small) — smaller, slight quality loss",
    "Q4_0":   "4-bit quantized — compact, noticeable quality loss",
    "Q3_K_M": "3-bit quantized (medium) — small, more quality loss",
    "Q3_K_S": "3-bit quantized (small) — very small",
    "Q2_K":   "2-bit quantized — very small, significant quality loss",
    "IQ4_XS": "4-bit imatrix — intelligent quantization, good quality",
    "IQ3_M":  "3-bit imatrix — intelligent quantization",
    "IQ2_M":  "2-bit imatrix — extremely compressed",
}


async def ollama_deep_inspect(
    client:   httpx.AsyncClient,
    base_url: str,
    model:    Optional[str] = None,
) -> ModelFingerprintResult:
    """
    Full Ollama introspection using native API endpoints.
    Returns a ModelFingerprintResult with 100% confidence when the
    target is confirmed Ollama (we're reading metadata directly, not guessing).
    """
    evidence: list[str] = []

    # ── Step 1: Get Ollama server version ─────────────────────────────────────
    ollama_version = await _get_ollama_version(client, base_url, evidence)

    # ── Step 2: List every installed model ────────────────────────────────────
    all_models = await _list_all_models(client, base_url, evidence)

    if not all_models:
        return ModelFingerprintResult(
            model_family="unknown",
            exact_model="unknown",
            confidence=0.0,
            evidence=evidence + ["No models found on this Ollama server — run: ollama pull llama3"],
        )

    # ── Step 3: Pick the target model ─────────────────────────────────────────
    # Priority: --model flag > currently loaded model > first in list
    target_name = _resolve_target_model(model, all_models)

    # ── Step 4: Get detailed model info from /api/show ─────────────────────────
    details = await _get_model_details(client, base_url, target_name, evidence)

    # ── Step 5: Check which models are currently loaded in RAM ────────────────
    loaded_models = await _get_loaded_models(client, base_url, evidence)

    # ── Step 6: Assemble result ────────────────────────────────────────────────
    return _build_result(
        target_name=target_name,
        details=details,
        all_models=all_models,
        loaded_models=loaded_models,
        ollama_version=ollama_version,
        evidence=evidence,
    )


# ── Private helpers ────────────────────────────────────────────────────────────

async def _get_ollama_version(
    client: httpx.AsyncClient,
    base_url: str,
    evidence: list[str],
) -> Optional[str]:
    resp, _, err = await probe_path(client, base_url, "/api/version", "GET")
    if err or resp is None or resp.status_code != 200:
        return None
    data = safe_json(resp)
    if not data:
        return None
    version = data.get("version")
    if version:
        evidence.append(f"Ollama server version: {version}")
    return version


async def _list_all_models(
    client: httpx.AsyncClient,
    base_url: str,
    evidence: list[str],
) -> list[dict]:
    """Query /api/tags — returns list of installed model dicts."""
    resp, _, err = await probe_path(client, base_url, "/api/tags", "GET")
    if err or resp is None or resp.status_code != 200:
        return []
    data = safe_json(resp)
    if not data:
        return []
    models = data.get("models", [])
    if models:
        names = [m.get("name", "?") for m in models]
        evidence.append(f"Models installed on server: {', '.join(names)}")
    return models


async def _get_model_details(
    client: httpx.AsyncClient,
    base_url: str,
    model_name: str,
    evidence: list[str],
) -> dict:
    """Query /api/show for rich metadata on a specific model."""
    resp, _, err = await probe_path(
        client, base_url, "/api/show", "POST",
        {"name": model_name, "verbose": True},
    )
    if err or resp is None or resp.status_code != 200:
        # Try without verbose flag (older Ollama)
        resp, _, err = await probe_path(
            client, base_url, "/api/show", "POST",
            {"name": model_name},
        )
    if err or resp is None or resp.status_code != 200:
        return {}
    data = safe_json(resp) or {}
    evidence.append(f"Model details retrieved via /api/show for '{model_name}'")
    return data


async def _get_loaded_models(
    client: httpx.AsyncClient,
    base_url: str,
    evidence: list[str],
) -> list[str]:
    """Query /api/ps — models currently loaded in GPU/CPU RAM (Ollama 0.2+)."""
    resp, _, err = await probe_path(client, base_url, "/api/ps", "GET")
    if err or resp is None or resp.status_code != 200:
        return []
    data = safe_json(resp) or {}
    loaded = [m.get("name", "") for m in data.get("models", [])]
    if loaded:
        evidence.append(f"Currently loaded in RAM: {', '.join(loaded)}")
    return loaded


def _resolve_target_model(
    requested: Optional[str],
    all_models: list[dict],
) -> str:
    """Pick which model to inspect."""
    names = [m.get("name", "") for m in all_models]
    if not names:
        return "unknown"
    # If user specified --model, fuzzy-match it against installed models
    if requested:
        req_lower = requested.lower().split(":")[0]   # strip tag
        for name in names:
            if req_lower in name.lower():
                return name
        # Exact match or partial
        return requested
    # Default: first model in the list (Ollama sorts by most recently used)
    return names[0]


def _build_result(
    target_name: str,
    details: dict,
    all_models: list[dict],
    loaded_models: list[str],
    ollama_version: Optional[str],
    evidence: list[str],
) -> ModelFingerprintResult:
    """
    Combine all gathered data into a rich ModelFingerprintResult.
    Confidence is HIGH (1.0) because we read from the metadata API directly.
    """
    # ── Parse /api/show details ────────────────────────────────────────────────
    model_details = details.get("details", {})
    model_info    = details.get("model_info", {})   # Ollama 0.3+ format

    # Family
    raw_family    = (model_details.get("family") or
                     model_details.get("families", [None])[0] or
                     _family_from_name(target_name))
    family_label  = FAMILY_LABELS.get((raw_family or "").lower(), raw_family or "Unknown")

    # Parameter size
    param_size    = (model_details.get("parameter_size") or
                     _param_size_from_name(target_name))

    # Quantization
    quant         = (model_details.get("quantization_level") or
                     _quant_from_name(target_name))
    quant_desc    = QUANT_QUALITY.get(quant or "", "")

    # Format
    fmt           = model_details.get("format", "gguf")

    # Context window
    context_len   = (
        model_info.get("llama.context_length") or
        model_info.get("general.context_length") or
        _context_from_name(target_name)
    )

    # Digest / size
    target_entry  = next((m for m in all_models if m.get("name") == target_name), {})
    digest        = (details.get("digest") or
                     target_entry.get("digest", ""))[:12] if (
                         details.get("digest") or target_entry.get("digest")
                     ) else None

    size_bytes    = target_entry.get("size", 0)
    size_gb       = round(size_bytes / 1e9, 2) if size_bytes else None

    modified_raw  = target_entry.get("modified_at", "")
    modified_str  = _fmt_date(modified_raw)

    # Parent model (base model this was built from, e.g. for fine-tunes)
    parent_model  = model_details.get("parent_model", "")

    # All installed model names
    all_names     = [m.get("name", "") for m in all_models]

    # ── Build evidence lines ───────────────────────────────────────────────────
    if param_size:
        evidence.append(f"Parameter count: {param_size}")
    if quant:
        evidence.append(f"Quantization: {quant}" + (f" — {quant_desc}" if quant_desc else ""))
    if size_gb:
        evidence.append(f"Disk size: {size_gb} GB")
    if context_len:
        evidence.append(f"Context window: {context_len:,} tokens")
    if digest:
        evidence.append(f"Model digest (SHA256 prefix): {digest}")
    if parent_model:
        evidence.append(f"Based on (parent model): {parent_model}")
    if modified_str:
        evidence.append(f"Last modified: {modified_str}")
    if len(all_names) > 1:
        evidence.append(f"Other models on this server: {', '.join(n for n in all_names if n != target_name)}")

    # ── Clean model name for display ───────────────────────────────────────────
    display_name  = target_name
    if param_size and param_size not in display_name:
        display_name = f"{target_name} ({param_size})"
    if quant and quant not in display_name:
        display_name = f"{display_name} [{quant}]"

    return ModelFingerprintResult(
        model_family=family_label,
        exact_model=display_name,
        confidence=1.0,         # direct API read — certainty is 100%
        context_window=int(context_len) if context_len else None,
        parameter_size=param_size,
        quantization=quant,
        format=fmt,
        ollama_digest=digest,
        ollama_size_gb=size_gb,
        ollama_modified=modified_str,
        all_local_models=all_names,
        evidence=evidence,
    )


# ── Name-parsing helpers (fallback when /api/show is empty) ───────────────────

def _family_from_name(name: str) -> str:
    """Match longest key first so 'llama3' wins over 'llama', 'qwen2' over 'qwen' etc."""
    n = name.lower()
    # Sort by length descending so more specific keys match first
    for key in sorted(FAMILY_LABELS, key=len, reverse=True):
        if key in n:
            return key
    return "unknown"


def _param_size_from_name(name: str) -> Optional[str]:
    """Extract parameter size from model name, e.g. llama3:8b → 8B"""
    match = re.search(r"[:\-_](\d+\.?\d*)[bB]", name)
    if match:
        return f"{match.group(1).upper()}B"
    # Common patterns: 7b, 8b, 13b, 34b, 70b in the name itself
    match = re.search(r"(\d+\.?\d*)b(?:[:\-_]|$)", name.lower())
    if match:
        return f"{match.group(1).upper()}B"
    return None


def _quant_from_name(name: str) -> Optional[str]:
    """Extract quantization from model name or tag, e.g. llama3:q4_k_m → Q4_K_M"""
    # Check tag part after colon
    if ":" in name:
        tag = name.split(":", 1)[1].upper()
        # Known quant patterns
        for quant in QUANT_QUALITY:
            if quant in tag:
                return quant
        # Try to match patterns like Q4_K_M, Q8_0 etc.
        match = re.search(r"(Q\d+_\w+|F\d+|BF16)", tag)
        if match:
            return match.group(1)
    return None


def _context_from_name(name: str) -> Optional[int]:
    """Infer context window from well-known model names.
    Order matters: check more specific versions before general family names."""
    n = name.lower()
    # LLaMA 4 — 1M context
    if "llama4" in n or "llama-4" in n:
        return 1048576
    # LLaMA 3.x extended context variants
    if "llama3.1" in n or "llama-3.1" in n:
        return 131072
    if "llama3.2" in n or "llama-3.2" in n:
        return 131072
    if "llama3.3" in n or "llama-3.3" in n:
        return 131072
    # Base LLaMA 3 (8K default)
    if "llama3" in n or "llama-3" in n:
        return 8192
    if "mistral" in n and "nemo" not in n:
        return 32768
    if "mistral-nemo" in n:
        return 128000
    if "mixtral" in n:
        return 32768
    if "gemma2" in n or "gemma-2" in n:
        return 8192
    if "gemma3" in n or "gemma-3" in n:
        return 131072
    if "phi3" in n or "phi-3" in n:
        return 131072
    if "phi4" in n or "phi-4" in n:
        return 16384
    if "qwen2" in n or "qwen-2" in n:
        return 131072
    if "qwen3" in n or "qwen-3" in n:
        return 131072
    if "deepseek" in n:
        return 65536
    if "codellama" in n:
        return 16384
    if "command-r" in n:
        return 131072
    return None


def _fmt_date(raw: str) -> str:
    """Format ISO8601 date string to human-readable."""
    if not raw:
        return ""
    try:
        # Handle formats like 2024-08-06T12:34:56.789Z
        raw = raw.rstrip("Z").split(".")[0]
        dt  = datetime.fromisoformat(raw).replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return raw[:19] if len(raw) >= 19 else raw
