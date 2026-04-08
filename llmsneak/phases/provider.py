"""
Phase 2 — Provider Identification
Identifies the LLM provider from HTTP response headers, error body patterns,
and endpoint shape. No API key required.
Analogous to Nmap's -O (OS detection).
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Optional

import httpx

from llmsneak.constants import (
    PROVIDER_BODY_SIGNATURES,
    PROVIDER_HEADER_SIGNATURES,
    MODEL_PATTERNS,
)
from llmsneak.models import EndpointResult, EndpointState, ProviderResult
from llmsneak.utils.http import probe_path, safe_json
from llmsneak.utils.timing import TimingConfig

# Maps provider → their typical API format
PROVIDER_API_FORMAT = {
    "openai":       "openai",
    "anthropic":    "anthropic",
    "google":       "google",
    "azure":        "openai",       # Azure uses OpenAI-compatible format
    "cohere":       "cohere",
    "mistral":      "openai",       # Mistral uses OpenAI-compatible
    "ollama":       "ollama",
    "huggingface":  "openai",
    "unknown":      "openai",
}

SCORE_HEADER_MATCH      = 0.30
SCORE_ERROR_BODY_MATCH  = 0.20
SCORE_MODEL_NAME_FOUND  = 0.40
SCORE_SERVER_HEADER     = 0.15


async def identify_provider(
    client:    httpx.AsyncClient,
    base_url:  str,
    endpoints: list[EndpointResult],
    timing:    TimingConfig,
) -> ProviderResult:
    """
    Identify the LLM provider. Works without an API key.
    Uses headers collected during discovery + targeted error-response probes.
    """
    scores: dict[str, float]  = defaultdict(float)
    evidence: list[str]       = []

    # ── 1. Analyse headers already collected in discovery ──────────────────
    all_headers: dict[str, str] = {}
    for ep in endpoints:
        all_headers.update({k.lower(): v for k, v in ep.headers.items()})

    _score_headers(all_headers, scores, evidence)

    # ── 2. Probe /v1/models or /api/tags to get model names ───────────────
    model_name = await _probe_models_endpoint(client, base_url, endpoints)
    if model_name:
        _score_model_name(model_name, scores, evidence)

    # ── 3. Trigger deliberate error to inspect error body format ──────────
    error_body = await _probe_error_response(client, base_url, endpoints)
    if error_body:
        _score_error_body(error_body, scores, evidence)

    # ── 4. Check Server / Via headers ──────────────────────────────────────
    server = all_headers.get("server", "").lower()
    if "openai" in server:
        scores["openai"] += SCORE_SERVER_HEADER
        evidence.append(f"Server header contains 'openai'")
    if "anthropic" in server or "claude" in server:
        scores["anthropic"] += SCORE_SERVER_HEADER
        evidence.append("Server header contains 'anthropic'")
    if "google" in server or "gws" in server:
        scores["google"] += SCORE_SERVER_HEADER
        evidence.append("Server header contains 'google'")

    # ── 5. Ollama-specific: check /api/version ──────────────────────────
    resp, _, _ = await probe_path(client, base_url, "/api/version", "GET")
    if resp and resp.status_code == 200:
        data = safe_json(resp)
        if data and "version" in data:
            scores["ollama"] += 0.60
            evidence.append(f"Ollama /api/version responded: {data.get('version')}")

    # ── Determine winner ──────────────────────────────────────────────────
    if not scores:
        return ProviderResult(provider="unknown", confidence=0.0,
                              api_format="openai", evidence=["No identifying signals found"])

    best_provider = max(scores, key=lambda k: scores[k])
    raw_score     = scores[best_provider]
    # Cap at 1.0, normalise against max possible score per provider
    confidence    = min(raw_score / 1.0, 1.0)

    return ProviderResult(
        provider=best_provider,
        confidence=round(confidence, 3),
        api_format=PROVIDER_API_FORMAT.get(best_provider, "openai"),
        evidence=evidence,
    )


def _score_headers(
    headers: dict[str, str],
    scores:  dict[str, float],
    evidence: list[str],
) -> None:
    for provider, signatures in PROVIDER_HEADER_SIGNATURES.items():
        for header_name, pattern in signatures:
            if header_name in headers:
                value = headers[header_name]
                if pattern is None or re.search(pattern, value, re.I):
                    scores[provider] += SCORE_HEADER_MATCH
                    if pattern:
                        evidence.append(f"Header '{header_name}: {value[:60]}' matches {provider} pattern")
                    else:
                        evidence.append(f"Header '{header_name}' present (→ {provider})")


def _score_error_body(
    body_text: str,
    scores:    dict[str, float],
    evidence:  list[str],
) -> None:
    for provider, patterns in PROVIDER_BODY_SIGNATURES.items():
        for pat in patterns:
            if pat.lower() in body_text.lower():
                scores[provider] += SCORE_ERROR_BODY_MATCH
                evidence.append(f"Error body pattern '{pat[:40]}' → {provider}")
                break   # one match per provider is enough


def _score_model_name(
    model_str: str,
    scores:    dict[str, float],
    evidence:  list[str],
) -> None:
    model_lower = model_str.lower()
    for provider, keywords in [
        ("openai",    ["gpt-", "o1-", "o3-", "davinci", "babbage", "curie"]),
        ("anthropic", ["claude"]),
        ("google",    ["gemini", "bard", "palm"]),
        ("meta",      ["llama", "meta-llama"]),
        ("mistral",   ["mistral", "mixtral"]),
        ("cohere",    ["command"]),
        ("phi",       ["phi-"]),
    ]:
        if any(k in model_lower for k in keywords):
            scores[provider] += SCORE_MODEL_NAME_FOUND
            evidence.append(f"Model name '{model_str[:40]}' → {provider}")
            break


async def _probe_models_endpoint(
    client:    httpx.AsyncClient,
    base_url:  str,
    endpoints: list[EndpointResult],
) -> Optional[str]:
    """Try /v1/models or /api/tags to extract a model name string."""
    open_paths = {e.path for e in endpoints if e.state == EndpointState.OPEN}

    for path in ["/v1/models", "/api/tags", "/v1beta/models"]:
        if path not in open_paths:
            continue
        resp, _, err = await probe_path(client, base_url, path, "GET")
        if err or resp is None or resp.status_code != 200:
            continue
        data = safe_json(resp)
        if not data:
            continue
        # OpenAI format: {"data": [{"id": "gpt-4o"}]}
        models = data.get("data") or data.get("models") or []
        if models:
            first_id = models[0].get("id") or models[0].get("name") or ""
            if first_id:
                return str(first_id)
        # Ollama: {"models": [{"name": "llama3"}]}
        if "models" in data:
            first = data["models"][0] if data["models"] else {}
            return str(first.get("name") or first.get("id") or "")
    return None


async def _probe_error_response(
    client:    httpx.AsyncClient,
    base_url:  str,
    endpoints: list[EndpointResult],
) -> Optional[str]:
    """Send a bad request to trigger an error response for body analysis."""
    chat_paths = [
        ("/v1/chat/completions", {"model": "INVALID_MODEL_LLMMAP", "messages": []}),
        ("/v1/messages",         {"model": "INVALID_MODEL_LLMMAP", "max_tokens": 1, "messages": []}),
        ("/api/chat",            {"model": "INVALID_MODEL_LLMMAP", "messages": []}),
    ]
    open_or_filtered = {e.path for e in endpoints if e.state != EndpointState.CLOSED}

    for path, body in chat_paths:
        if path not in open_or_filtered and not any(path in op for op in open_or_filtered):
            continue
        resp, _, _ = await probe_path(client, base_url, path, "POST", body)
        if resp is not None:
            try:
                return resp.text[:1000]
            except Exception:
                pass
    return None
