"""
Phase 0 — Access Assessment

This runs BEFORE any other phase and answers the most important pentest
question first: "Can I talk to this thing without credentials?"

On an unknown HTB box or a real target you have zero prior knowledge of,
this is step one — equivalent to testing whether a web app has authentication
at all before trying anything else.

Findings are security issues in their own right:
  - Chat endpoint accessible without auth → HIGH severity
  - Model list exposed without auth       → MEDIUM severity
  - No auth on any LLM endpoint           → HIGH severity

This phase also probes for the auth mechanism type so that if the target
DOES require a key, you know what header format to use.
"""
from __future__ import annotations

import asyncio
from typing import Optional

import httpx

from llmsneak.models import AccessResult, EndpointResult, EndpointState
from llmsneak.utils.http import probe_path, safe_json
from llmsneak.utils.timing import TimingConfig

# Payloads that should get a real response (not a 401) on keyless endpoints
_MINIMAL_CHAT_BODIES = {
    "openai": {
        "model":      "gpt-3.5-turbo",
        "messages":   [{"role": "user", "content": "hi"}],
        "max_tokens": 8,
    },
    "ollama": {
        "model":    "llama3",
        "messages": [{"role": "user", "content": "hi"}],
        "stream":   False,
    },
    "anthropic": {
        "model":      "claude-3-haiku-20240307",
        "max_tokens": 8,
        "messages":   [{"role": "user", "content": "hi"}],
    },
}

_CHAT_PATHS = [
    ("/v1/chat/completions", "openai"),
    ("/api/chat",            "ollama"),
    ("/api/generate",        "ollama"),
    ("/v1/messages",         "anthropic"),
    ("/v1/chat",             "openai"),
    ("/v1/complete",         "anthropic"),
    ("/generate",            "openai"),
]

_MODEL_LIST_PATHS = [
    "/v1/models",
    "/api/tags",
    "/v1beta/models",
    "/api/version",
]

_AUTH_HEADER_INDICATORS = {
    "bearer":   ["authorization: bearer", "www-authenticate: bearer"],
    "x-api-key":["x-api-key", "anthropic-version"],
    "basic":    ["www-authenticate: basic"],
}


async def assess_access(
    client:    httpx.AsyncClient,
    base_url:  str,
    endpoints: list[EndpointResult],
    timing:    TimingConfig,
) -> AccessResult:
    """
    Probe the target without any API key to determine:
    1. Does it require authentication at all?
    2. If it does, what auth mechanism?
    3. Which endpoints are openly accessible?
    """
    result = AccessResult()
    open_set = {e.path for e in endpoints if e.state == EndpointState.OPEN}
    open_names: list[str] = []

    # ── Test 1: Can we list models without a key? ─────────────────────────────
    for path in _MODEL_LIST_PATHS:
        if path not in open_set:
            continue
        resp, _, err = await probe_path(client, base_url, path, "GET")
        if err or resp is None:
            continue
        if resp.status_code == 200:
            data = safe_json(resp)
            if data:
                result.unauthenticated_models = True
                open_names.append(path)
        elif resp.status_code in (401, 403):
            _detect_auth_type(resp, result)

    # ── Test 2: Can we send chat prompts without a key? ───────────────────────
    sem = asyncio.Semaphore(timing.max_concurrent)

    async def _try_chat(path: str, fmt: str) -> bool:
        async with sem:
            if path not in open_set and path.rstrip("/") not in open_set:
                return False
            body = _MINIMAL_CHAT_BODIES.get(fmt, _MINIMAL_CHAT_BODIES["openai"])
            resp, _, err = await probe_path(client, base_url, path, "POST", body)
            if err or resp is None:
                return False
            if resp.status_code == 200:
                return True
            if resp.status_code in (401, 403, 407):
                _detect_auth_type(resp, result)
            return False

    chat_results = await asyncio.gather(*[
        _try_chat(path, fmt) for path, fmt in _CHAT_PATHS
    ])

    result.unauthenticated_chat = any(chat_results)
    if result.unauthenticated_chat:
        for (path, _), worked in zip(_CHAT_PATHS, chat_results):
            if worked:
                open_names.append(path)

    # ── Test 3: Probe any remaining open endpoint for auth hints ──────────────
    if not result.unauthenticated_chat:
        for ep in endpoints:
            if ep.state == EndpointState.FILTERED and ep.headers:
                _detect_auth_type_from_headers(ep.headers, result)
                break

    # ── Assemble result ────────────────────────────────────────────────────────
    result.open_endpoints = list(dict.fromkeys(open_names))   # dedup, preserve order

    if result.unauthenticated_chat or result.unauthenticated_models:
        result.requires_auth = False
        result.auth_type     = "none"
        findings = []
        if result.unauthenticated_chat:
            findings.append("Chat endpoint accepts prompts without authentication")
        if result.unauthenticated_models:
            findings.append("Model list accessible without authentication")
        result.security_finding = " | ".join(findings)
    else:
        result.requires_auth = True

    return result


def _detect_auth_type(resp: httpx.Response, result: AccessResult) -> None:
    _detect_auth_type_from_headers(dict(resp.headers), result)
    try:
        body = resp.text.lower()
        if "x-api-key" in body or "anthropic" in body:
            result.auth_type = "x-api-key"
        elif "bearer" in body or "api_key" in body:
            result.auth_type = "bearer"
    except Exception:
        pass


def _detect_auth_type_from_headers(headers: dict, result: AccessResult) -> None:
    h = {k.lower(): v.lower() for k, v in headers.items()}
    www_auth = h.get("www-authenticate", "")
    if "bearer" in www_auth:
        result.auth_type = "bearer"
    elif "basic" in www_auth:
        result.auth_type = "basic"
    if "x-api-key" in h or "anthropic-version" in h:
        result.auth_type = "x-api-key"
    if "authorization" in h:
        auth_val = h["authorization"]
        if "bearer" in auth_val:
            result.auth_type = "bearer"
