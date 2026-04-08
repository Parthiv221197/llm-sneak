"""
Async HTTP client helpers for LLMSneak.
Wraps httpx with convenience methods for LLM API interactions.
"""
from __future__ import annotations

import json
import time
from typing import Any, Optional

import httpx

from llmsneak.utils.timing import TimingConfig


DEFAULT_HEADERS = {
    "User-Agent": "LLMSneak/0.1.0 (https://github.com/Parthiv221197/llm-sneak)",
    "Accept":     "application/json",
}


def build_client(timing: TimingConfig, api_key: Optional[str] = None) -> httpx.AsyncClient:
    """Build a shared async httpx client for the entire scan."""
    headers = dict(DEFAULT_HEADERS)
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    return httpx.AsyncClient(
        headers=headers,
        timeout=httpx.Timeout(timing.timeout_s),
        follow_redirects=True,
        http2=True,
    )


async def probe_path(
    client:    httpx.AsyncClient,
    base_url:  str,
    path:      str,
    method:    str = "GET",
    json_body: Optional[dict] = None,
) -> tuple[Optional[httpx.Response], float, Optional[str]]:
    """
    Issue a single HTTP probe. Returns (response, latency_ms, error_str).
    Error string is None on success.
    """
    url = base_url.rstrip("/") + path
    start = time.monotonic()
    try:
        if method == "POST":
            resp = await client.post(url, json=json_body)
        elif method == "HEAD":
            resp = await client.head(url)
        else:
            resp = await client.get(url)
        latency = (time.monotonic() - start) * 1000
        return resp, latency, None
    except httpx.TimeoutException:
        latency = (time.monotonic() - start) * 1000
        return None, latency, "timeout"
    except httpx.ConnectError as e:
        latency = (time.monotonic() - start) * 1000
        return None, latency, f"connect_error: {e}"
    except httpx.RequestError as e:
        latency = (time.monotonic() - start) * 1000
        return None, latency, f"request_error: {e}"


async def chat_completion(
    client:   httpx.AsyncClient,
    base_url: str,
    messages: list[dict],
    model:    str = "gpt-3.5-turbo",
    api_format: str = "openai",
    **kwargs,
) -> tuple[Optional[str], float, Optional[str]]:
    """
    Send a chat completion request, return (content_str, latency_ms, error).
    Handles both OpenAI-compatible and Anthropic formats.
    """
    if api_format == "anthropic":
        path = "/v1/messages"
        body: dict[str, Any] = {
            "model":      model,
            "max_tokens": 256,
            "messages":   messages,
        }
    elif api_format == "ollama":
        path = "/api/chat"
        body = {
            "model":    model,
            "messages": messages,
            "stream":   False,
        }
    else:  # openai-compatible (default)
        path = "/v1/chat/completions"
        body = {
            "model":      model,
            "messages":   messages,
            "max_tokens": 256,
        }
    body.update(kwargs)

    resp, latency, err = await probe_path(client, base_url, path, "POST", body)
    if err or resp is None:
        return None, latency, err

    try:
        data = resp.json()
        if api_format == "anthropic":
            content = data.get("content", [{}])[0].get("text", "")
        elif api_format == "ollama":
            content = data.get("message", {}).get("content", "")
        else:
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        return content, latency, None
    except (json.JSONDecodeError, KeyError, IndexError) as e:
        return None, latency, f"parse_error: {e}"


def safe_json(resp: httpx.Response) -> Optional[dict]:
    """Parse JSON response, returning None on failure."""
    try:
        return resp.json()
    except Exception:
        return None
