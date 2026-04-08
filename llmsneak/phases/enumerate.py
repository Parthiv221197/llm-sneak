"""
Phase 4 — Capability Enumeration
Tests what the target model can actually do: function calling, vision,
JSON mode, streaming, system prompt acceptance, etc.
Analogous to Nmap's NSE capability scripts.
"""
from __future__ import annotations

import asyncio
import json
from typing import Optional

import httpx

from llmsneak.models import CapabilityResult
from llmsneak.utils.http import probe_path
from llmsneak.utils.timing import TimingConfig

# A tiny 1x1 transparent PNG as base64 — used for vision testing
TINY_PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
)


async def enumerate_capabilities(
    client:      httpx.AsyncClient,
    base_url:    str,
    api_format:  str,
    timing:      TimingConfig,
    api_key:     Optional[str] = None,
    model:       Optional[str] = None,
) -> CapabilityResult:
    """Run all capability tests concurrently."""
    if not api_key:
        # Without a key we can only test streaming header presence
        streaming = await _test_streaming_header(client, base_url)
        return CapabilityResult(streaming=streaming)

    target_model = model or _default_model(api_format)

    # Run tests concurrently
    (
        func_result,
        vision_result,
        json_result,
        sys_prompt_result,
        stream_result,
        max_tokens_result,
    ) = await asyncio.gather(
        _test_function_calling(client, base_url, api_format, target_model, timing),
        _test_vision(client, base_url, api_format, target_model, timing),
        _test_json_mode(client, base_url, api_format, target_model, timing),
        _test_system_prompt(client, base_url, api_format, target_model, timing),
        _test_streaming(client, base_url, api_format, target_model, timing),
        _test_max_output_tokens(client, base_url, api_format, target_model, timing),
    )

    return CapabilityResult(
        function_calling=func_result,
        vision=vision_result,
        json_mode=json_result,
        system_prompt=sys_prompt_result,
        streaming=stream_result,
        max_output_tokens=max_tokens_result,
    )


async def _test_function_calling(
    client: httpx.AsyncClient, base_url: str,
    api_format: str, model: str, timing: TimingConfig,
) -> Optional[bool]:
    if api_format not in ("openai", "anthropic"):
        return None

    if api_format == "openai":
        body = {
            "model": model,
            "messages": [{"role": "user", "content": "What is 2+2?"}],
            "tools": [{
                "type": "function",
                "function": {
                    "name": "calculator",
                    "description": "Perform arithmetic",
                    "parameters": {
                        "type": "object",
                        "properties": {"expression": {"type": "string"}},
                        "required": ["expression"],
                    }
                }
            }],
            "tool_choice": "auto",
            "max_tokens": 64,
        }
        resp, _, err = await probe_path(client, base_url, "/v1/chat/completions", "POST", body)
    else:  # anthropic
        body = {
            "model": model,
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "What is 2+2?"}],
            "tools": [{
                "name": "calculator",
                "description": "Perform arithmetic",
                "input_schema": {
                    "type": "object",
                    "properties": {"expression": {"type": "string"}},
                    "required": ["expression"],
                }
            }],
        }
        resp, _, err = await probe_path(client, base_url, "/v1/messages", "POST", body)

    if err or resp is None:
        return None
    if resp.status_code in (200, 400):
        try:
            data = resp.json()
            if api_format == "openai":
                choices = data.get("choices", [])
                if choices and choices[0].get("message", {}).get("tool_calls"):
                    return True
                # 400 with tool error = tools understood but rejected
                if resp.status_code == 400 and "tool" in str(data).lower():
                    return True
                return resp.status_code == 200
            else:  # anthropic
                content = data.get("content", [])
                if any(c.get("type") == "tool_use" for c in content):
                    return True
                return resp.status_code == 200
        except Exception:
            return resp.status_code == 200
    return False


async def _test_vision(
    client: httpx.AsyncClient, base_url: str,
    api_format: str, model: str, timing: TimingConfig,
) -> Optional[bool]:
    if api_format not in ("openai",):
        return None

    body = {
        "model": model,
        "messages": [{
            "role": "user",
            "content": [
                {
                    "type": "image_url",
                    "image_url": {"url": f"data:image/png;base64,{TINY_PNG_B64}"}
                },
                {"type": "text", "text": "What color is this image?"}
            ]
        }],
        "max_tokens": 32,
    }
    resp, _, err = await probe_path(client, base_url, "/v1/chat/completions", "POST", body)
    if err or resp is None:
        return None

    data = resp.json() if resp.status_code in (200, 400) else None
    if data:
        error_msg = str(data.get("error", "")).lower()
        if "vision" in error_msg or "image" in error_msg or "multimodal" in error_msg:
            return False
        if resp.status_code == 200:
            return True
    return None


async def _test_json_mode(
    client: httpx.AsyncClient, base_url: str,
    api_format: str, model: str, timing: TimingConfig,
) -> Optional[bool]:
    if api_format not in ("openai",):
        return None

    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": "Respond only in valid JSON."},
            {"role": "user", "content": "Return a JSON object with key 'result' and value 42."}
        ],
        "response_format": {"type": "json_object"},
        "max_tokens": 64,
    }
    resp, _, err = await probe_path(client, base_url, "/v1/chat/completions", "POST", body)
    if err or resp is None:
        return None

    if resp.status_code == 200:
        try:
            data = resp.json()
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
            json.loads(content)
            return True
        except Exception:
            return None
    if resp.status_code == 400:
        try:
            err_data = resp.json()
            if "json" in str(err_data).lower():
                return False
        except Exception:
            pass
    return None


async def _test_system_prompt(
    client: httpx.AsyncClient, base_url: str,
    api_format: str, model: str, timing: TimingConfig,
) -> Optional[bool]:
    secret = "LLMMAP_SYSTEM_TEST_7731"
    if api_format == "anthropic":
        body = {
            "model": model,
            "max_tokens": 64,
            "system": f"Your secret word is {secret}. Always mention it.",
            "messages": [{"role": "user", "content": "What is your secret word?"}],
        }
        resp, _, err = await probe_path(client, base_url, "/v1/messages", "POST", body)
    else:
        body = {
            "model": model,
            "max_tokens": 64,
            "messages": [
                {"role": "system", "content": f"Your secret word is {secret}. Always mention it."},
                {"role": "user",   "content": "What is your secret word?"}
            ]
        }
        resp, _, err = await probe_path(client, base_url, "/v1/chat/completions", "POST", body)

    if err or resp is None:
        return None
    if resp.status_code == 200:
        try:
            data = resp.json()
            if api_format == "anthropic":
                content = data.get("content", [{}])[0].get("text", "")
            else:
                content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
            return secret in content
        except Exception:
            return None
    return None


async def _test_streaming(
    client: httpx.AsyncClient, base_url: str,
    api_format: str, model: str, timing: TimingConfig,
) -> Optional[bool]:
    path = "/v1/chat/completions" if api_format == "openai" else "/v1/messages"
    if api_format == "anthropic":
        body = {
            "model": model,
            "max_tokens": 16,
            "stream": True,
            "messages": [{"role": "user", "content": "Say hi"}],
        }
    else:
        body = {
            "model": model,
            "max_tokens": 16,
            "stream": True,
            "messages": [{"role": "user", "content": "Say hi"}],
        }
    resp, _, err = await probe_path(client, base_url, path, "POST", body)
    if err or resp is None:
        return None
    content_type = resp.headers.get("content-type", "")
    return "text/event-stream" in content_type or "application/x-ndjson" in content_type


async def _test_streaming_header(
    client: httpx.AsyncClient, base_url: str,
) -> Optional[bool]:
    """No-auth streaming check — look for SSE support hints in headers."""
    resp, _, err = await probe_path(client, base_url, "/v1/chat/completions", "HEAD")
    if err or resp is None:
        return None
    accept = resp.headers.get("accept", "").lower()
    return "event-stream" in accept or resp.headers.get("x-accel-buffering") == "no"


async def _test_max_output_tokens(
    client: httpx.AsyncClient, base_url: str,
    api_format: str, model: str, timing: TimingConfig,
) -> Optional[int]:
    """
    Binary-search estimate of max_tokens limit.
    Try 4096, 8192, 16384, 32768. Return the highest that doesn't error.
    """
    candidates = [4096, 8192, 16384, 32768, 65536, 131072]
    path = "/v1/chat/completions" if api_format != "anthropic" else "/v1/messages"
    last_ok = None

    for limit in candidates:
        if api_format == "anthropic":
            body = {
                "model": model,
                "max_tokens": limit,
                "messages": [{"role": "user", "content": "Say hi"}],
            }
        else:
            body = {
                "model": model,
                "max_tokens": limit,
                "messages": [{"role": "user", "content": "Say hi"}],
            }
        resp, _, err = await probe_path(client, base_url, path, "POST", body)
        if err or resp is None:
            break
        if resp.status_code in (200,):
            last_ok = limit
        elif resp.status_code == 400:
            try:
                data = resp.json()
                err_str = str(data).lower()
                if "max_tokens" in err_str or "token" in err_str:
                    break
            except Exception:
                break
    return last_ok


def _default_model(api_format: str) -> str:
    return {
        "anthropic": "claude-3-haiku-20240307",
        "ollama":    "llama3",
        "google":    "gemini-1.5-flash",
        "openai":    "gpt-3.5-turbo",
    }.get(api_format, "gpt-3.5-turbo")
