"""
Phase 0.5 — LLM Port Discovery

The core idea: you hand llm-sneak a hostname or IP and it finds the LLM.
You should not need to know what port it's running on.

This is what makes llm-sneak equivalent to Nmap rather than just a
URL checker. Nmap doesn't ask you "what port is SSH on?" — it finds it.
llm-sneak doesn't ask you "what port is your LLM on?" — it finds it.

Strategy
─────────
1. TCP connectivity check     — is the port even open?
2. HTTP probe                 — does it speak HTTP?
3. LLM fingerprint paths      — is there an LLM API at any known path?
4. Service classification     — which specific software is it?

The phase runs concurrently across all known LLM ports.
With T3 (default) timing: scans 22 ports in ~0.5–1.5 seconds.
With T5 (insane): ~0.1 seconds.

Ports scanned by default (22 total):
  11434  Ollama              1234   LM Studio
  8000   vLLM / FastAPI      8080   llama.cpp / TGI
  1337   Jan AI              5001   Kobold.cpp
  7860   Gradio/HuggingFace  8888   TGI / Jupyter
  3001   AnythingLLM         9000   LocalAI
  5000   tabbyAPI            4000   LiteLLM proxy
  3000   MCP server          ...and more

Skip this phase by providing a full URL with port, e.g.:
    llm-sneak http://localhost:11434    ← port given, skip scan
    llm-sneak 10.0.0.50                 ← no port, run port scan
"""
from __future__ import annotations

import asyncio
import socket
import time
from typing import Optional
from urllib.parse import urlparse

import httpx

from llmsneak.constants import (
    LLM_PORTS, LLM_PORT_SCAN_ORDER, LLM_PROBE_PATHS
)
from llmsneak.models import PortResult, PortScanResult
from llmsneak.utils.timing import TimingConfig


# Response body signatures that confirm an LLM is present
# These are checked in the HTTP response body of probe paths
_LLM_BODY_SIGNATURES = [
    # Ollama
    b'"models"',            b'"model"',         b'"digest"',
    b'"parameter_size"',    b'"modified_at"',
    # OpenAI-compatible
    b'"object":"model"',    b'"owned_by"',       b'"created"',
    b'"choices"',           b'"usage"',
    # Generic chat/inference
    b'"generated_text"',    b'"response"',       b'"completion"',
    b'"message"',
    # Errors that still confirm an LLM API
    b'model not found',     b'no model loaded',  b'ollama',
    b'llama',               b'mistral',          b'gpt',
    b'anthropic',           b'huggingface',
]

# HTTP headers that strongly indicate an LLM API (not a generic web server)
_LLM_HEADER_SIGNATURES = [
    "openai-processing-ms",
    "anthropic-ratelimit",
    "x-ratelimit-limit-tokens",
    "ollama",
]


async def scan_ports(
    host:         str,
    timing:       TimingConfig,
    ports:        Optional[list[int]] = None,
    api_key:      Optional[str]       = None,
) -> PortScanResult:
    """
    Scan all known LLM ports on `host` and return results.

    Args:
        host:    Bare hostname or IP (no scheme, no port, no path).
        timing:  Controls concurrency and delay between probes.
        ports:   Override the default port list (None = scan all LLM_PORTS).
        api_key: Optional — passed in auth header if provided.
    """
    port_list = ports if ports is not None else LLM_PORT_SCAN_ORDER
    start     = time.monotonic()
    result    = PortScanResult(host=host, ports_scanned=len(port_list))

    # Semaphore controls how many ports we probe concurrently
    # Use higher concurrency than endpoint scan — we're checking TCP, not chatting
    max_conc = max(timing.max_concurrent * 3, 10)
    sem = asyncio.Semaphore(max_conc)

    async def _probe_port(port: int) -> PortResult:
        async with sem:
            return await _probe_single_port(host, port, timing, api_key)

    port_results = await asyncio.gather(*[_probe_port(p) for p in port_list])

    for pr in port_results:
        if pr.is_llm:
            result.open_llm_ports.append(pr)
        elif pr.state == "open":
            result.open_ports.append(pr)

    # Sort: Ollama first (best metadata), then by port number
    result.open_llm_ports.sort(
        key=lambda r: (0 if r.api_format == "ollama" else 1, r.port)
    )

    result.duration_ms = (time.monotonic() - start) * 1000
    return result


async def _probe_single_port(
    host:    str,
    port:    int,
    timing:  TimingConfig,
    api_key: Optional[str],
) -> PortResult:
    """
    Full probe sequence for one port:
      1. TCP connect (socket)  — fast, confirms port is open
      2. HTTP GET /            — confirms HTTP
      3. LLM path probes       — confirms LLM API
    """
    known   = LLM_PORTS.get(port, ("Unknown", "openai", "http"))
    service, api_hint, default_scheme = known

    # Determine scheme: try HTTP first for known-HTTP ports, HTTPS for 443/8443
    scheme   = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{host}:{port}"

    pr = PortResult(
        port=port, host=host,
        service=service, api_format=api_hint,
        scheme=scheme, base_url=base_url,
    )

    # ── Step 1: TCP connect ────────────────────────────────────────────────────
    if not await _tcp_connect(host, port, timeout=min(timing.timeout_s, 2.0)):
        pr.state = "closed"
        return pr

    # ── Step 2: HTTP probe ─────────────────────────────────────────────────────
    http_ok, banner, headers, latency = await _http_probe(base_url, api_key, timing)
    pr.latency_ms = latency
    pr.banner     = banner[:120] if banner else ""

    if not http_ok:
        pr.state = "filtered"   # TCP open but no valid HTTP
        return pr

    pr.state = "open"

    # Check headers for LLM signals
    header_evidence = _check_headers(headers)
    pr.evidence.extend(header_evidence)

    # ── Step 3: LLM path probes ────────────────────────────────────────────────
    is_llm, path_evidence, detected_service, detected_format = \
        await _probe_llm_paths(base_url, api_key, timing)

    pr.evidence.extend(path_evidence)

    if is_llm or header_evidence:
        pr.state      = "open-llm"
        pr.is_llm     = True
        if detected_service:
            pr.service    = detected_service
        if detected_format:
            pr.api_format = detected_format
    elif header_evidence:
        pr.state   = "open-llm"
        pr.is_llm  = True

    return pr


async def _tcp_connect(host: str, port: int, timeout: float = 2.0) -> bool:
    """Non-blocking TCP connect to test if port is open."""
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except (ConnectionRefusedError, OSError, asyncio.TimeoutError):
        return False


async def _http_probe(
    base_url: str,
    api_key:  Optional[str],
    timing:   TimingConfig,
) -> tuple[bool, str, dict, float]:
    """
    Send a GET / to the port and return (success, banner, headers, latency_ms).
    """
    headers = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    headers["User-Agent"] = "llm-sneak/0.1.0"

    start = time.monotonic()
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(min(timing.timeout_s, 3.0)),
            follow_redirects=True,
            verify=False,             # self-signed certs common on local servers
        ) as client:
            resp = await client.get(base_url + "/", headers=headers)
            latency = (time.monotonic() - start) * 1000

            banner = ""
            try:
                text = resp.text[:200]
                banner = text.replace("\n", " ").strip()
            except Exception:
                pass

            return True, banner, dict(resp.headers), latency
    except httpx.ConnectError:
        latency = (time.monotonic() - start) * 1000
        # Port is TCP-open but refused HTTP — might be HTTPS
        return False, "", {}, latency
    except Exception:
        latency = (time.monotonic() - start) * 1000
        return False, "", {}, latency


async def _probe_llm_paths(
    base_url: str,
    api_key:  Optional[str],
    timing:   TimingConfig,
) -> tuple[bool, list[str], str, str]:
    """
    Try known LLM API paths and check response bodies for LLM signatures.
    Returns (is_llm, evidence, service_name, api_format).
    """
    headers_req = {"User-Agent": "llm-sneak/0.1.0", "Accept": "application/json"}
    if api_key:
        headers_req["Authorization"] = f"Bearer {api_key}"

    evidence       = []
    detected_svc   = ""
    detected_fmt   = ""

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(min(timing.timeout_s, 3.0)),
        follow_redirects=True,
        verify=False,
    ) as client:
        for path, description in LLM_PROBE_PATHS:
            try:
                resp = await client.get(base_url + path, headers=headers_req)
            except Exception:
                continue

            if resp.status_code not in (200, 400, 401, 403, 404, 429, 500):
                continue

            body_lower = resp.content.lower()

            # Check body for LLM signatures
            matched_sigs = [
                sig.decode() for sig in _LLM_BODY_SIGNATURES
                if sig in body_lower
            ]

            if resp.status_code == 200 and matched_sigs:
                evidence.append(
                    f"{path} → HTTP {resp.status_code} — "
                    f"LLM signature: {matched_sigs[0]}"
                )

                # Detect specific service from body
                svc, fmt = _classify_from_body(body_lower)
                if svc and not detected_svc:
                    detected_svc = svc
                    detected_fmt = fmt

                return True, evidence, detected_svc, detected_fmt

            elif resp.status_code in (400, 401) and matched_sigs:
                # Auth required but LLM confirmed
                evidence.append(
                    f"{path} → HTTP {resp.status_code} (auth required) — "
                    f"LLM signature: {matched_sigs[0]}"
                )
                svc, fmt = _classify_from_body(body_lower)
                if svc:
                    detected_svc = svc
                    detected_fmt = fmt
                return True, evidence, detected_svc, detected_fmt

            elif resp.status_code == 200:
                # 200 but no LLM signature — might still be LLM with unusual response
                if path in ("/health", "/healthz"):
                    evidence.append(f"{path} → HTTP 200 (health OK)")

    return bool(evidence), evidence, detected_svc, detected_fmt


def _classify_from_body(body_lower: bytes) -> tuple[str, str]:
    """Detect service name and API format from response body bytes.
    Input should already be lowercased (body.lower()), but we lowercase
    again defensively for safety."""
    body_lower = body_lower.lower()
    if b'"modified_at"' in body_lower or b'ollama' in body_lower:
        return "Ollama", "ollama"
    if b'"owned_by"' in body_lower or b'"object":"model"' in body_lower:
        return "OpenAI-compatible", "openai"
    if b'"model_version"' in body_lower and b'"framework"' in body_lower:
        return "Triton Inference Server", "openai"
    if b'text-generation-inference' in body_lower or b'"generated_text"' in body_lower:
        return "HuggingFace TGI", "openai"
    if b'vllm' in body_lower:
        return "vLLM", "openai"
    if b'llama.cpp' in body_lower:
        return "llama.cpp", "openai"
    if b'kobold' in body_lower:
        return "Kobold.cpp", "openai"
    if b'tabby' in body_lower:
        return "tabbyAPI", "openai"
    if b'xinference' in body_lower:
        return "Xinference", "openai"
    if b'litellm' in body_lower:
        return "LiteLLM", "openai"
    if b'"choices"' in body_lower or b'"usage"' in body_lower:
        return "OpenAI-compatible", "openai"
    return "", ""


def _check_headers(headers: dict) -> list[str]:
    """Check HTTP response headers for LLM API signatures.
    Uses prefix matching so 'anthropic-ratelimit' matches
    'anthropic-ratelimit-requests-limit' etc."""
    evidence = []
    h_keys = {k.lower() for k in headers.keys()}
    for sig in _LLM_HEADER_SIGNATURES:
        # Check exact match OR any header starts with this signature
        if any(k == sig or k.startswith(sig) for k in h_keys):
            evidence.append(f"Header '{sig}' detected")
    return evidence


def extract_host(target: str) -> tuple[str, Optional[int]]:
    """
    Parse a user-supplied target and return (host, port).
    Returns port=None if no port was specified.

    Examples:
        "10.0.0.50"              → ("10.0.0.50", None)
        "10.0.0.50:11434"        → ("10.0.0.50", 11434)
        "https://api.example.com" → ("api.example.com", None)
        "http://localhost:8080"   → ("localhost", 8080)
        "localhost"              → ("localhost", None)
    """
    # Strip scheme if present
    if "://" in target:
        parsed = urlparse(target)
        host   = parsed.hostname or target
        port   = parsed.port
        return host, port

    # host:port format
    if ":" in target:
        parts = target.rsplit(":", 1)
        try:
            return parts[0], int(parts[1])
        except ValueError:
            pass

    return target, None


def needs_port_scan(target: str) -> bool:
    """
    Returns True if the target has no port specified
    (meaning we should run the port scan phase).
    """
    _, port = extract_host(target)
    return port is None
