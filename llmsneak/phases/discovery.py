"""
Phase 1 — Endpoint Discovery
Probes all known LLM API paths and classifies them as open/filtered/closed.
Analogous to Nmap's port scan (-sn / default scan).
"""
from __future__ import annotations

import asyncio
from typing import Optional

import httpx

from llmsneak.constants import KNOWN_ENDPOINTS, STATUS_STATE_MAP
from llmsneak.models import EndpointResult, EndpointState
from llmsneak.utils.http import probe_path
from llmsneak.utils.timing import TimingConfig


async def discover_endpoints(
    client:       httpx.AsyncClient,
    base_url:     str,
    timing:       TimingConfig,
    custom_paths: Optional[list[tuple[str, str]]] = None,
    show_only_open: bool = False,
    verbose:      int = 0,
) -> list[EndpointResult]:
    """
    Probe all known (or custom) endpoint paths concurrently.
    Returns a sorted list of EndpointResult objects.
    """
    targets = custom_paths if custom_paths else KNOWN_ENDPOINTS

    sem = asyncio.Semaphore(timing.max_concurrent)
    results: list[EndpointResult] = []

    async def _probe(path: str, service: str) -> EndpointResult:
        async with sem:
            if timing.delay_s > 0:
                await asyncio.sleep(timing.delay_s)

            # Try HEAD first (cheap), fall back to GET for real content
            resp, latency, err = await probe_path(client, base_url, path, "HEAD")

            # Some servers don't support HEAD; retry with GET
            if resp is not None and resp.status_code == 405:
                resp, latency, err = await probe_path(client, base_url, path, "GET")

            if err == "timeout":
                return EndpointResult(
                    path=path, state=EndpointState.UNKNOWN,
                    service=service, latency_ms=latency, error="timeout"
                )
            if err or resp is None:
                return EndpointResult(
                    path=path, state=EndpointState.CLOSED,
                    service=service, latency_ms=latency, error=err
                )

            state_str = STATUS_STATE_MAP.get(resp.status_code, "closed")
            state = EndpointState(state_str)

            return EndpointResult(
                path=path,
                state=state,
                service=service,
                latency_ms=round(latency, 1),
                status_code=resp.status_code,
                headers=dict(resp.headers),
            )

    tasks = [_probe(path, svc) for path, svc in targets]
    results = await asyncio.gather(*tasks)

    # Deduplicate same path (e.g. /v1/chat/completions appears in multiple packs)
    seen: dict[str, EndpointResult] = {}
    for r in results:
        key = r.path
        if key not in seen or r.state.value == "open":
            seen[key] = r

    ordered = sorted(seen.values(), key=lambda r: (r.state.value != "open", r.path))

    if show_only_open:
        ordered = [r for r in ordered if r.state == EndpointState.OPEN]

    return ordered


def fastest_open_endpoint(endpoints: list[EndpointResult]) -> Optional[EndpointResult]:
    """Return the open endpoint with lowest latency — used for latency reporting."""
    open_eps = [e for e in endpoints if e.state == EndpointState.OPEN]
    if not open_eps:
        return None
    return min(open_eps, key=lambda e: e.latency_ms)


def best_chat_endpoint(endpoints: list[EndpointResult]) -> Optional[EndpointResult]:
    """Return the best open chat endpoint for subsequent probing."""
    preferred_paths = [
        "/v1/chat/completions",
        "/v1/messages",
        "/api/chat",
        "/api/generate",
        "/v1/generate",
    ]
    open_map = {e.path: e for e in endpoints if e.state in (EndpointState.OPEN, EndpointState.FILTERED)}
    for p in preferred_paths:
        if p in open_map:
            return open_map[p]
    # Fall back to any chat service
    for e in endpoints:
        if "chat" in e.service and e.state != EndpointState.CLOSED:
            return e
    return None
