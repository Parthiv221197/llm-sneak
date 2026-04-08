"""
Phase 3 — Model Fingerprinting

Two strategies:

  OLLAMA  → ollama_deep_inspect()  (metadata API — 100% confidence)

  ALL OTHERS → behavioural probe packs
    - Tries WITHOUT an API key first (works on keyless local deployments,
      misconfigured cloud endpoints, etc.)
    - Falls back to key-based probing if unauthenticated requests are rejected
    - Caller supplies `access` result so we know what to attempt

This is the core of the HTB workflow: even on an unknown target with no
credentials, if the chat endpoint is open we can fingerprint the model.
"""
from __future__ import annotations

import asyncio
from collections import defaultdict
from pathlib import Path
from typing import Optional

import httpx

from llmsneak.models import AccessResult, ModelFingerprintResult, ProbeMatch
from llmsneak.phases.ollama_inspect import ollama_deep_inspect
from llmsneak.probes.loader import Probe, load_all_packs
from llmsneak.utils.http import chat_completion
from llmsneak.utils.timing import TimingConfig

DEFAULT_PROBE_LIMIT = 8   # raised from 6 — we have more packs now


async def fingerprint_model(
    client:     httpx.AsyncClient,
    base_url:   str,
    provider:   str,
    api_format: str,
    timing:     TimingConfig,
    api_key:    Optional[str] = None,
    model:      Optional[str] = None,
    probe_dir:  Optional[Path] = None,
    aggressive: bool = False,
    access:     Optional[AccessResult] = None,
) -> ModelFingerprintResult:
    """
    Fingerprint the model. Works without an API key when the endpoint
    allows unauthenticated access (common on local/misconfigured deployments).
    """
    # ── Ollama fast-path: direct metadata, no probes needed ───────────────────
    if provider == "ollama" or api_format == "ollama":
        return await ollama_deep_inspect(client, base_url, model)

    # ── Determine if we can probe at all ──────────────────────────────────────
    can_probe_keyless = (
        access is not None and
        (access.unauthenticated_chat or not access.requires_auth)
    )
    has_key = bool(api_key)

    if not can_probe_keyless and not has_key:
        return ModelFingerprintResult(
            model_family="unknown",
            exact_model="unknown",
            confidence=0.0,
            evidence=[
                "Endpoint requires authentication — no API key provided.",
                "Supply --api-key to enable behavioural fingerprinting.",
            ],
        )

    packs = load_all_packs(probe_dir)
    if not packs:
        return ModelFingerprintResult(evidence=["No probe packs found"])

    all_probes: dict[str, Probe] = {}
    for pack in packs:
        for probe in pack.probes:
            all_probes[probe.id] = probe

    probes = list(all_probes.values())
    if not aggressive:
        probes = probes[:DEFAULT_PROBE_LIMIT]

    sem     = asyncio.Semaphore(timing.max_concurrent)
    scores: dict[str, float] = defaultdict(float)
    matches: list[ProbeMatch] = []
    evidence: list[str]       = []
    auth_note = "(keyless — endpoint is open)" if can_probe_keyless and not has_key else ""

    async def _run_probe(probe: Probe) -> None:
        async with sem:
            if timing.delay_s > 0:
                await asyncio.sleep(timing.delay_s)

            messages     = _build_messages(probe)
            target_model = model or _default_model(api_format)

            content, latency, err = await chat_completion(
                client, base_url, messages,
                model=target_model,
                api_format=api_format,
            )
            if err or content is None:
                return

            snippet      = content[:120].replace("\n", " ")
            probe_scores = probe.score_response(content)
            for model_id, delta in probe_scores.items():
                scores[model_id] += delta
            if probe_scores:
                for model_id, delta in probe_scores.items():
                    evidence.append(
                        f"[{probe.id}] '{snippet[:60]}…' → +{delta:.2f} → {model_id}"
                    )
                matches.append(ProbeMatch(
                    probe_id=probe.id,
                    matched=True,
                    response_snippet=snippet,
                    latency_ms=round(latency, 1),
                ))

    await asyncio.gather(*[_run_probe(p) for p in probes])

    if not scores:
        return ModelFingerprintResult(
            evidence=[f"No probe matched — model may be unknown or heavily sandboxed {auth_note}"],
            probe_matches=matches,
        )

    best_model = max(scores, key=lambda k: scores[k])
    total      = sum(v for v in scores.values() if v > 0)
    confidence = min(scores[best_model] / total, 1.0) if total else 0.0

    ev_prefix = [f"Probed {auth_note}"] if auth_note else []

    return ModelFingerprintResult(
        model_family=_model_family(best_model),
        exact_model=best_model,
        confidence=round(confidence, 3),
        probe_matches=matches,
        evidence=ev_prefix + evidence[:12],
    )


def _build_messages(probe: Probe) -> list[dict]:
    msgs = list(probe.messages)
    if probe.system:
        msgs = [{"role": "system", "content": probe.system}] + msgs
    return msgs


def _default_model(api_format: str) -> str:
    return {
        "anthropic": "claude-3-haiku-20240307",
        "google":    "gemini-1.5-flash",
        "openai":    "gpt-3.5-turbo",
    }.get(api_format, "gpt-3.5-turbo")


def _model_family(model_id: str) -> str:
    m = model_id.lower()
    if "gpt-4o"      in m: return "GPT-4o"
    if "gpt-4"       in m: return "GPT-4"
    if "gpt-3.5"     in m: return "GPT-3.5"
    if "o1"          in m: return "OpenAI o1"
    if "o3"          in m: return "OpenAI o3"
    if "claude-3.5"  in m: return "Claude 3.5"
    if "claude-3"    in m: return "Claude 3"
    if "claude"      in m: return "Claude"
    if "gemini-2"    in m: return "Gemini 2"
    if "gemini-1.5"  in m: return "Gemini 1.5"
    if "gemini"      in m: return "Gemini"
    if "llama-3"     in m: return "LLaMA 3"
    if "llama3"      in m: return "LLaMA 3"
    if "llama"       in m: return "LLaMA"
    if "mistral"     in m: return "Mistral"
    if "mixtral"     in m: return "Mixtral"
    if "phi"         in m: return "Microsoft Phi"
    if "deepseek"    in m: return "DeepSeek"
    if "qwen"        in m: return "Qwen"
    if "gemma"       in m: return "Google Gemma"
    return "Unknown"
