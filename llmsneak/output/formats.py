"""
File output formats: JSON (-oJ), normal text (-oN), grepable (-oG), XML (-oX).
Mirrors Nmap's -o* output flags.
"""
from __future__ import annotations

import dataclasses
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

from llmsneak.models import ScanResult


# ────────────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────────────

def _result_to_dict(result: ScanResult) -> dict:
    """Convert ScanResult to a JSON-serialisable dict."""
    def _dc(obj):
        if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
            return {k: _dc(v) for k, v in dataclasses.asdict(obj).items()}
        if isinstance(obj, list):
            return [_dc(i) for i in obj]
        if hasattr(obj, "value"):   # Enum
            return obj.value
        return obj

    return _dc(result)


# ────────────────────────────────────────────────────────────────────────────
# JSON  (-oJ)
# ────────────────────────────────────────────────────────────────────────────

def write_json(result: ScanResult, path: str) -> None:
    data = _result_to_dict(result)
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")


# ────────────────────────────────────────────────────────────────────────────
# Normal text  (-oN)
# ────────────────────────────────────────────────────────────────────────────

def write_normal(result: ScanResult, path: str) -> None:
    lines: list[str] = []
    lines.append(f"# LLMSneak scan report for {result.target}")
    lines.append(f"# Scanned at: {result.scan_start}")
    lines.append(f"# Duration:   {result.duration:.2f}s")
    lines.append("")

    # Endpoints
    lines.append("ENDPOINTS:")
    for ep in result.endpoints:
        if ep.state.value in ("open", "filtered"):
            lines.append(f"  {ep.path:<36} {ep.state.value:<10} {ep.service:<20} {ep.status_code}")
    lines.append("")

    # Provider
    if result.provider:
        p = result.provider
        lines.append(f"PROVIDER: {p.provider} (confidence={p.confidence_label} {p.confidence:.2f})")
        lines.append(f"API_FORMAT: {p.api_format}")
        for ev in p.evidence:
            lines.append(f"  EVIDENCE: {ev}")
    lines.append("")

    # Fingerprint
    if result.fingerprint:
        f = result.fingerprint
        lines.append(f"MODEL: {f.exact_model} (confidence={f.confidence_label} {f.confidence:.2f})")
        lines.append(f"FAMILY: {f.model_family}")
        if f.context_window:
            lines.append(f"CONTEXT_WINDOW: ~{f.context_window}")
    lines.append("")

    # Capabilities
    if result.capabilities:
        c = result.capabilities
        for attr in ["function_calling","vision","json_mode","streaming","system_prompt"]:
            val = getattr(c, attr, None)
            val_str = "YES" if val is True else "NO" if val is False else "UNKNOWN"
            lines.append(f"CAPABILITY: {attr.upper()}: {val_str}")
    lines.append("")

    # Guards
    if result.guards:
        g = result.guards
        lines.append(f"SAFETY_LAYER: {'ACTIVE' if g.safety_layer_active else 'INACTIVE'}")
        lines.append(f"FILTER_TYPE: {g.filter_type}")
        lines.append(f"REFUSAL_RATE: {g.refusal_rate:.0%} ({g.refusal_count}/{g.probe_count})")
        if g.system_prompt_leak:
            lines.append(f"SYSTEM_PROMPT_LEAK: {g.system_prompt_leak[:100]}")

    Path(path).write_text("\n".join(lines), encoding="utf-8")


# ────────────────────────────────────────────────────────────────────────────
# Grepable  (-oG)
# ────────────────────────────────────────────────────────────────────────────

def write_grepable(result: ScanResult, path: str) -> None:
    """Single-line grepable format — easy to pipe to awk/grep."""
    parts: list[str] = [f"Host: {result.target}"]

    open_eps  = "/".join(e.path for e in result.endpoints if e.state.value == "open")
    filt_eps  = "/".join(e.path for e in result.endpoints if e.state.value == "filtered")
    if open_eps:   parts.append(f"Open: {open_eps}")
    if filt_eps:   parts.append(f"Filtered: {filt_eps}")

    if result.provider:
        parts.append(f"Provider: {result.provider.provider}")
        parts.append(f"Confidence: {result.provider.confidence:.2f}")

    if result.fingerprint:
        parts.append(f"Model: {result.fingerprint.exact_model}")
        parts.append(f"ModelConfidence: {result.fingerprint.confidence:.2f}")

    if result.guards:
        parts.append(f"SafetyLayer: {'active' if result.guards.safety_layer_active else 'none'}")
        parts.append(f"RefusalRate: {result.guards.refusal_rate:.2f}")

    parts.append(f"Duration: {result.duration:.2f}s")

    Path(path).write_text("\t".join(parts) + "\n", encoding="utf-8")


# ────────────────────────────────────────────────────────────────────────────
# XML  (-oX)
# ────────────────────────────────────────────────────────────────────────────

def write_xml(result: ScanResult, path: str) -> None:
    root = ET.Element("llmsneak-scan", target=result.target,
                      duration=f"{result.duration:.2f}")

    endpoints_el = ET.SubElement(root, "endpoints")
    for ep in result.endpoints:
        ET.SubElement(endpoints_el, "endpoint",
                      path=ep.path,
                      state=ep.state.value,
                      service=ep.service,
                      status=str(ep.status_code),
                      latency_ms=f"{ep.latency_ms:.1f}")

    if result.provider:
        p = result.provider
        ET.SubElement(root, "provider",
                      name=p.provider,
                      confidence=f"{p.confidence:.3f}",
                      api_format=p.api_format)

    if result.fingerprint:
        f = result.fingerprint
        ET.SubElement(root, "fingerprint",
                      model=f.exact_model,
                      family=f.model_family,
                      confidence=f"{f.confidence:.3f}")

    if result.guards:
        g = result.guards
        ET.SubElement(root, "guards",
                      safety_layer=str(g.safety_layer_active),
                      filter_type=g.filter_type,
                      refusal_rate=f"{g.refusal_rate:.2f}")

    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")
    tree.write(path, encoding="utf-8", xml_declaration=True)


# ────────────────────────────────────────────────────────────────────────────
# Dispatch
# ────────────────────────────────────────────────────────────────────────────

def write_outputs(result: ScanResult, args) -> None:
    """Write all requested output files based on parsed CLI args."""
    import os

    def _write(fmt: str, filepath: str) -> None:
        try:
            {
                "json":    write_json,
                "normal":  write_normal,
                "grep":    write_grepable,
                "xml":     write_xml,
            }[fmt](result, filepath)
            print(f"Output saved: {filepath}")
        except Exception as e:
            print(f"Failed to write {filepath}: {e}")

    if getattr(args, "output_json",   None): _write("json",   args.output_json)
    if getattr(args, "output_normal", None): _write("normal", args.output_normal)
    if getattr(args, "output_grep",   None): _write("grep",   args.output_grep)
    if getattr(args, "output_xml",    None): _write("xml",    args.output_xml)

    if getattr(args, "output_all", None):
        base = args.output_all
        _write("normal", base + ".txt")
        _write("json",   base + ".json")
        _write("grep",   base + ".gnmap")
        _write("xml",    base + ".xml")
