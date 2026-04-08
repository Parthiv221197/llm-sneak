"""
Terminal output renderer — makes LLMSneak look like Nmap.
Uses Rich for color, tables, and panels.
"""
from __future__ import annotations

import datetime
from typing import Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from llmsneak.constants import BANNER, HOMEPAGE, VERSION
from llmsneak.models import (
    CapabilityResult,
    EndpointResult,
    EndpointState,
    GuardResult,
    ModelFingerprintResult,
    ProviderResult,
    ScanResult,
)

console = Console(highlight=False)


# ────────────────────────────────────────────────────────────────────────────
# Banner
# ────────────────────────────────────────────────────────────────────────────

def print_banner() -> None:
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M %Z")
    console.print(
        f"[bold cyan]Starting {BANNER}[/] [dim]( {HOMEPAGE} )[/] [dim]at {now}[/]",
        highlight=False,
    )
    console.print()


def print_scan_header(target: str) -> None:
    console.print(f"[bold]LLMSneak scan report for[/] [bold green]{target}[/]")


def print_access(result) -> None:
    """Print Phase 0 — Access Assessment result."""
    console.print("[bold cyan]ACCESS ASSESSMENT[/]")

    if not result.requires_auth:
        console.print(
            f"  [bold]Auth Required:[/]  [bold green]NO[/]  "
            f"[bold red]⚠  SECURITY FINDING[/]"
        )
        if result.unauthenticated_chat:
            console.print("  [bold red]  → Chat endpoint accepts prompts WITHOUT authentication[/]")
        if result.unauthenticated_models:
            console.print("  [yellow]  → Model list accessible without authentication[/]")
        if result.open_endpoints:
            console.print(f"  [bold]Open paths:[/]")
            for ep in result.open_endpoints:
                console.print(f"    [green]○[/]  {ep}  [dim](no auth required)[/]")
    else:
        console.print(f"  [bold]Auth Required:[/]  [green]YES[/]  [dim](endpoint is protected)[/]")
        if result.auth_type and result.auth_type not in ("unknown", "none"):
            console.print(f"  [bold]Auth Type:[/]      [cyan]{result.auth_type}[/]")
        else:
            console.print(f"  [dim]Auth type not determined — try --api-key to proceed[/]")

    console.print()


def print_latency(latency_ms: float) -> None:
    console.print(f"[dim]Target responded[/] [cyan]({latency_ms:.1f}ms latency)[/]")
    console.print()


# ────────────────────────────────────────────────────────────────────────────
# Phase 1 — Endpoints
# ────────────────────────────────────────────────────────────────────────────

def print_endpoints(endpoints: list[EndpointResult], show_all: bool = False) -> None:
    visible = endpoints if show_all else [
        e for e in endpoints if e.state in (EndpointState.OPEN, EndpointState.FILTERED)
    ]
    if not visible:
        console.print("[dim]No open endpoints found.[/]")
        return

    table = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold cyan",
        expand=False,
        padding=(0, 1),
    )
    table.add_column("PATH",        style="", min_width=32)
    table.add_column("STATE",       min_width=10)
    table.add_column("SERVICE",     style="dim", min_width=16)
    table.add_column("STATUS",      justify="right", style="dim")
    table.add_column("LATENCY",     justify="right", style="dim")

    for ep in visible:
        state_text = Text(ep.state.value)
        state_text.stylize(ep.state_color())

        status_str = str(ep.status_code) if ep.status_code else "-"
        latency_str = f"{ep.latency_ms:.0f}ms" if ep.latency_ms else "-"

        table.add_row(ep.path, state_text, ep.service, status_str, latency_str)

    console.print("[bold cyan]ENDPOINT SCAN RESULTS[/]")
    console.print(table)


# ────────────────────────────────────────────────────────────────────────────
# Phase 2 — Provider
# ────────────────────────────────────────────────────────────────────────────

def print_provider(result: ProviderResult) -> None:
    console.print("[bold cyan]PROVIDER DETECTION[/]")

    conf_color = result.confidence_color
    conf_label = result.confidence_label
    pct        = f"{result.confidence * 100:.0f}%"

    console.print(
        f"  [bold]Provider:[/]   "
        f"[bold {conf_color}]{result.provider.upper()}[/]  "
        f"[dim](confidence: [{conf_color}]{conf_label}[/] {pct})[/]"
    )
    console.print(f"  [bold]API Style:[/]  [cyan]{result.api_format}[/]")

    if result.evidence:
        console.print("  [bold]Evidence:[/]")
        for ev in result.evidence[:6]:
            console.print(f"    [dim]○[/] {ev}")
    console.print()


# ────────────────────────────────────────────────────────────────────────────
# Phase 3 — Fingerprint
# ────────────────────────────────────────────────────────────────────────────

def print_fingerprint(result: ModelFingerprintResult) -> None:
    console.print("[bold cyan]MODEL FINGERPRINT[/]")

    conf_color = result.confidence_color
    conf_label = result.confidence_label
    pct        = f"{result.confidence * 100:.0f}%"

    # Model name + confidence badge
    console.print(
        f"  [bold]Model:[/]          "
        f"[bold {conf_color}]{result.exact_model}[/]  "
        f"[dim](confidence: [{conf_color}]{conf_label}[/] {pct})[/]"
    )
    console.print(f"  [bold]Family:[/]         [cyan]{result.model_family}[/]")

    # Ollama-specific rich fields
    if getattr(result, "parameter_size", None):
        console.print(f"  [bold]Parameters:[/]     [cyan]{result.parameter_size}[/]")

    if getattr(result, "quantization", None):
        from llmsneak.phases.ollama_inspect import QUANT_QUALITY
        quant     = result.quantization
        quant_tip = QUANT_QUALITY.get(quant, "")
        tip_str   = f"  [dim]{quant_tip}[/]" if quant_tip else ""
        console.print(f"  [bold]Quantization:[/]   [cyan]{quant}[/]{tip_str}")

    if getattr(result, "format", None) and result.format not in ("unknown", None):
        console.print(f"  [bold]Format:[/]         [dim]{result.format}[/]")

    if result.context_window:
        console.print(f"  [bold]Context window:[/] [cyan]{result.context_window:,}[/] tokens")

    if getattr(result, "ollama_size_gb", None):
        console.print(f"  [bold]Disk size:[/]      [dim]{result.ollama_size_gb} GB[/]")

    if getattr(result, "ollama_modified", None):
        console.print(f"  [bold]Last modified:[/]  [dim]{result.ollama_modified}[/]")

    if getattr(result, "ollama_digest", None):
        console.print(f"  [bold]Digest:[/]         [dim]{result.ollama_digest}…[/]")

    # All models on the server (Ollama only)
    all_models = getattr(result, "all_local_models", [])
    if len(all_models) > 1:
        others = [m for m in all_models if m not in result.exact_model]
        if others:
            console.print(f"  [bold]Other models:[/]   [dim]{', '.join(others)}[/]")

    if result.streaming_supported is not None:
        stream_str = "[green]supported[/]" if result.streaming_supported else "[red]not detected[/]"
        console.print(f"  [bold]Streaming:[/]      {stream_str}")

    if result.evidence:
        console.print("  [bold]Evidence:[/]")
        for ev in result.evidence[:8]:
            console.print(f"    [dim]○[/]  {ev}")
    console.print()


# ────────────────────────────────────────────────────────────────────────────
# Phase 4 — Capabilities
# ────────────────────────────────────────────────────────────────────────────

def _cap(val: Optional[bool]) -> Text:
    if val is True:   return Text("YES",     style="bold green")
    if val is False:  return Text("NO",      style="red")
    return Text("?",           style="dim")


def print_capabilities(result: CapabilityResult) -> None:
    console.print("[bold cyan]CAPABILITIES[/]")

    fields = [
        ("function_calling",  "Function Calling"),
        ("parallel_tools",    "Parallel Tools"),
        ("vision",            "Vision / Images"),
        ("json_mode",         "JSON Mode"),
        ("streaming",         "Streaming (SSE)"),
        ("system_prompt",     "System Prompt"),
        ("embeddings",        "Embeddings"),
        ("audio_tts",         "Audio (TTS)"),
        ("image_generation",  "Image Generation"),
    ]

    table = Table(
        box=None,
        show_header=False,
        padding=(0, 2),
    )
    table.add_column("cap",   style="dim", min_width=22)
    table.add_column("value", min_width=6)

    for attr, label in fields:
        val = getattr(result, attr, None)
        table.add_row(label, _cap(val))

    if result.max_output_tokens:
        table.add_row("Max Output Tokens", Text(f"~{result.max_output_tokens:,}", style="cyan"))

    console.print(table)
    console.print()


# ────────────────────────────────────────────────────────────────────────────
# Phase 5 — Guards
# ────────────────────────────────────────────────────────────────────────────

def print_guards(result: GuardResult) -> None:
    console.print("[bold cyan]GUARD DETECTION[/]")

    active_text = Text("ACTIVE", style="bold red") if result.safety_layer_active else Text("none detected", style="dim green")
    console.print(f"  [bold]Safety Layer:[/]  {active_text}")
    console.print(f"  [bold]Filter Type:[/]   [cyan]{result.filter_type}[/]")

    if result.probe_count > 0:
        pct = f"{result.refusal_rate * 100:.0f}%"
        color = "red" if result.refusal_rate > 0.5 else "yellow" if result.refusal_rate > 0.2 else "green"
        console.print(
            f"  [bold]Refusal Rate:[/]  [{color}]{pct}[/] "
            f"[dim]({result.refusal_count}/{result.probe_count} adversarial probes blocked)[/]"
        )

    if result.system_prompt_present:
        console.print(f"  [bold]System Prompt:[/] [yellow]PRESENT[/]")
    if result.system_prompt_leak:
        leak_preview = result.system_prompt_leak[:80].replace("\n", " ")
        console.print(f"  [bold]Leaked Snippet:[/] [bold yellow]\"{leak_preview}...\"[/]")

    if result.evidence:
        console.print("  [bold]Evidence:[/]")
        for ev in result.evidence[:5]:
            console.print(f"    [dim]○[/] {ev}")
    console.print()


# ────────────────────────────────────────────────────────────────────────────
# Footer
# ────────────────────────────────────────────────────────────────────────────

def print_done(result: ScanResult) -> None:
    n_open     = len(result.open_endpoints)
    n_filtered = len(result.filtered_endpoints)
    duration   = result.duration

    console.rule(style="dim")

    # Pentest summary line
    access_str = ""
    if result.access:
        if not result.access.requires_auth:
            access_str = "  [bold red]⚠ OPEN (no auth)[/]"
        else:
            access_str = "  [green]Protected[/]"

    fp_str = ""
    if result.fingerprint and result.fingerprint.exact_model != "unknown":
        fp_str = f"  Model: [cyan]{result.fingerprint.exact_model}[/]"

    vuln_str = ""
    if result.vulns and hasattr(result.vulns, "findings"):
        crits = sum(1 for f in result.vulns.findings if f.severity == "CRITICAL")
        highs = sum(1 for f in result.vulns.findings if f.severity == "HIGH")
        if crits or highs:
            vuln_str = f"  [bold red]{crits} CRITICAL  {highs} HIGH[/]"

    console.print(
        f"[bold]llm-sneak done:[/] 1 target | "
        f"[green]{n_open} open[/] [yellow]{n_filtered} filtered[/]{access_str}{fp_str}{vuln_str} | "
        f"[dim]{duration:.2f}s[/]"
    )

    if result.errors:
        console.print()
        for err in result.errors[:3]:
            console.print(f"  [red]✗[/] {err}")


def print_error(msg: str) -> None:
    console.print(f"[bold red]ERROR:[/] {msg}")


def print_verbose(msg: str, level: int, verbosity: int) -> None:
    if verbosity >= level:
        prefix = "[dim cyan]VERBOSE:[/]" if level == 1 else "[dim]DEBUG:[/]"
        console.print(f"{prefix} {msg}")


# ────────────────────────────────────────────────────────────────────────────
# Full result render (used at end of scan)
# ────────────────────────────────────────────────────────────────────────────

def render_result(result: ScanResult, args) -> None:
    """Render all collected scan results to the terminal."""
    print_scan_header(result.target)

    # Latency from fastest open endpoint
    open_eps = result.open_endpoints
    if open_eps:
        fastest = min(open_eps, key=lambda e: e.latency_ms)
        print_latency(fastest.latency_ms)

    if result.endpoints:
        show_all = getattr(args, "verbose", 0) > 0
        print_endpoints(result.endpoints, show_all=show_all)

    if result.provider:
        print_provider(result.provider)

    if result.fingerprint:
        print_fingerprint(result.fingerprint)

    if result.capabilities:
        print_capabilities(result.capabilities)

    if result.guards:
        print_guards(result.guards)

    print_done(result)


# ── Phase 6 — Vulnerability scan output ──────────────────────────────────────

def print_vulns(result) -> None:
    """Print VulnScanResult (imported lazily to avoid circular deps)."""
    from llmsneak.phases.vulns import SEVERITY_COLORS, SEVERITY_ORDER

    console.print("[bold cyan]VULNERABILITY SCAN  (--script vuln)[/]")
    console.print(f"  [dim]Tested: {result.tested} probes  |  "
                  f"Findings: {len(result.findings)}[/]\n")

    if not result.findings:
        console.print("  [bold green]✓  No vulnerabilities detected[/]\n")
        return

    # Group by severity
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        findings = [f for f in result.findings if f.severity == sev]
        if not findings:
            continue
        color = SEVERITY_COLORS[sev]
        console.print(f"  [{color}]── {sev} ({len(findings)}) ──────────────────────────────[/]")
        for f in findings:
            console.print(f"  [{color}]▶  {f.vuln_id}: {f.name}[/]")
            console.print(f"     [dim]{f.description[:120]}[/]")
            snippet = f.evidence[:100].replace("\n", " ")
            console.print(f"     [yellow]Evidence:[/] {snippet}")
            console.print(f"     [green]Fix:[/] {f.remediation[:100]}")
            if f.references:
                console.print(f"     [dim]Ref: {f.references[0]}[/]")
            console.print()


# ── Phase 7 — MCP output ────────────────────────────────────────────────────────

def print_mcp(result) -> None:
    """Print MCPResult — MCP server and tool enumeration."""
    console.print("[bold cyan]MCP / AGENT TOOL DETECTION[/]")

    if not result.servers:
        console.print("  [dim]No MCP servers detected on this target[/]\n")
        return

    for srv in result.servers:
        tag = "inferred" if "inferred" in srv.name else "confirmed"
        console.print(
            f"  [bold]MCP Server:[/]  [bold green]{srv.name}[/]  "
            f"[dim]({tag}, {srv.url})[/]"
        )
        if srv.version:
            console.print(f"  [bold]Version:[/]     {srv.version}")
        if srv.protocol_version:
            console.print(f"  [bold]Protocol:[/]    MCP {srv.protocol_version}")

        if srv.tools:
            console.print(f"  [bold]Tools ({len(srv.tools)}):[/]")
            for tool in srv.tools:
                risk = tool.risk_level
                color = {"CRITICAL": "bold red", "HIGH": "red",
                         "MEDIUM": "yellow", "LOW": "cyan"}.get(risk, "dim")
                console.print(
                    f"    [{color}]▶  {tool.name:<28}[/] "
                    f"[dim]{risk:<8}[/]  {tool.description[:60]}"
                )
        if srv.resources:
            console.print(f"  [bold]Resources:[/]   {', '.join(srv.resources[:5])}")
        console.print()

    # Risk summary
    risk = result.highest_risk
    risk_color = {"CRITICAL": "bold red", "HIGH": "red",
                  "MEDIUM": "yellow", "LOW": "cyan"}.get(risk, "dim")
    console.print(f"  [bold]Risk level:[/]  [{risk_color}]{risk}[/]  — {result.risk_summary}")

    # Capability flags
    flags = []
    if result.has_shell_access: flags.append("[bold red]Shell execution[/]")
    if result.has_code_exec:    flags.append("[bold red]Code execution[/]")
    if result.has_file_access:  flags.append("[red]File access[/]")
    if result.has_db_access:    flags.append("[red]Database access[/]")
    if result.has_web_access:   flags.append("[yellow]Web access (SSRF risk)[/]")
    if result.has_email_access: flags.append("[yellow]Email/calendar[/]")
    if flags:
        console.print(f"  [bold]Capabilities:[/] " + "  ".join(flags))

    # Evidence
    if result.evidence:
        console.print("  [bold]Evidence:[/]")
        for ev in result.evidence[:6]:
            console.print(f"    [dim]○[/]  {ev}")
    console.print()
