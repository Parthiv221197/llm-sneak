"""
Core scan orchestrator.

Phases:
  0.5  Port Scan         No port given? Find which ports run LLMs automatically.
  1    Endpoint Disc.    Which API paths exist at this base URL?
  0    Access Check      Does this endpoint require authentication?
  2    Provider ID       Which vendor/software is this?
  3    Fingerprinting    Which exact model is running?
  4    Capabilities      What can it do? (tools, vision, streaming...)
  5    Guard Detection   Are safety filters active?
  6    Vuln Scan         OWASP LLM Top 10 quick screen
  7    MCP & Tools       Are there agent tools attached?

Key principle: start with NOTHING. Give it an IP and it finds the LLM,
identifies it, and assesses it — exactly like Nmap does for networks.
"""
from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Optional

import httpx

from llmsneak.models import AccessResult, ProviderResult, ScanResult
from llmsneak.output.renderer import (
    console,
    print_banner,
    print_scan_header,
    print_latency,
    print_port_scan,
    print_access,
    print_endpoints,
    print_provider,
    print_fingerprint,
    print_capabilities,
    print_guards,
    print_vulns,
    print_mcp,
    print_done,
    print_verbose,
)
from llmsneak.phases.port_scan    import scan_ports, extract_host, needs_port_scan
from llmsneak.phases.access       import assess_access
from llmsneak.phases.discovery    import discover_endpoints, fastest_open_endpoint
from llmsneak.phases.provider     import identify_provider
from llmsneak.phases.fingerprint  import fingerprint_model
from llmsneak.phases.enumerate    import enumerate_capabilities
from llmsneak.phases.guards       import detect_guards
from llmsneak.phases.vulns        import scan_vulnerabilities
from llmsneak.phases.mcp_detect   import detect_mcp
from llmsneak.utils.http          import build_client
from llmsneak.utils.timing        import TimingConfig


class ScanConfig:
    def __init__(self, args):
        # Resolve --profile first
        _profile_name = getattr(args, "profile", None)
        _host = None
        if _profile_name:
            from llmsneak.hosts import get_host
            _host = get_host(_profile_name)

        raw_target = getattr(args, "target", "") or ""
        if not raw_target and _host:
            raw_target = _host.base_url

        self.raw_target:     str            = raw_target
        self.target:         str            = _normalise_target(raw_target) if raw_target else ""
        self.api_key:        Optional[str]  = getattr(args, "api_key", None)
        self.model:          Optional[str]  = getattr(args, "model", None)
        self.profile:        Optional[str]  = _profile_name
        self.host_info:      object         = _host
        self.timing:         TimingConfig   = TimingConfig.from_level(getattr(args, "timing", 3))
        self.verbose:        int            = getattr(args, "verbose", 0)
        self.show_only_open: bool           = getattr(args, "open", False)
        self.probe_dir:      Optional[Path] = Path(args.probe_dir) if getattr(args, "probe_dir", None) else None
        self.api_format_override: Optional[str] = getattr(args, "api_format_override", None)

        # Port scan control
        # --no-port-scan disables auto-discovery even if no port given
        self.skip_port_scan: bool = getattr(args, "no_port_scan", False)
        # --ports 11434,8080 overrides which ports to scan
        _ports_raw = getattr(args, "scan_ports", None)
        self.custom_ports: Optional[list[int]] = (
            [int(p.strip()) for p in _ports_raw.split(",") if p.strip().isdigit()]
            if _ports_raw else None
        )

        # Phase flags
        self.discovery_only: bool = getattr(args, "discovery_only", False)
        self.version_detect:  bool = getattr(args, "version_detect", False) or getattr(args, "aggressive", False)
        self.aggressive:      bool = getattr(args, "aggressive", False)

        scripts_raw = getattr(args, "script", "") or ""
        self.scripts: set[str] = set(s.strip() for s in scripts_raw.split(",") if s.strip())
        if "all" in self.scripts:
            self.scripts = {"guards", "capabilities", "extract", "vuln", "mcp"}

        run_all = self.aggressive
        self.run_provider:     bool = not self.discovery_only
        self.run_fingerprint:  bool = self.version_detect or run_all
        self.run_capabilities: bool = run_all or "capabilities" in self.scripts
        self.run_guards:       bool = run_all or "guards" in self.scripts or "extract" in self.scripts
        self.run_vulns:        bool = run_all or "vuln" in self.scripts or "vulns" in self.scripts
        self.run_mcp:          bool = run_all or "mcp" in self.scripts or "tools" in self.scripts or "agents" in self.scripts

        paths_raw = getattr(args, "paths", None)
        self.custom_paths: Optional[list[tuple[str, str]]] = None
        if paths_raw:
            self.custom_paths = [(p.strip(), "custom") for p in paths_raw.split(",") if p.strip()]


def _normalise_target(target: str) -> str:
    """
    Add scheme if missing. Use http for local/LAN IPs and known LLM ports,
    https for everything else.
    """
    if "://" in target:
        return target.rstrip("/")

    LOCAL_HTTP_PORTS = (
        "11434","1234","8000","8080","5000","3000","7860",
        "8888","9000","1337","5001","3001","4000","7861",
        "8001","8002","8081","9997","5005",
    )
    is_local = (
        target.startswith("localhost")
        or target.startswith("127.")
        or target.startswith("0.0.0.0")
        or target.startswith("192.168.")
        or target.startswith("10.")
        or target.startswith("172.")
        or any(f":{p}" in target for p in LOCAL_HTTP_PORTS)
    )
    scheme = "http" if is_local else "https"
    return f"{scheme}://{target}".rstrip("/")


async def run_scan(cfg: ScanConfig) -> ScanResult:
    result = ScanResult(target=cfg.target, scan_start=time.time())

    print_banner()

    # ── Phase 0.5: Port Scan (only when no port specified in target) ──────────
    actual_target = cfg.target   # may be updated after port scan

    if not cfg.skip_port_scan and needs_port_scan(cfg.raw_target):
        host, _ = extract_host(cfg.raw_target)
        console.print(f"[bold dim][ Phase 0.5 ]  Port scan — searching for LLMs on {host}...[/]")

        port_result = await scan_ports(
            host     = host,
            timing   = cfg.timing,
            ports    = cfg.custom_ports,
            api_key  = cfg.api_key,
        )
        result.port_scan = port_result
        print_port_scan(port_result)

        if port_result.open_llm_ports:
            # Use the best discovered port as our target for remaining phases
            actual_target = port_result.best_target
            result.target = actual_target
            console.print(f"  [green]→[/] Targeting: [bold]{actual_target}[/]\n")
        elif port_result.open_ports:
            # Found open HTTP but not confirmed LLM — still try the first one
            actual_target = port_result.open_ports[0].base_url
            result.target = actual_target
            console.print(
                f"  [yellow]→[/] Found open port (not confirmed LLM): [bold]{actual_target}[/]\n"
                f"     Continuing scan — may not be an LLM endpoint.\n"
            )
        else:
            console.print(
                f"  [red]✗[/] No LLM services found on any known port on {host}.\n"
                f"     Is the service running? Try: ollama serve  OR  specify port manually.\n"
                f"     Example: llm-sneak {host}:11434\n"
            )
            result.scan_end = time.time()
            return result
    else:
        # Port given or scan skipped — use target as-is
        if cfg.skip_port_scan:
            console.print("[dim]  Port scan skipped (--no-port-scan)[/]\n")

    print_scan_header(actual_target)

    # ── Remaining phases use actual_target ────────────────────────────────────
    _format_hint = cfg.api_format_override
    if not _format_hint and cfg.api_key:
        if "anthropic.com" in actual_target:
            _format_hint = "anthropic"

    async with build_client(cfg.timing, cfg.api_key, _format_hint) as client:

        # ── Phase 1: Endpoint Discovery ───────────────────────────────────────
        console.print("[bold dim][ Phase 1 ]  Endpoint discovery...[/]")
        endpoints = await discover_endpoints(
            client, actual_target, cfg.timing,
            custom_paths=cfg.custom_paths,
            show_only_open=cfg.show_only_open,
            verbose=cfg.verbose,
        )
        result.endpoints = endpoints

        fastest = fastest_open_endpoint(endpoints)
        if fastest:
            print_latency(fastest.latency_ms)
        else:
            console.print("[yellow]  No open endpoints — target may be down or fully filtered.[/]\n")

        print_endpoints(endpoints, show_all=cfg.verbose > 0)

        if cfg.discovery_only:
            result.scan_end = time.time()
            print_done(result)
            return result

        # ── Phase 0: Access Assessment ────────────────────────────────────────
        console.print("[bold dim][ Phase 0 ]  Access assessment (auth check)...[/]")
        access = await assess_access(client, actual_target, endpoints, cfg.timing)
        result.access = access
        print_access(access)

        # ── Phase 2: Provider Identification ──────────────────────────────────
        if cfg.run_provider:
            console.print("[bold dim][ Phase 2 ]  Provider identification...[/]")
            provider = await identify_provider(client, actual_target, endpoints, cfg.timing)
            result.provider = provider
            print_provider(provider)
        else:
            result.provider = ProviderResult(provider="unknown", api_format="openai")

        api_format    = (
            cfg.api_format_override
            or (result.provider.api_format if result.provider else "openai")
        )
        provider_name = result.provider.provider if result.provider else "unknown"

        # Use format hint from port scan if we got Ollama detection
        if (not cfg.api_format_override and result.port_scan
                and result.port_scan.open_llm_ports):
            detected_fmt = result.port_scan.open_llm_ports[0].api_format
            if detected_fmt and api_format == "openai":
                api_format = detected_fmt

        # ── Phase 3: Model Fingerprinting ─────────────────────────────────────
        if cfg.run_fingerprint:
            console.print("[bold dim][ Phase 3 ]  Model fingerprinting...[/]")
            if not cfg.api_key and not access.unauthenticated_chat and access.requires_auth:
                console.print(
                    "  [yellow]⚠[/]  Endpoint requires auth — no --api-key provided.\n"
                    "      Provide --api-key to enable behavioural fingerprinting.\n"
                )
            fingerprint = await fingerprint_model(
                client, actual_target,
                provider=provider_name,
                api_format=api_format,
                timing=cfg.timing,
                api_key=cfg.api_key,
                model=cfg.model,
                probe_dir=cfg.probe_dir,
                aggressive=cfg.aggressive,
                access=access,
            )
            result.fingerprint = fingerprint
            print_fingerprint(fingerprint)
        else:
            console.print("[dim]  Fingerprinting skipped — use -sV or -A[/]\n")

        # ── Phase 4: Capability Enumeration ───────────────────────────────────
        if cfg.run_capabilities:
            console.print("[bold dim][ Phase 4 ]  Capability enumeration...[/]")
            capabilities = await enumerate_capabilities(
                client, actual_target,
                api_format=api_format,
                timing=cfg.timing,
                api_key=cfg.api_key,
                model=cfg.model,
            )
            result.capabilities = capabilities
            print_capabilities(capabilities)
        else:
            console.print("[dim]  Capability scan skipped — use --script capabilities or -A[/]\n")

        # ── Phase 5: Guard Detection ───────────────────────────────────────────
        if cfg.run_guards:
            console.print("[bold dim][ Phase 5 ]  Guard detection...[/]")
            can_guard = cfg.api_key or access.unauthenticated_chat
            if not can_guard:
                console.print("  [yellow]⚠[/]  Guard detection needs --api-key or open endpoint.\n")
            else:
                guards = await detect_guards(
                    client, actual_target,
                    provider=provider_name,
                    api_format=api_format,
                    timing=cfg.timing,
                    api_key=cfg.api_key,
                    model=cfg.model,
                    aggressive=cfg.aggressive,
                )
                result.guards = guards
                print_guards(guards)
        else:
            console.print("[dim]  Guard scan skipped — use --script guards or -A[/]\n")

        # ── Phase 6: Vulnerability Scan ───────────────────────────────────────
        if cfg.run_vulns:
            console.print("[bold dim][ Phase 6 ]  Vulnerability scan (OWASP LLM Top 10)...[/]")
            can_vuln = cfg.api_key or access.unauthenticated_chat
            if not can_vuln:
                console.print("  [yellow]⚠[/]  Vuln scan needs --api-key or open endpoint.\n")
            else:
                vulns = await scan_vulnerabilities(
                    client, actual_target,
                    api_format=api_format,
                    timing=cfg.timing,
                    api_key=cfg.api_key,
                    model=cfg.model,
                    aggressive=cfg.aggressive,
                )
                result.vulns = vulns
                print_vulns(vulns)
        else:
            console.print("[dim]  Vuln scan skipped — use --script vuln or -A[/]\n")

        # ── Phase 7: MCP & Agent Tool Detection ─────────────────────────────
        if cfg.run_mcp:
            console.print("[bold dim][ Phase 7 ]  MCP server + agent tool detection...[/]")
            mcp = await detect_mcp(
                client, actual_target,
                api_format=api_format,
                timing=cfg.timing,
                api_key=cfg.api_key,
                model=cfg.model,
            )
            result.mcp = mcp
            print_mcp(mcp)
        else:
            console.print("[dim]  MCP scan skipped — use --script mcp or -A[/]\n")

    result.scan_end = time.time()
    print_done(result)
    return result


def scan(args) -> ScanResult:
    cfg = ScanConfig(args)
    return asyncio.run(run_scan(cfg))
