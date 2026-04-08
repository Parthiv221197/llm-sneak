"""
Core scan orchestrator — the HTB-style pipeline:

  Phase 0  Access Assessment     Is authentication even required?
  Phase 1  Endpoint Discovery    What paths exist?
  Phase 2  Provider ID           What API format / provider?
  Phase 3  Model Fingerprinting  What model? (works keyless if endpoint is open)
  Phase 4  Capability Enum       What can it do?
  Phase 5  Guard Detection       How well defended is it?
  Phase 6  Vulnerability Scan    What can be exploited?

The key design principle: just like Nmap, you start with NOTHING and the
tool discovers everything progressively. No --api-key needed to get
meaningful intelligence on an open target.
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
from llmsneak.phases.access      import assess_access
from llmsneak.phases.discovery   import discover_endpoints, fastest_open_endpoint
from llmsneak.phases.provider    import identify_provider
from llmsneak.phases.fingerprint import fingerprint_model
from llmsneak.phases.enumerate   import enumerate_capabilities
from llmsneak.phases.guards      import detect_guards
from llmsneak.phases.vulns       import scan_vulnerabilities
from llmsneak.phases.mcp_detect  import detect_mcp
from llmsneak.utils.http         import build_client
from llmsneak.utils.timing       import TimingConfig


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

        self.target:         str            = _normalise_target(raw_target) if raw_target else ""
        self.api_key:        Optional[str]  = getattr(args, "api_key", None)
        self.model:          Optional[str]  = getattr(args, "model", None)
        self.profile:        Optional[str]  = _profile_name
        self.host_info:      object         = _host
        self.timing:         TimingConfig   = TimingConfig.from_level(getattr(args, "timing", 3))
        self.verbose:        int            = getattr(args, "verbose", 0)
        self.show_only_open: bool           = getattr(args, "open", False)
        self.probe_dir:      Optional[Path] = Path(args.probe_dir) if getattr(args, "probe_dir", None) else None

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
        self.run_mcp:         bool = run_all or "mcp" in self.scripts or "tools" in self.scripts or "agents" in self.scripts

        paths_raw = getattr(args, "paths", None)
        self.custom_paths: Optional[list[tuple[str, str]]] = None
        if paths_raw:
            self.custom_paths = [(p.strip(), "custom") for p in paths_raw.split(",") if p.strip()]


def _normalise_target(target: str) -> str:
    if "://" in target:
        return target.rstrip("/")
    LOCAL_HTTP_PORTS = ("11434", "1234", "8000", "8080", "5000", "3000", "7860", "8888", "9000")
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
    print_scan_header(cfg.target)

    async with build_client(cfg.timing, cfg.api_key) as client:

        # ── Phase 1: Endpoint Discovery ───────────────────────────────────────
        console.print("[bold dim][ Phase 1 ]  Endpoint discovery...[/]")
        endpoints = await discover_endpoints(
            client, cfg.target, cfg.timing,
            custom_paths=cfg.custom_paths,
            show_only_open=cfg.show_only_open,
            verbose=cfg.verbose,
        )
        result.endpoints = endpoints

        fastest = fastest_open_endpoint(endpoints)
        if fastest:
            print_latency(fastest.latency_ms)
        else:
            console.print("[yellow]  No open endpoints found — target may be down or fully filtered.[/]\n")

        print_endpoints(endpoints, show_all=cfg.verbose > 0)

        if cfg.discovery_only:
            result.scan_end = time.time()
            print_done(result)
            return result

        # ── Phase 0 (runs after P1): Access Assessment ────────────────────────
        console.print("[bold dim][ Phase 0 ]  Access assessment (auth check)...[/]")
        access = await assess_access(client, cfg.target, endpoints, cfg.timing)
        result.access = access
        print_access(access)

        # ── Phase 2: Provider Identification ──────────────────────────────────
        if cfg.run_provider:
            console.print("[bold dim][ Phase 2 ]  Provider identification...[/]")
            provider = await identify_provider(client, cfg.target, endpoints, cfg.timing)
            result.provider = provider
            print_provider(provider)
        else:
            result.provider = ProviderResult(provider="unknown", api_format="openai")

        api_format   = result.provider.api_format if result.provider else "openai"
        provider_name = result.provider.provider   if result.provider else "unknown"

        # ── Phase 3: Model Fingerprinting ─────────────────────────────────────
        if cfg.run_fingerprint:
            console.print("[bold dim][ Phase 3 ]  Model fingerprinting...[/]")
            if not cfg.api_key and not access.unauthenticated_chat and access.requires_auth:
                console.print("  [yellow]⚠[/]  Endpoint requires auth and no --api-key was given.\n"
                               "      Provide --api-key to enable behavioural fingerprinting.\n")
            fingerprint = await fingerprint_model(
                client, cfg.target,
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
                client, cfg.target,
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
                console.print("  [yellow]⚠[/]  Guard detection needs either --api-key or an open endpoint.\n")
            else:
                guards = await detect_guards(
                    client, cfg.target,
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
                console.print("  [yellow]⚠[/]  Vuln scan needs either --api-key or an open endpoint.\n")
            else:
                vulns = await scan_vulnerabilities(
                    client, cfg.target,
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
                client, cfg.target,
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
