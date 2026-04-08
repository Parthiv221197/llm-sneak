"""
LLMSneak CLI — Nmap-style argument parsing for LLM reconnaissance.

Usage mirrors Nmap as closely as possible so existing Nmap users
don't have to relearn their habits.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from llmsneak.constants import VERSION, HOMEPAGE
from llmsneak.output.formats import write_outputs
from llmsneak.output.renderer import console, print_error
from llmsneak.probes.loader import list_packs


# ────────────────────────────────────────────────────────────────────────────
# Help epilog (shown at bottom of --help)
# ────────────────────────────────────────────────────────────────────────────

EPILOG = f"""
EXAMPLES:
  Basic endpoint discovery (no API key needed):
    llmsneak https://api.openai.com
    llmsneak http://localhost:11434              # Ollama local instance

  Provider identification + endpoint discovery:
    llmsneak -sn https://api.example.com

  Model version detection (requires API key):
    llmsneak -sV --api-key sk-... https://api.openai.com

  Aggressive scan — all phases:
    llmsneak -A --api-key sk-... https://api.openai.com

  Target a specific model:
    llmsneak -A --api-key sk-... --model gpt-4o https://api.openai.com

  Run specific scripts only:
    llmsneak --script guards --api-key sk-... https://api.openai.com
    llmsneak --script capabilities,guards --api-key sk-... https://api.openai.com
    llmsneak --script all --api-key sk-... https://api.openai.com

  MCP / agent tool detection:
    llm-sneak --script mcp --model llama3 http://localhost:11434
    llm-sneak --script mcp https://api.example.com

  LLM vulnerability scan (OWASP LLM Top 10):
    llmsneak --script vuln --api-key sk-... https://api.openai.com
    llmsneak --script vuln --api-key none http://localhost:11434  # Ollama

  Ollama local scan (no key required):
    llmsneak -A http://localhost:11434
    llmsneak -sV --model llama3 http://localhost:11434

  Custom paths only:
    llmsneak -p /v1/chat/completions,/v1/models https://api.example.com

  Timing control:
    llmsneak -T1 -sV https://api.example.com    # Sneaky (slow)
    llmsneak -T5 -sV https://api.example.com    # Insane (fast)

  Save all output formats:
    llmsneak -A -oA results --api-key sk-... https://api.openai.com
    llmsneak -A -oJ scan.json --api-key sk-... https://api.openai.com

  List available probe packs:
    llmsneak --list-probes

TIMING TEMPLATES:
  -T0  Paranoid   (1 req, 2000ms delay, 30s timeout) — IDS evasion
  -T1  Sneaky     (1 req, 1000ms delay, 20s timeout)
  -T2  Polite     (2 req,  500ms delay, 15s timeout)
  -T3  Normal     (3 req,  200ms delay, 10s timeout)  [default]
  -T4  Aggressive (5 req,   50ms delay,  8s timeout)
  -T5  Insane    (10 req,    0ms delay,  5s timeout)  — fast, noisy

SCAN PHASE SUMMARY:
  Phase 1  Endpoint Discovery       always runs
  Phase 2  Provider Identification  skipped with -sn
  Phase 3  Model Fingerprinting     -sV or -A
  Phase 4  Capability Enumeration   --script capabilities or -A
  Phase 5  Guard Detection          --script guards or -A
  Phase 6  Vulnerability Scan        --script vuln or -A  (OWASP LLM Top 10)
  Phase 7  MCP & Tool Detection      --script mcp or -A   (agent attack surface)
  Phase 7  MCP & Tool Detection      --script mcp  or -A  (agent attack surface)

See {HOMEPAGE} for full documentation and probe pack authoring guide.
"""


# ────────────────────────────────────────────────────────────────────────────
# Parser
# ────────────────────────────────────────────────────────────────────────────

class _NmapHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Slightly wider help formatter, closer to Nmap's style."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, max_help_position=34, width=90, **kwargs)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="llm-sneak",
        description=(
            f"LLMSneak {VERSION} — The Nmap for LLMs\n"
            "Recon and fingerprinting tool for Large Language Model endpoints.\n"
            f"{HOMEPAGE}"
        ),
        formatter_class=_NmapHelpFormatter,
        epilog=EPILOG,
        add_help=True,
    )

    # ── Positional ──────────────────────────────────────────────────────────
    parser.add_argument(
        "target",
        metavar="TARGET",
        help="Target URL or hostname (e.g. https://api.openai.com or localhost:11434)",
    )

    # ── Scan types ──────────────────────────────────────────────────────────
    scan = parser.add_argument_group("SCAN TYPES")
    scan.add_argument(
        "-sn",
        action="store_true",
        dest="discovery_only",
        help="Endpoint discovery only — skip provider ID and fingerprinting",
    )
    scan.add_argument(
        "-sV",
        action="store_true",
        dest="version_detect",
        help="Probe open endpoints to determine model version (needs --api-key)",
    )
    scan.add_argument(
        "-A",
        action="store_true",
        dest="aggressive",
        help="Aggressive scan: all phases (provider + fingerprint + capabilities + guards)",
    )
    scan.add_argument(
        "--script",
        metavar="SCRIPTS",
        default="",
        help="Run script(s): guards, capabilities, extract, vuln, mcp, all (comma-separated)",
    )

    # ── Authentication ───────────────────────────────────────────────────────
    auth = parser.add_argument_group("AUTHENTICATION")
    auth.add_argument(
        "--api-key",
        metavar="KEY",
        default=None,
        help="API key for authenticated probing (enables fingerprinting and guard detection)",
    )
    auth.add_argument(
        "--model",
        metavar="MODEL",
        default=None,
        help="Specify the target model name (e.g. gpt-4o, llama3, claude-3-haiku-20240307)",
    )
    auth.add_argument(
        "--profile",
        metavar="PROFILE",
        default=None,
        help="Use a known host profile (e.g. groq, openrouter, github-models). "
             "Auto-fills base_url and api_format. Use --list-hosts to see all.",
    )

    # ── Probe options ────────────────────────────────────────────────────────
    probes = parser.add_argument_group("PROBE OPTIONS")
    probes.add_argument(
        "-p",
        metavar="PATHS",
        dest="paths",
        default=None,
        help="Only probe specific paths, comma-separated (e.g. /v1/chat/completions,/api/chat)",
    )
    probes.add_argument(
        "--probe-dir",
        metavar="DIR",
        default=None,
        help="Additional directory containing custom probe pack YAML files",
    )
    probes.add_argument(
        "--list-probes",
        action="store_true",
        default=False,
        help="List all available probe packs and exit",
    )
    probes.add_argument(
        "--list-hosts",
        action="store_true",
        default=False,
        help="List all known public LLM API hosts and exit",
    )

    # ── Timing ──────────────────────────────────────────────────────────────
    timing = parser.add_argument_group("TIMING AND PERFORMANCE")
    timing.add_argument(
        "-T",
        metavar="0-5",
        dest="timing",
        type=int,
        choices=range(6),
        default=3,
        help="Timing template: 0=paranoid, 1=sneaky, 2=polite, 3=normal, 4=aggressive, 5=insane",
    )
    timing.add_argument(
        "--delay",
        metavar="MS",
        dest="delay",
        type=int,
        default=None,
        help="Override delay between probes in milliseconds",
    )

    # ── Output ───────────────────────────────────────────────────────────────
    output = parser.add_argument_group("OUTPUT")
    output.add_argument(
        "-oN",
        metavar="FILE",
        dest="output_normal",
        default=None,
        help="Save normal (human-readable) output to FILE",
    )
    output.add_argument(
        "-oJ",
        metavar="FILE",
        dest="output_json",
        default=None,
        help="Save JSON output to FILE",
    )
    output.add_argument(
        "-oG",
        metavar="FILE",
        dest="output_grep",
        default=None,
        help="Save grepable output to FILE",
    )
    output.add_argument(
        "-oX",
        metavar="FILE",
        dest="output_xml",
        default=None,
        help="Save XML output to FILE",
    )
    output.add_argument(
        "-oA",
        metavar="BASENAME",
        dest="output_all",
        default=None,
        help="Save all output formats to BASENAME.{txt,json,gnmap,xml}",
    )
    output.add_argument(
        "-v",
        action="count",
        default=0,
        dest="verbose",
        help="Increase verbosity (-v, -vv)",
    )
    output.add_argument(
        "--open",
        action="store_true",
        default=False,
        help="Show only open endpoints in output",
    )

    # ── Misc ─────────────────────────────────────────────────────────────────
    misc = parser.add_argument_group("MISC")
    misc.add_argument(
        "--version",
        action="version",
        version=f"llm-sneak {VERSION} — {HOMEPAGE}",
    )

    return parser


# ────────────────────────────────────────────────────────────────────────────
# Entry point
# ────────────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args   = parser.parse_args(argv)

    # ── --list-probes (no target needed) ────────────────────────────────────
    if args.list_probes:
        _print_probe_list(Path(args.probe_dir) if args.probe_dir else None)
        return 0

    # ── --list-hosts (no target needed) ──────────────────────────────────────
    if getattr(args, "list_hosts", False):
        _print_host_list()
        return 0

    # ── Validate target ──────────────────────────────────────────────────────
    if not args.target:
        parser.print_usage()
        return 1

    # ── Warn about unauthenticated fingerprinting ────────────────────────────
    needs_key = args.version_detect or args.aggressive or bool(args.script)
    if needs_key and not args.api_key:
        console.print(
            "[yellow]Note:[/] [dim]Fingerprinting, capability, and guard scans work best with "
            "--api-key. Proceeding with header-only analysis.[/]\n"
        )

    # ── Run scan ─────────────────────────────────────────────────────────────
    try:
        from llmsneak.scanner import scan
        result = scan(args)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted.[/]")
        return 130
    except Exception as e:
        print_error(str(e))
        if args.verbose >= 2:
            import traceback
            traceback.print_exc()
        return 1

    # ── Write file outputs ───────────────────────────────────────────────────
    write_outputs(result, args)

    return 0


def _print_probe_list(probe_dir: Path | None = None) -> None:
    packs = list_packs(probe_dir)
    if not packs:
        console.print("[yellow]No probe packs found.[/]")
        return

    from rich.table import Table
    from rich import box
    table = Table(title="Available Probe Packs", box=box.SIMPLE_HEAD, header_style="bold cyan")
    table.add_column("Name",     style="bold")
    table.add_column("Provider", style="cyan")
    table.add_column("Probes",   justify="right")
    table.add_column("Version",  style="dim")

    for p in packs:
        table.add_row(p["name"], p["provider"], str(p["probes"]), p["version"])

    console.print(table)
    console.print(f"\n[dim]Total: {len(packs)} packs, {sum(p['probes'] for p in packs)} probes[/]")


def _print_host_list() -> None:
    from llmsneak.hosts import list_hosts
    from rich.table import Table
    from rich import box
    from rich.text import Text
    hosts = list_hosts()
    table = Table(
        title="Known LLM API Hosts  (use --profile NAME)",
        box=box.SIMPLE_HEAD, header_style="bold cyan", expand=False
    )
    table.add_column("PROFILE",    style="bold",  min_width=16)
    table.add_column("NAME",       min_width=22)
    table.add_column("FORMAT",     style="cyan",  min_width=10)
    table.add_column("KEY",        justify="center", min_width=5)
    table.add_column("FREE TIER",  style="dim",   min_width=30)
    for h in hosts:
        key_str = Text("No",  style="green") if not h["key_needed"] else Text("Yes", style="yellow")
        table.add_row(h["profile"], h["name"], h["format"], key_str, h["free_tier"][:40])
    console.print(table)
    console.print()
    console.print("[dim]Examples:[/]")
    console.print("  llm-sneak --profile groq --api-key $GROQ_KEY --model llama-3.3-70b-versatile")
    console.print("  llm-sneak --profile github-models --api-key $GITHUB_PAT --model openai/gpt-4o")
    console.print("  llm-sneak --profile ollama                   # no key needed")
    console.print()


if __name__ == "__main__":
    sys.exit(main())
