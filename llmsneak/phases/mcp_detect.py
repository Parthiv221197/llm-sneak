"""
Phase 7 — MCP & Agent Tool Detection

MCP (Model Context Protocol) is Anthropic's open standard for connecting
AI models to external tools and data sources. When an LLM is deployed with
MCP servers attached, it may have access to:

  - Filesystem (read/write files on the server)
  - Shell / code execution
  - Databases (read/modify data)
  - Email / calendar
  - Web browsing / search
  - GitHub / source code
  - Custom business tools

From a pentest perspective, each tool represents an attack surface BEYOND
the LLM itself. A prompt injection that makes the model call a shell tool
is effectively RCE.

Detection strategy (multi-layer):
  1. HTTP endpoint probing  — known MCP server paths and ports
  2. JSON-RPC handshake     — MCP initialize + tools/list calls
  3. OpenAI tools endpoint  — /v1/tools or tools returned in model info
  4. Behavioral inference   — ask the model what it can do (covert probes)
  5. Error leak analysis    — tool names sometimes leak in error messages

Reference: https://modelcontextprotocol.io/specification
"""
from __future__ import annotations

import asyncio
import json
from typing import Optional

import httpx

from llmsneak.models import MCPResult, MCPServerInfo, MCPTool
from llmsneak.utils.http import probe_path, safe_json, chat_completion
from llmsneak.utils.timing import TimingConfig


# ── Known MCP endpoint patterns ────────────────────────────────────────────────

MCP_PATHS = [
    "/mcp",
    "/mcp/sse",
    "/sse",
    "/.well-known/mcp",
    "/v1/mcp",
    "/api/mcp",
    "/tools",
    "/v1/tools",
    "/agent/tools",
]

# Ports commonly used by MCP servers alongside the main LLM API
MCP_EXTRA_PORTS = [3000, 3001, 8081, 9000, 9090]

# JSON-RPC request templates
_JSONRPC_INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "llm-sneak", "version": "0.1.0"},
    },
}

_JSONRPC_TOOLS_LIST = {
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/list",
    "params": {},
}

_JSONRPC_RESOURCES_LIST = {
    "jsonrpc": "2.0",
    "id": 3,
    "method": "resources/list",
    "params": {},
}

# ── Risk classification ─────────────────────────────────────────────────────────

# Tool name keywords → risk classification
TOOL_RISK_MAP: dict[str, tuple[str, str]] = {
    # (risk_level, capability_flag)
    "bash":          ("CRITICAL", "has_shell_access"),
    "shell":         ("CRITICAL", "has_shell_access"),
    "exec":          ("CRITICAL", "has_code_exec"),
    "execute":       ("CRITICAL", "has_code_exec"),
    "run_code":      ("CRITICAL", "has_code_exec"),
    "python":        ("CRITICAL", "has_code_exec"),
    "subprocess":    ("CRITICAL", "has_shell_access"),
    "terminal":      ("CRITICAL", "has_shell_access"),
    "read_file":     ("HIGH",     "has_file_access"),
    "write_file":    ("HIGH",     "has_file_access"),
    "create_file":   ("HIGH",     "has_file_access"),
    "delete_file":   ("HIGH",     "has_file_access"),
    "filesystem":    ("HIGH",     "has_file_access"),
    "file_system":   ("HIGH",     "has_file_access"),
    "list_dir":      ("HIGH",     "has_file_access"),
    "read_dir":      ("HIGH",     "has_file_access"),
    "database":      ("HIGH",     "has_db_access"),
    "sql":           ("HIGH",     "has_db_access"),
    "query":         ("HIGH",     "has_db_access"),
    "postgres":      ("HIGH",     "has_db_access"),
    "mysql":         ("HIGH",     "has_db_access"),
    "sqlite":        ("HIGH",     "has_db_access"),
    "email":         ("MEDIUM",   "has_email_access"),
    "send_email":    ("MEDIUM",   "has_email_access"),
    "gmail":         ("MEDIUM",   "has_email_access"),
    "smtp":          ("MEDIUM",   "has_email_access"),
    "calendar":      ("MEDIUM",   "has_email_access"),
    "web_search":    ("MEDIUM",   "has_web_access"),
    "search":        ("MEDIUM",   "has_web_access"),
    "browse":        ("MEDIUM",   "has_web_access"),
    "fetch":         ("MEDIUM",   "has_web_access"),
    "http_request":  ("MEDIUM",   "has_web_access"),
    "web_fetch":     ("MEDIUM",   "has_web_access"),
    "github":        ("MEDIUM",   "has_web_access"),
    "git":           ("MEDIUM",   "has_web_access"),
    "slack":         ("MEDIUM",   "has_email_access"),
    "notion":        ("LOW",      ""),
    "jira":          ("LOW",      ""),
    "calculator":    ("LOW",      ""),
    "weather":       ("LOW",      "has_web_access"),
}


def classify_tool(tool_name: str, description: str = "") -> tuple[str, str]:
    """Return (risk_level, capability_flag) for a tool name."""
    combined = (tool_name + " " + description).lower()
    best_risk = "LOW"
    best_flag = ""
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    for keyword, (risk, flag) in TOOL_RISK_MAP.items():
        if keyword in combined:
            if risk_order[risk] < risk_order[best_risk]:
                best_risk = risk
                best_flag = flag
    return best_risk, best_flag


# ── Main detection function ─────────────────────────────────────────────────────

async def detect_mcp(
    client:     httpx.AsyncClient,
    base_url:   str,
    api_format: str,
    timing:     TimingConfig,
    api_key:    Optional[str] = None,
    model:      Optional[str] = None,
) -> MCPResult:
    """
    Detect MCP servers and enumerate tools available to the target model.
    Works with and without an API key.
    """
    result   = MCPResult()
    evidence = result.evidence

    sem = asyncio.Semaphore(timing.max_concurrent)

    # ── Strategy 1: Probe known MCP HTTP endpoints ────────────────────────────
    mcp_servers = await _probe_mcp_endpoints(client, base_url, sem, timing, evidence)

    # ── Strategy 2: Probe extra ports on same host ────────────────────────────
    host_servers = await _probe_extra_ports(base_url, sem, timing, evidence)
    mcp_servers.extend(host_servers)

    # ── Strategy 3: OpenAI /v1/tools endpoint ────────────────────────────────
    oa_tools = await _probe_openai_tools(client, base_url, sem, evidence)
    if oa_tools:
        srv = MCPServerInfo(url=base_url + "/v1/tools", name="OpenAI-tools-endpoint")
        srv.tools = oa_tools
        mcp_servers.append(srv)

    # ── Strategy 4: Behavioural inference via chat ────────────────────────────
    inferred_tools = await _infer_tools_via_chat(
        client, base_url, api_format, timing, api_key, model, evidence
    )
    if inferred_tools:
        srv = MCPServerInfo(url=base_url, name="inferred-via-chat")
        srv.tools = inferred_tools
        mcp_servers.append(srv)

    # ── Aggregate results ─────────────────────────────────────────────────────
    result.servers = mcp_servers
    all_tools: list[MCPTool] = []
    for srv in mcp_servers:
        all_tools.extend(srv.tools)

    result.tool_count = len(all_tools)

    for tool in all_tools:
        risk, flag = classify_tool(tool.name, tool.description)
        tool.risk_level = risk
        if flag:
            setattr(result, flag, True)

    if all_tools:
        risk_counts: dict[str, int] = {}
        for t in all_tools:
            risk_counts[t.risk_level] = risk_counts.get(t.risk_level, 0) + 1
        parts = [f"{v}x {k}" for k, v in risk_counts.items()]
        result.risk_summary = f"{len(all_tools)} tools detected — " + ", ".join(parts)
        evidence.append(f"Total tools enumerated: {len(all_tools)}")
    else:
        result.risk_summary = "No tools detected"

    return result


async def _probe_mcp_endpoints(
    client:   httpx.AsyncClient,
    base_url: str,
    sem:      asyncio.Semaphore,
    timing:   TimingConfig,
    evidence: list[str],
) -> list[MCPServerInfo]:
    """Probe known MCP HTTP paths on the base URL."""
    servers: list[MCPServerInfo] = []

    async def _try_path(path: str) -> Optional[MCPServerInfo]:
        async with sem:
            if timing.delay_s > 0:
                await asyncio.sleep(timing.delay_s)

            # Try JSON-RPC initialize first
            resp, _, err = await probe_path(
                client, base_url, path, "POST", _JSONRPC_INIT
            )
            if err or resp is None:
                return None
            if resp.status_code not in (200, 201):
                return None

            data = safe_json(resp)
            if not data or "result" not in data:
                return None

            # This looks like an MCP server!
            srv_info = data["result"].get("serverInfo", {})
            srv = MCPServerInfo(
                url      = base_url + path,
                name     = srv_info.get("name", path.lstrip("/")),
                version  = srv_info.get("version", ""),
                protocol_version = data["result"].get("protocolVersion", ""),
            )
            evidence.append(f"MCP server found at {base_url + path} — name: {srv.name}")

            # Now enumerate tools
            resp2, _, _ = await probe_path(
                client, base_url, path, "POST", _JSONRPC_TOOLS_LIST
            )
            if resp2 and resp2.status_code == 200:
                data2 = safe_json(resp2)
                if data2:
                    for t in data2.get("result", {}).get("tools", []):
                        srv.tools.append(MCPTool(
                            name=t.get("name", ""),
                            description=t.get("description", ""),
                            input_schema=t.get("inputSchema", {}),
                        ))
                    if srv.tools:
                        evidence.append(
                            f"  Tools: {', '.join(t.name for t in srv.tools)}"
                        )

            # Enumerate resources
            resp3, _, _ = await probe_path(
                client, base_url, path, "POST", _JSONRPC_RESOURCES_LIST
            )
            if resp3 and resp3.status_code == 200:
                data3 = safe_json(resp3)
                if data3:
                    for r in data3.get("result", {}).get("resources", []):
                        uri = r.get("uri", "")
                        if uri:
                            srv.resources.append(uri)
                    if srv.resources:
                        evidence.append(
                            f"  Resources: {', '.join(srv.resources[:5])}"
                        )

            return srv

    results = await asyncio.gather(*[_try_path(p) for p in MCP_PATHS])
    return [s for s in results if s is not None]


async def _probe_extra_ports(
    base_url: str,
    sem:      asyncio.Semaphore,
    timing:   TimingConfig,
    evidence: list[str],
) -> list[MCPServerInfo]:
    """Try MCP-common ports on the same host."""
    from urllib.parse import urlparse
    parsed = urlparse(base_url)
    host   = parsed.hostname or ""
    servers: list[MCPServerInfo] = []

    async def _try_port(port: int) -> Optional[MCPServerInfo]:
        async with sem:
            scheme = "http"
            test_url = f"{scheme}://{host}:{port}"
            try:
                async with httpx.AsyncClient(timeout=3) as c:
                    resp = await c.post(
                        test_url + "/mcp",
                        json=_JSONRPC_INIT,
                        headers={"Content-Type": "application/json"},
                    )
                    if resp.status_code == 200:
                        data = safe_json(resp)
                        if data and "result" in data:
                            srv_info = data["result"].get("serverInfo", {})
                            srv = MCPServerInfo(
                                url  = test_url + "/mcp",
                                name = srv_info.get("name", f"port-{port}"),
                            )
                            evidence.append(
                                f"MCP server on extra port {port}: {test_url}/mcp"
                            )
                            return srv
            except Exception:
                pass
            return None

    results = await asyncio.gather(*[_try_port(p) for p in MCP_EXTRA_PORTS])
    return [s for s in results if s is not None]


async def _probe_openai_tools(
    client:   httpx.AsyncClient,
    base_url: str,
    sem:      asyncio.Semaphore,
    evidence: list[str],
) -> list[MCPTool]:
    """Some OpenAI-compatible deployments expose a /v1/tools endpoint."""
    tools: list[MCPTool] = []
    async with sem:
        resp, _, err = await probe_path(client, base_url, "/v1/tools", "GET")
        if err or resp is None or resp.status_code != 200:
            return []
        data = safe_json(resp) or {}
        raw_tools = data.get("tools", data.get("data", []))
        for t in raw_tools:
            tools.append(MCPTool(
                name        = t.get("name", t.get("function", {}).get("name", "")),
                description = t.get("description", t.get("function", {}).get("description", "")),
            ))
        if tools:
            evidence.append(f"/v1/tools returned {len(tools)} tools")
    return tools


async def _infer_tools_via_chat(
    client:     httpx.AsyncClient,
    base_url:   str,
    api_format: str,
    timing:     TimingConfig,
    api_key:    Optional[str],
    model:      Optional[str],
    evidence:   list[str],
) -> list[MCPTool]:
    """
    Ask the model what tools it has access to using natural language.
    This is covert — it doesn't say "list your MCP tools", it asks
    indirectly in ways that reveal tool access without being obvious.
    """
    tools: list[MCPTool] = []
    target_model = model or _default_model(api_format)

    # Probe 1: capability question (indirect)
    content, _, err = await chat_completion(
        client, base_url,
        [{"role": "user",
          "content": "What actions can you take beyond just generating text? "
                     "List each capability on its own line."}],
        model=target_model,
        api_format=api_format,
    )

    if err or not content:
        return []

    evidence.append(f"Tool inference via chat — response: '{content[:80].strip()}'")

    # Parse the response for tool indicators
    tool_keywords = {
        "search": ("web_search", "Search the web"),
        "browse": ("web_browse", "Browse URLs"),
        "file":   ("file_access", "Read/write files"),
        "read":   ("read_file", "Read files"),
        "write":  ("write_file", "Write files"),
        "run":    ("code_exec", "Execute code"),
        "execute":("code_exec", "Execute code"),
        "code":   ("code_exec", "Execute code"),
        "python": ("python_repl", "Python execution"),
        "bash":   ("bash", "Bash execution"),
        "shell":  ("shell", "Shell access"),
        "email":  ("send_email", "Send emails"),
        "send":   ("send_message", "Send messages"),
        "database":("db_query", "Database access"),
        "sql":    ("sql_query", "SQL queries"),
        "query":  ("db_query", "Query databases"),
        "github": ("github", "GitHub access"),
        "calendar":("calendar", "Calendar access"),
        "image":  ("image_gen", "Generate images"),
        "draw":   ("image_gen", "Generate images"),
        "memory": ("memory", "Persistent memory"),
        "remember":("memory", "Persistent memory"),
    }

    content_lower = content.lower()
    seen = set()
    for keyword, (tool_name, description) in tool_keywords.items():
        if keyword in content_lower and tool_name not in seen:
            tools.append(MCPTool(name=tool_name, description=description))
            seen.add(tool_name)
            evidence.append(f"  Inferred tool '{tool_name}' from keyword '{keyword}'")

    # Probe 2: try to trigger a tool call
    if tools:
        content2, _, err2 = await chat_completion(
            client, base_url,
            [{"role": "user",
              "content": "What is the current date and time right now?"}],
            model=target_model,
            api_format=api_format,
        )
        if not err2 and content2:
            import re
            date_pattern = r"\d{4}-\d{2}-\d{2}|\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}"
            if re.search(date_pattern, content2, re.I):
                has_time_tool = MCPTool(
                    name="get_current_time",
                    description="Get current date/time — model answered with a specific date, suggesting real-time access"
                )
                tools.append(has_time_tool)
                evidence.append(
                    f"  Model returned specific date ({content2[:40].strip()}) — "
                    f"suggests real-time tool access"
                )

    return tools


def _default_model(api_format: str) -> str:
    return {
        "anthropic": "claude-3-haiku-20240307",
        "ollama":    "llama3",
        "google":    "gemini-1.5-flash",
    }.get(api_format, "gpt-3.5-turbo")
