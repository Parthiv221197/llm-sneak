"""
Core data models for LLMSneak scan results.
All scan phases return instances of these dataclasses.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class EndpointState(Enum):
    OPEN     = "open"
    FILTERED = "filtered"
    CLOSED   = "closed"
    UNKNOWN  = "unknown"


class Confidence(Enum):
    HIGH   = "HIGH"
    MEDIUM = "MEDIUM"
    LOW    = "LOW"
    NONE   = "NONE"

    @classmethod
    def from_score(cls, score: float) -> "Confidence":
        if score >= 0.75:   return cls.HIGH
        if score >= 0.50:   return cls.MEDIUM
        if score > 0.0:     return cls.LOW
        return cls.NONE

    def color(self) -> str:
        return {
            "HIGH":   "green",
            "MEDIUM": "yellow",
            "LOW":    "orange3",
            "NONE":   "red",
        }[self.value]


@dataclass
class EndpointResult:
    path:        str
    state:       EndpointState
    service:     str   = ""
    latency_ms:  float = 0.0
    status_code: int   = 0
    headers:     dict  = field(default_factory=dict)
    error:       Optional[str] = None

    def state_color(self) -> str:
        return {
            EndpointState.OPEN:     "green",
            EndpointState.FILTERED: "yellow",
            EndpointState.CLOSED:   "red",
            EndpointState.UNKNOWN:  "dim",
        }[self.state]


@dataclass
class ProviderResult:
    provider:   str   = "unknown"
    confidence: float = 0.0
    api_format: str   = "unknown"   # openai-compatible | anthropic | google | ollama | custom
    evidence:   list[str] = field(default_factory=list)

    @property
    def confidence_label(self) -> str:
        return Confidence.from_score(self.confidence).value

    @property
    def confidence_color(self) -> str:
        return Confidence.from_score(self.confidence).color()


@dataclass
class ProbeMatch:
    probe_id:        str
    matched:         bool
    response_snippet: str  = ""
    latency_ms:      float = 0.0


@dataclass
class ModelFingerprintResult:
    model_family:         str   = "unknown"
    exact_model:          str   = "unknown"
    confidence:           float = 0.0
    context_window:       Optional[int]   = None
    streaming_supported:  Optional[bool]  = None
    estimated_temperature: Optional[float] = None
    probe_matches:        list[ProbeMatch] = field(default_factory=list)
    evidence:             list[str]        = field(default_factory=list)
    # Ollama-specific rich fields (populated by ollama_inspect)
    parameter_size:       Optional[str]   = None   # e.g. "8B", "70B"
    quantization:         Optional[str]   = None   # e.g. "Q4_K_M", "Q8_0", "F16"
    format:               Optional[str]   = None   # "gguf", "ggml"
    ollama_digest:        Optional[str]   = None   # model content hash
    ollama_size_gb:       Optional[float] = None   # disk size in GB
    ollama_modified:      Optional[str]   = None   # last modified date
    all_local_models:     list[str]       = field(default_factory=list)  # every model on this server

    @property
    def confidence_label(self) -> str:
        return Confidence.from_score(self.confidence).value

    @property
    def confidence_color(self) -> str:
        return Confidence.from_score(self.confidence).color()


@dataclass
class CapabilityResult:
    function_calling:     Optional[bool] = None
    parallel_tools:       Optional[bool] = None
    vision:               Optional[bool] = None
    json_mode:            Optional[bool] = None
    system_prompt:        Optional[bool] = None
    streaming:            Optional[bool] = None
    max_output_tokens:    Optional[int]  = None
    embeddings:           Optional[bool] = None
    audio_tts:            Optional[bool] = None
    image_generation:     Optional[bool] = None


@dataclass
class GuardResult:
    safety_layer_active:  bool  = False
    filter_type:          str   = "unknown"
    refusal_count:        int   = 0
    probe_count:          int   = 0
    system_prompt_present: bool = False
    system_prompt_leak:   Optional[str] = None
    evidence:             list[str] = field(default_factory=list)

    @property
    def refusal_rate(self) -> float:
        return self.refusal_count / self.probe_count if self.probe_count else 0.0


@dataclass
class MCPTool:
    """A single tool exposed by an MCP server."""
    name:        str
    description: str             = ""
    input_schema: dict           = None   # JSON Schema of the tool's inputs
    risk_level:  str             = "LOW"  # CRITICAL | HIGH | MEDIUM | LOW | INFO

    def __post_init__(self):
        if self.input_schema is None:
            self.input_schema = {}


@dataclass
class MCPServerInfo:
    """A detected MCP server."""
    url:             str
    name:            str             = "unknown"
    version:         str             = ""
    tools:           list            = None   # list[MCPTool]
    resources:       list[str]       = None
    protocol_version: str            = ""

    def __post_init__(self):
        if self.tools     is None: self.tools     = []
        if self.resources is None: self.resources = []


@dataclass
class MCPResult:
    """Phase 7 — MCP and Agent Tool Detection result."""
    servers:        list           = None    # list[MCPServerInfo]
    tool_count:     int            = 0
    has_file_access: bool          = False
    has_code_exec:   bool          = False
    has_web_access:  bool          = False
    has_db_access:   bool          = False
    has_email_access: bool         = False
    has_shell_access: bool         = False
    risk_summary:   str            = ""
    evidence:       list[str]      = None

    def __post_init__(self):
        if self.servers  is None: self.servers  = []
        if self.evidence is None: self.evidence = []

    @property
    def highest_risk(self) -> str:
        if self.has_shell_access or self.has_code_exec: return "CRITICAL"
        if self.has_file_access or self.has_db_access:  return "HIGH"
        if self.has_web_access or self.has_email_access: return "MEDIUM"
        if self.tool_count > 0:                          return "LOW"
        return "INFO"


@dataclass
class AccessResult:
    """Auth state of the target — determined before any key-based probing."""
    requires_auth:          bool            = True
    auth_type:              str             = "unknown"   # bearer | x-api-key | none | unknown
    unauthenticated_chat:   bool            = False       # can we send prompts without a key?
    unauthenticated_models: bool            = False       # can we list models without a key?
    open_endpoints:         list[str]       = field(default_factory=list)
    security_finding:       Optional[str]   = None        # e.g. "Chat accessible without auth"


@dataclass
class ScanResult:
    target:      str
    scan_start:  float = field(default_factory=time.time)
    scan_end:    float = 0.0
    endpoints:   list[EndpointResult]         = field(default_factory=list)
    access:      Optional[AccessResult]       = None       # auth state (new — pentest phase 0)
    provider:    Optional[ProviderResult]     = None
    fingerprint: Optional[ModelFingerprintResult] = None
    capabilities: Optional[CapabilityResult] = None
    guards:      Optional[GuardResult]        = None
    errors:      list[str]                    = field(default_factory=list)
    vulns:       object                        = None      # Phase 6 VulnScanResult
    mcp:         object                        = None      # Phase 7 MCPResult

    @property
    def duration(self) -> float:
        return (self.scan_end or time.time()) - self.scan_start

    @property
    def open_endpoints(self) -> list[EndpointResult]:
        return [e for e in self.endpoints if e.state == EndpointState.OPEN]

    @property
    def filtered_endpoints(self) -> list[EndpointResult]:
        return [e for e in self.endpoints if e.state == EndpointState.FILTERED]

