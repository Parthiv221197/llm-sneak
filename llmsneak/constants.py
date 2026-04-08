"""
Known LLM endpoint paths, provider HTTP signatures, and model name patterns.
Extend these dicts to add support for new providers.
"""

VERSION   = "0.1.0"
BANNER    = f"llm-sneak {VERSION}"
HOMEPAGE  = "https://github.com/safellm/llm-sneak"

# ---------------------------------------------------------------------------
# Endpoint paths to probe  (path, service_label)
# ---------------------------------------------------------------------------
KNOWN_ENDPOINTS: list[tuple[str, str]] = [
    # ── OpenAI / OpenAI-compatible ──────────────────────────────────────────
    ("/v1/chat/completions",        "llm-chat"),
    ("/v1/completions",             "llm-completions"),
    ("/v1/models",                  "llm-models"),
    ("/v1/embeddings",              "llm-embed"),
    ("/v1/images/generations",      "llm-image"),
    ("/v1/audio/speech",            "llm-tts"),
    ("/v1/audio/transcriptions",    "llm-stt"),
    ("/v1/moderations",             "llm-moderation"),
    ("/v1/assistants",              "llm-assistants"),
    ("/v1/files",                   "llm-files"),
    ("/v1/threads",                 "llm-threads"),
    ("/v1/fine_tuning/jobs",        "llm-finetune"),
    # ── Anthropic ───────────────────────────────────────────────────────────
    ("/v1/messages",                "llm-chat"),
    ("/v1/complete",                "llm-completions"),
    # ── Google Gemini ────────────────────────────────────────────────────────
    ("/v1beta/models",              "llm-models"),
    ("/v1beta/models:generateContent", "llm-chat"),
    # ── Cohere ──────────────────────────────────────────────────────────────
    ("/v1/chat",                    "llm-chat"),
    ("/v1/generate",                "llm-generate"),
    ("/v2/chat",                    "llm-chat"),
    ("/v1/embed",                   "llm-embed"),
    # ── Mistral AI ──────────────────────────────────────────────────────────
    ("/v1/chat/completions",        "llm-chat"),   # OpenAI-compat
    # ── Azure OpenAI ────────────────────────────────────────────────────────
    ("/openai/deployments",         "llm-deployments"),
    # ── Ollama / LM Studio (local) ──────────────────────────────────────────
    ("/api/generate",               "llm-generate"),
    ("/api/chat",                   "llm-chat"),
    ("/api/tags",                   "llm-models"),
    ("/api/show",                   "llm-info"),
    ("/api/embeddings",             "llm-embed"),
    ("/api/version",                "llm-info"),
    # ── HuggingFace TGI / vLLM ──────────────────────────────────────────────
    ("/generate",                   "llm-generate"),
    ("/generate_stream",            "llm-stream"),
    ("/info",                       "llm-info"),
    # ── MCP (Model Context Protocol) servers ─────────────────────────────────
    ("/mcp",                         "mcp-server"),
    ("/mcp/sse",                     "mcp-sse"),
    ("/.well-known/mcp",             "mcp-discovery"),
    ("/v1/mcp",                      "mcp-server"),
    ("/tools",                       "mcp-tools"),
    ("/v1/tools",                    "mcp-tools"),
    # ── Generic health / meta ────────────────────────────────────────────────
    ("/health",                     "llm-health"),
    ("/healthz",                    "llm-health"),
    ("/ping",                       "llm-health"),
    ("/_health",                    "llm-health"),
    ("/status",                     "llm-status"),
    ("/metrics",                    "llm-metrics"),
    ("/openapi.json",               "llm-schema"),
    ("/swagger.json",               "llm-schema"),
    ("/docs",                       "llm-docs"),
]

# ---------------------------------------------------------------------------
# HTTP response header signatures  {provider: [(header_name, regex|None)]}
# None means "presence is sufficient"
# ---------------------------------------------------------------------------
PROVIDER_HEADER_SIGNATURES: dict[str, list[tuple[str, str | None]]] = {
    "openai": [
        ("openai-organization",         None),
        ("openai-processing-ms",        None),
        ("openai-version",              None),
        ("x-ratelimit-limit-requests",  None),
        ("x-ratelimit-limit-tokens",    None),
        ("x-request-id",                r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
    ],
    "anthropic": [
        ("anthropic-ratelimit-requests-limit",  None),
        ("anthropic-ratelimit-tokens-limit",    None),
        ("anthropic-ratelimit-input-tokens-limit", None),
        ("request-id",                           r"req_[0-9a-zA-Z]+"),
    ],
    "google": [
        ("x-goog-api-version",          None),
        ("x-goog-request-id",           None),
        ("x-guploader-uploadid",        None),
    ],
    "azure": [
        ("apim-request-id",             None),
        ("x-ms-region",                 None),
        ("x-ms-client-request-id",      None),
        ("x-accel-buffering",           None),
        ("azureml-model-deployment",    None),
    ],
    "cohere": [
        ("x-cohere-request-id",         None),
        ("x-accel-buffering",           None),
    ],
    "ollama": [
        ("content-type",                r"application/x-ndjson"),
    ],
    "huggingface": [
        ("x-compute-type",              None),
        ("x-compute-time",              None),
        ("x-request-id",                r"Root=[0-9A-Za-z\-]+"),
    ],
    "mistral": [
        ("x-kong-request-id",           None),
        ("x-kong-upstream-latency",     None),
    ],
}

# ---------------------------------------------------------------------------
# Error/response body string signatures  {provider: [pattern]}
# ---------------------------------------------------------------------------
PROVIDER_BODY_SIGNATURES: dict[str, list[str]] = {
    "openai": [
        "invalid_request_error",
        "insufficient_quota",
        "model_not_found",
        '"param"',
        '"type": "invalid_request_error"',
        '"code": "invalid_api_key"',
    ],
    "anthropic": [
        "authentication_error",
        '"type": "error"',
        '"error": {',
        "x-api-key",
        "anthropic-version",
        "overloaded_error",
    ],
    "google": [
        "API_KEY_INVALID",
        "PERMISSION_DENIED",
        "INVALID_ARGUMENT",
        '"@type": "type.googleapis.com',
        "generativelanguage.googleapis.com",
    ],
    "cohere": [
        "invalid api token",
        "no api key",
        '"message": "invalid api',
    ],
    "ollama": [
        "model not found",
        "unknown model",
        '"error": "model',
        "pull model",
    ],
    "huggingface": [
        "Input validation error",
        '"error_type"',
        "Token indices sequence length",
        "is not supported",
        "huggingface",
    ],
    "azure": [
        "DeploymentNotFound",
        "ResourceNotFound",
        "InvalidResourceName",
        "azure",
        "microsoft",
    ],
}

# ---------------------------------------------------------------------------
# Model name detection patterns  {canonical_name: [substring_patterns]}
# ---------------------------------------------------------------------------
MODEL_PATTERNS: dict[str, list[str]] = {
    "gpt-4o":          ["gpt-4o"],
    "gpt-4-turbo":     ["gpt-4-turbo", "gpt-4-1106", "gpt-4-0125"],
    "gpt-4":           ["gpt-4-0314", "gpt-4-0613", "gpt-4-32k"],
    "gpt-3.5-turbo":   ["gpt-3.5", "gpt-35"],
    "o1":              ["o1-preview", "o1-mini", "/o1"],
    "o3":              ["o3-mini", "/o3"],
    "claude-3-opus":   ["claude-3-opus"],
    "claude-3.5-sonnet": ["claude-3-5-sonnet", "claude-3.5-sonnet"],
    "claude-3-sonnet": ["claude-3-sonnet"],
    "claude-3.5-haiku": ["claude-3-5-haiku", "claude-3.5-haiku"],
    "claude-3-haiku":  ["claude-3-haiku"],
    "gemini-2.0":      ["gemini-2.0"],
    "gemini-1.5-pro":  ["gemini-1.5-pro"],
    "gemini-1.5-flash": ["gemini-1.5-flash", "gemini-flash"],
    "llama-3.x":       ["llama-3", "llama3", "meta-llama-3"],
    "llama-2":         ["llama-2", "llama2"],
    "mistral-large":   ["mistral-large"],
    "mistral-7b":      ["mistral-7b", "mistral-small"],
    "mixtral":         ["mixtral"],
    "phi-3":           ["phi-3", "phi3"],
    "phi-2":           ["phi-2"],
    "qwen2":           ["qwen2", "qwen-2"],
    "qwen":            ["qwen"],
    "deepseek":        ["deepseek"],
    "command-r":       ["command-r"],
    "command":         ["command-light", "command-nightly"],
}

# ---------------------------------------------------------------------------
# Timing templates  {level: (max_concurrent, delay_between_ms, timeout_s)}
# ---------------------------------------------------------------------------
TIMING_TEMPLATES: dict[int, tuple[int, int, int]] = {
    0: (1,  2000, 30),   # Paranoid  — slow, low noise
    1: (1,  1000, 20),   # Sneaky    — slow
    2: (2,   500, 15),   # Polite
    3: (3,   200, 10),   # Normal    (default)
    4: (5,    50,  8),   # Aggressive
    5: (10,    0,  5),   # Insane    — fast, loud
}

TIMING_NAMES = {0: "paranoid", 1: "sneaky", 2: "polite", 3: "normal", 4: "aggressive", 5: "insane"}

# HTTP status code → endpoint state
STATUS_STATE_MAP: dict[int, str] = {
    200: "open",
    201: "open",
    400: "open",      # Bad request = endpoint exists, just needs right body
    401: "filtered",  # Unauthorized = endpoint exists
    403: "filtered",  # Forbidden = endpoint exists
    405: "open",      # Method not allowed = endpoint exists
    422: "open",      # Unprocessable = endpoint exists
    429: "filtered",  # Rate limited = endpoint exists
    500: "open",      # Server error = endpoint exists (misconfigured)
    503: "filtered",  # Service unavailable
}
