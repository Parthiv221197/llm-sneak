"""
Known public LLM API hosts.

These are legitimate, documented, publicly-accessible LLM API providers
that llm-sneak users can test against. All require free account signup
unless marked as truly keyless.

Use: llm-sneak --target-profile groq  (auto-fills base_url, api_format, etc.)

Sources:
  - https://github.com/cheahjs/free-llm-api-resources
  - https://github.com/mnfst/awesome-free-llm-apis
  - Individual provider documentation
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class KnownHost:
    """A known public LLM API provider."""
    name:           str
    base_url:       str
    api_format:     str          # openai | anthropic | google | ollama | cohere
    signup_url:     str
    free_tier:      str          # description of free tier
    default_models: list[str]    = field(default_factory=list)
    rate_limits:    str          = ""
    notes:          str          = ""
    requires_key:   bool         = True
    header_name:    str          = "Authorization"    # how to pass key
    header_prefix:  str          = "Bearer "


# ─────────────────────────────────────────────────────────────────────────────
# FIRST-PARTY (trained by the provider)
# ─────────────────────────────────────────────────────────────────────────────

FIRST_PARTY_HOSTS: dict[str, KnownHost] = {

    "openai": KnownHost(
        name         = "OpenAI",
        base_url     = "https://api.openai.com",
        api_format   = "openai",
        signup_url   = "https://platform.openai.com/signup",
        free_tier    = "$5 credit on signup (expires 3 months)",
        default_models = ["gpt-4o-mini", "gpt-3.5-turbo", "gpt-4o"],
        rate_limits  = "Varies by tier; free: 3 RPM, 200 RPD",
        notes        = "The gold standard. Best for testing fingerprint accuracy.",
    ),

    "anthropic": KnownHost(
        name         = "Anthropic",
        base_url     = "https://api.anthropic.com",
        api_format   = "anthropic",
        signup_url   = "https://console.anthropic.com/",
        free_tier    = "Free trial credits on signup",
        default_models = ["claude-3-haiku-20240307", "claude-3-5-sonnet-20241022"],
        rate_limits  = "60 RPM on free tier",
        notes        = "Native format: use --api-format anthropic. Strongest safety filters.",
        header_name  = "x-api-key",
        header_prefix = "",
    ),

    "google-gemini": KnownHost(
        name         = "Google Gemini (AI Studio)",
        base_url     = "https://generativelanguage.googleapis.com",
        api_format   = "google",
        signup_url   = "https://aistudio.google.com/app/apikey",
        free_tier    = "FREE — 15 RPM, 1500 RPD, 1M TPD on Gemini 1.5 Flash",
        default_models = ["gemini-1.5-flash", "gemini-1.5-pro", "gemini-2.0-flash"],
        rate_limits  = "15 RPM free (Flash), 2 RPM (Pro)",
        notes        = "Completely free. Best free option for Gemini fingerprinting. No credit card.",
    ),

    "cohere": KnownHost(
        name         = "Cohere",
        base_url     = "https://api.cohere.com",
        api_format   = "cohere",
        signup_url   = "https://dashboard.cohere.com/register",
        free_tier    = "Free: 20 RPM, 1000 calls/month forever",
        default_models = ["command-r", "command-r-plus", "command"],
        rate_limits  = "20 RPM, 1K/month on free tier",
        notes        = "Permanent free tier. Good for testing Cohere-specific detection.",
    ),

    "mistral": KnownHost(
        name         = "Mistral AI",
        base_url     = "https://api.mistral.ai",
        api_format   = "openai",
        signup_url   = "https://console.mistral.ai/",
        free_tier    = "Free: 1 req/s, 500K tok/month on Mistral Small",
        default_models = ["mistral-small-latest", "mistral-large-latest", "open-mistral-7b"],
        rate_limits  = "1 req/s free",
        notes        = "European provider. Tests Mistral-specific fingerprints.",
    ),
}

# ─────────────────────────────────────────────────────────────────────────────
# THIRD-PARTY PLATFORMS (host multiple models)
# ─────────────────────────────────────────────────────────────────────────────

PLATFORM_HOSTS: dict[str, KnownHost] = {

    "groq": KnownHost(
        name         = "Groq",
        base_url     = "https://api.groq.com/openai/v1",
        api_format   = "openai",
        signup_url   = "https://console.groq.com/",
        free_tier    = "FREE — 30 RPM, generous daily token limits",
        default_models = [
            "llama-3.3-70b-versatile",
            "llama-3.1-8b-instant",
            "llama4-scout-17b-16e-instruct",
            "mixtral-8x7b-32768",
            "gemma2-9b-it",
        ],
        rate_limits  = "30 RPM, 14,400 RPD per model",
        notes        = "FASTEST inference available (custom LPU hardware). Best free test target. "
                       "Serves LLaMA and Gemma. Perfect for fingerprinting open models.",
    ),

    "openrouter": KnownHost(
        name         = "OpenRouter",
        base_url     = "https://openrouter.ai/api/v1",
        api_format   = "openai",
        signup_url   = "https://openrouter.ai/keys",
        free_tier    = "Free models available (append :free to model name). 20 RPM.",
        default_models = [
            "meta-llama/llama-3.3-70b-instruct:free",
            "microsoft/phi-3-mini-128k-instruct:free",
            "mistralai/mistral-7b-instruct:free",
            "google/gemma-2-9b-it:free",
            "deepseek/deepseek-r1:free",
        ],
        rate_limits  = "20 RPM, 50 RPD on free models",
        notes        = "Best variety: access 100+ models through one API key. "
                       "Append ':free' to model name for free tier. "
                       "Excellent for cross-model comparison scanning.",
    ),

    "github-models": KnownHost(
        name         = "GitHub Models",
        base_url     = "https://models.github.ai/inference",
        api_format   = "openai",
        signup_url   = "https://github.com/settings/tokens",
        free_tier    = "FREE with any GitHub account. No credit card.",
        default_models = [
            "openai/gpt-4o",
            "openai/gpt-4o-mini",
            "meta/Llama-3.3-70B-Instruct",
            "mistral-ai/Mistral-Large-2411",
            "deepseek/DeepSeek-R1",
            "microsoft/Phi-4",
        ],
        rate_limits  = "10-15 RPM, 50-150 RPD depending on model",
        notes        = "FREE with GitHub Personal Access Token (PAT). No payment required. "
                       "Best for testing GPT-4o without paying OpenAI directly. "
                       "API key = your GitHub PAT.",
    ),

    "cloudflare-ai": KnownHost(
        name         = "Cloudflare Workers AI",
        base_url     = "https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/v1",
        api_format   = "openai",
        signup_url   = "https://dash.cloudflare.com/sign-up",
        free_tier    = "FREE: 10,000 neurons/day (~1000 requests). No credit card.",
        default_models = [
            "@cf/meta/llama-3.3-70b-instruct-fp8-fast",
            "@cf/meta/llama-3.1-8b-instruct",
            "@cf/mistral/mistral-7b-instruct-v0.2",
            "@cf/google/gemma-7b-it",
            "@cf/qwen/qwen1.5-14b-chat-awq",
        ],
        rate_limits  = "10K neurons/day free",
        notes        = "Replace {account_id} in base_url with your Cloudflare account ID. "
                       "Use API token from Cloudflare dashboard.",
    ),

    "cerebras": KnownHost(
        name         = "Cerebras",
        base_url     = "https://api.cerebras.ai/v1",
        api_format   = "openai",
        signup_url   = "https://cloud.cerebras.ai/",
        free_tier    = "FREE: 30 RPM, 14,400 RPD",
        default_models = [
            "llama-3.3-70b",
            "llama-3.1-8b",
            "qwen-3-32b",
        ],
        rate_limits  = "30 RPM free",
        notes        = "Extremely fast inference on Cerebras WSE chips. "
                       "Good free alternative to Groq for LLaMA testing.",
    ),

    "nvidia-nim": KnownHost(
        name         = "NVIDIA NIM",
        base_url     = "https://integrate.api.nvidia.com/v1",
        api_format   = "openai",
        signup_url   = "https://build.nvidia.com/explore/discover",
        free_tier    = "FREE: 40 RPM with account",
        default_models = [
            "meta/llama-3.3-70b-instruct",
            "mistralai/mistral-large-2-instruct",
            "google/gemma-3-27b-it",
            "qwen/qwen3-235b-a22b",
        ],
        rate_limits  = "40 RPM free",
        notes        = "NVIDIA's cloud inference platform. Great model variety.",
    ),

    "together-ai": KnownHost(
        name         = "Together AI",
        base_url     = "https://api.together.xyz/v1",
        api_format   = "openai",
        signup_url   = "https://api.together.ai/signup",
        free_tier    = "$25 free credits on signup (one-time)",
        default_models = [
            "meta-llama/Llama-3.3-70B-Instruct-Turbo",
            "mistralai/Mixtral-8x7B-Instruct-v0.1",
            "Qwen/Qwen2.5-72B-Instruct-Turbo",
            "deepseek-ai/DeepSeek-R1",
        ],
        rate_limits  = "Rate varies by plan",
        notes        = "$25 free = enough for ~2500 test scans. Great variety.",
    ),

    "huggingface": KnownHost(
        name         = "HuggingFace Inference API",
        base_url     = "https://api-inference.huggingface.co",
        api_format   = "openai",
        signup_url   = "https://huggingface.co/join",
        free_tier    = "FREE serverless inference on models <10GB",
        default_models = [
            "meta-llama/Llama-3.1-8B-Instruct",
            "mistralai/Mistral-7B-Instruct-v0.3",
            "google/gemma-2-9b-it",
            "microsoft/Phi-3-mini-4k-instruct",
        ],
        rate_limits  = "Rate limited, varies by model",
        notes        = "Largest model catalog. Many models available. "
                       "Use HF_TOKEN from huggingface.co/settings/tokens.",
    ),
}

# ─────────────────────────────────────────────────────────────────────────────
# LOCAL HOSTS (no API key needed)
# ─────────────────────────────────────────────────────────────────────────────

LOCAL_HOSTS: dict[str, KnownHost] = {

    "ollama": KnownHost(
        name         = "Ollama (local)",
        base_url     = "http://localhost:11434",
        api_format   = "ollama",
        signup_url   = "https://ollama.com/download",
        free_tier    = "FREE — runs entirely locally",
        default_models = ["llama3", "mistral", "phi3", "qwen2", "deepseek-r1"],
        requires_key = False,
        notes        = "Install: curl -fsSL https://ollama.com/install.sh | sh\n"
                       "Pull model: ollama pull llama3\n"
                       "Start: ollama serve",
    ),

    "lm-studio": KnownHost(
        name         = "LM Studio (local)",
        base_url     = "http://localhost:1234",
        api_format   = "openai",
        signup_url   = "https://lmstudio.ai/",
        free_tier    = "FREE — runs entirely locally",
        default_models = [],   # depends on user's downloaded models
        requires_key = False,
        notes        = "GUI app for running local models. Start server in Developer tab.",
    ),

    "jan": KnownHost(
        name         = "Jan (local)",
        base_url     = "http://localhost:1337",
        api_format   = "openai",
        signup_url   = "https://jan.ai/",
        free_tier    = "FREE — runs entirely locally",
        default_models = [],
        requires_key = False,
        notes        = "Open-source local AI client with OpenAI-compatible API.",
    ),
}

# ─────────────────────────────────────────────────────────────────────────────
# Combined lookup
# ─────────────────────────────────────────────────────────────────────────────

ALL_HOSTS: dict[str, KnownHost] = {
    **FIRST_PARTY_HOSTS,
    **PLATFORM_HOSTS,
    **LOCAL_HOSTS,
}


def get_host(profile_name: str) -> KnownHost | None:
    """Look up a host by profile name (case-insensitive)."""
    return ALL_HOSTS.get(profile_name.lower())


def list_hosts() -> list[dict]:
    """Return summary info for all known hosts."""
    result = []
    for key, host in ALL_HOSTS.items():
        result.append({
            "profile":   key,
            "name":      host.name,
            "base_url":  host.base_url,
            "format":    host.api_format,
            "free_tier": host.free_tier,
            "key_needed": host.requires_key,
        })
    return result
