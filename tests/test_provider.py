"""
Tests for llmsneak.phases.provider scoring logic.
Uses mock data — no real HTTP calls, no API keys needed.
"""
import sys
from collections import defaultdict
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import only the pure scoring helpers (no httpx dependency at module level)
from llmsneak.phases.provider import (
    _score_headers,
    _score_error_body,
    _score_model_name,
    PROVIDER_API_FORMAT,
)
from llmsneak.constants import PROVIDER_HEADER_SIGNATURES


def score(headers=None, body=None, model=None):
    """Helper: run all available scoring functions, return (scores_dict, evidence)."""
    s = defaultdict(float)
    e = []
    if headers:
        _score_headers(headers, s, e)
    if body:
        _score_error_body(body, s, e)
    if model:
        _score_model_name(model, s, e)
    return dict(s), e


class TestHeaderScoring:
    def test_openai_headers_win(self):
        s, ev = score(headers={
            "openai-processing-ms":       "247",
            "openai-organization":        "org-abc",
            "x-ratelimit-limit-requests": "3500",
        })
        assert s.get("openai", 0) > 0.5
        assert max(s, key=s.get) == "openai"

    def test_anthropic_headers_win(self):
        s, ev = score(headers={
            "anthropic-ratelimit-requests-limit": "50",
            "anthropic-ratelimit-tokens-limit":   "100000",
            "request-id":                         "req_011CNmFhUFHzPs",
        })
        assert max(s, key=s.get) == "anthropic"

    def test_azure_headers_win(self):
        s, ev = score(headers={
            "apim-request-id":             "abc-123",
            "x-ms-region":                 "eastus",
            "azureml-model-deployment":    "gpt4-prod",
        })
        assert max(s, key=s.get) == "azure"

    def test_ollama_content_type(self):
        s, ev = score(headers={"content-type": "application/x-ndjson"})
        assert s.get("ollama", 0) > 0

    def test_empty_headers_no_score(self):
        s, ev = score(headers={})
        assert s == {}

    def test_irrelevant_headers_no_score(self):
        s, ev = score(headers={"content-type": "text/html", "server": "nginx"})
        # Only ollama matches on content-type (when ndjson), so no matches here
        assert s.get("openai", 0) == 0
        assert s.get("anthropic", 0) == 0

    def test_evidence_populated(self):
        _, ev = score(headers={"openai-processing-ms": "100"})
        assert len(ev) > 0
        assert any("openai" in e.lower() for e in ev)


class TestErrorBodyScoring:
    def test_openai_error_format(self):
        body = '{"error": {"type": "invalid_request_error", "code": "model_not_found"}}'
        s, _ = score(body=body)
        assert s.get("openai", 0) > 0

    def test_anthropic_error_format(self):
        body = '{"type": "error", "error": {"type": "authentication_error"}}'
        s, _ = score(body=body)
        assert s.get("anthropic", 0) > 0

    def test_ollama_error_format(self):
        body = '{"error": "model \'llama99\' not found, try ollama pull llama99"}'
        s, _ = score(body=body)
        assert s.get("ollama", 0) > 0

    def test_google_error_format(self):
        body = '{"error": {"code": 400, "status": "INVALID_ARGUMENT"}}'
        s, _ = score(body=body)
        assert s.get("google", 0) > 0

    def test_empty_body_no_score(self):
        s, _ = score(body="")
        assert s == {}


class TestModelNameScoring:
    def test_gpt_model(self):
        s, _ = score(model="gpt-4o-2024-08-06")
        assert s.get("openai", 0) > 0

    def test_claude_model(self):
        s, _ = score(model="claude-3-5-sonnet-20241022")
        assert s.get("anthropic", 0) > 0

    def test_gemini_model(self):
        s, _ = score(model="gemini-1.5-pro-latest")
        assert s.get("google", 0) > 0

    def test_llama_model(self):
        s, _ = score(model="meta-llama-3-8b-instruct")
        assert s.get("meta", 0) > 0

    def test_mistral_model(self):
        s, _ = score(model="mistral-7b-instruct-v0.2")
        assert s.get("mistral", 0) > 0

    def test_unknown_model_no_crash(self):
        s, _ = score(model="unknown-model-xyz-1234")
        # Should not raise, may return empty or minimal scores
        assert isinstance(s, dict)


class TestProviderApiFormat:
    def test_all_header_providers_have_format(self):
        """Every provider in PROVIDER_HEADER_SIGNATURES must have an API format mapping."""
        for provider in PROVIDER_HEADER_SIGNATURES:
            assert provider in PROVIDER_API_FORMAT, \
                f"Provider '{provider}' has no API format mapping in PROVIDER_API_FORMAT"

    def test_format_values_valid(self):
        valid = {"openai", "anthropic", "google", "ollama", "cohere"}
        for provider, fmt in PROVIDER_API_FORMAT.items():
            assert fmt in valid, f"Provider '{provider}' has unknown format '{fmt}'"

    def test_openai_uses_openai_format(self):
        assert PROVIDER_API_FORMAT["openai"] == "openai"

    def test_anthropic_uses_anthropic_format(self):
        assert PROVIDER_API_FORMAT["anthropic"] == "anthropic"

    def test_azure_uses_openai_compat(self):
        assert PROVIDER_API_FORMAT["azure"] == "openai"   # Azure is OpenAI-compatible
