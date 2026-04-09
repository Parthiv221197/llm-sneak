"""Tests for provider scoring logic — run with pytest OR python3 -m unittest"""
import sys, types, unittest
from pathlib import Path
from collections import defaultdict
sys.path.insert(0, str(Path(__file__).parent.parent))

# Mock httpx before any imports
for mod in ["httpx","llmsneak.utils.http"]:
    m = types.ModuleType(mod)
    m.AsyncClient = object; m.Response = object
    m.probe_path = None; m.safe_json = None
    sys.modules[mod] = m

from llmsneak.phases.provider import (
    _score_headers, _score_error_body, _score_model_name, PROVIDER_API_FORMAT
)
from llmsneak.constants import PROVIDER_HEADER_SIGNATURES


def score(headers=None, body=None, model=None):
    s, e = defaultdict(float), []
    if headers: _score_headers(headers, s, e)
    if body:    _score_error_body(body, s, e)
    if model:   _score_model_name(model, s, e)
    return dict(s)


class TestHeaderScoring(unittest.TestCase):

    def test_openai_wins(self):
        s = score(headers={
            "openai-processing-ms":       "247",
            "x-ratelimit-limit-requests": "3500",
        })
        self.assertGreater(s.get("openai",0), 0.5)
        self.assertEqual(max(s, key=s.get), "openai")

    def test_anthropic_wins(self):
        s = score(headers={
            "anthropic-ratelimit-requests-limit": "50",
            "request-id": "req_abc",
        })
        self.assertEqual(max(s, key=s.get), "anthropic")

    def test_azure_wins(self):
        s = score(headers={"apim-request-id":"abc","x-ms-region":"eastus"})
        self.assertEqual(max(s, key=s.get), "azure")

    def test_empty_headers_no_scores(self):
        self.assertEqual(score(headers={}), {})

    def test_evidence_populated(self):
        e = []; s = defaultdict(float)
        _score_headers({"openai-processing-ms":"100"}, s, e)
        self.assertGreater(len(e), 0)


class TestErrorBodyScoring(unittest.TestCase):

    def test_openai_error(self):
        s = score(body='{"error":{"type":"invalid_request_error"}}')
        self.assertGreater(s.get("openai",0), 0)

    def test_anthropic_error(self):
        s = score(body='{"type":"error","error":{"type":"authentication_error"}}')
        self.assertGreater(s.get("anthropic",0), 0)

    def test_ollama_error(self):
        s = score(body='{"error":"model not found, try ollama pull llama3"}')
        self.assertGreater(s.get("ollama",0), 0)

    def test_empty_body(self):
        self.assertEqual(score(body=""), {})


class TestModelNameScoring(unittest.TestCase):

    def test_gpt_model(self):
        s = score(model="gpt-4o-2024-08-06")
        self.assertGreater(s.get("openai",0), 0)

    def test_claude_model(self):
        s = score(model="claude-3-5-sonnet-20241022")
        self.assertGreater(s.get("anthropic",0), 0)

    def test_gemini_model(self):
        s = score(model="gemini-1.5-pro-latest")
        self.assertGreater(s.get("google",0), 0)

    def test_llama_model(self):
        s = score(model="meta-llama-3-8b-instruct")
        self.assertGreater(s.get("meta",0), 0)

    def test_unknown_no_crash(self):
        self.assertIsInstance(score(model="unknown-xyz-1234"), dict)


class TestAPIFormatMapping(unittest.TestCase):

    def test_all_header_providers_have_format(self):
        for p in PROVIDER_HEADER_SIGNATURES:
            self.assertIn(p, PROVIDER_API_FORMAT, f"'{p}' has no API format")

    def test_key_mappings(self):
        self.assertEqual(PROVIDER_API_FORMAT["openai"],    "openai")
        self.assertEqual(PROVIDER_API_FORMAT["anthropic"], "anthropic")
        self.assertEqual(PROVIDER_API_FORMAT["azure"],     "openai")   # compat
        self.assertEqual(PROVIDER_API_FORMAT["ollama"],    "ollama")


if __name__ == "__main__":
    unittest.main(verbosity=2)
