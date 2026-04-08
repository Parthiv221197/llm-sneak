"""
Tests for llmsneak.constants — validates data integrity of all lookup tables.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from llmsneak.constants import (
    KNOWN_ENDPOINTS, PROVIDER_HEADER_SIGNATURES,
    PROVIDER_BODY_SIGNATURES, MODEL_PATTERNS,
    TIMING_TEMPLATES, STATUS_STATE_MAP,
    TIMING_NAMES, VERSION,
)


class TestEndpoints:
    def test_minimum_count(self):
        assert len(KNOWN_ENDPOINTS) >= 20

    def test_all_tuples(self):
        for item in KNOWN_ENDPOINTS:
            assert isinstance(item, tuple) and len(item) == 2, f"Bad entry: {item}"

    def test_paths_start_with_slash(self):
        for path, svc in KNOWN_ENDPOINTS:
            assert path.startswith("/"), f"Path '{path}' doesn't start with /"

    def test_service_labels_non_empty(self):
        for path, svc in KNOWN_ENDPOINTS:
            assert svc, f"Empty service label for {path}"

    def test_critical_paths_present(self):
        paths = {p for p, _ in KNOWN_ENDPOINTS}
        for required in ["/v1/chat/completions", "/v1/messages", "/api/chat", "/api/tags"]:
            assert required in paths, f"Missing critical path: {required}"


class TestProviderHeaderSigs:
    def test_has_key_providers(self):
        for provider in ["openai", "anthropic", "google", "azure", "ollama"]:
            assert provider in PROVIDER_HEADER_SIGNATURES, f"Missing: {provider}"

    def test_sig_format(self):
        for provider, sigs in PROVIDER_HEADER_SIGNATURES.items():
            assert isinstance(sigs, list), f"{provider}: sigs not a list"
            for entry in sigs:
                assert isinstance(entry, tuple) and len(entry) == 2, \
                    f"{provider}: bad sig entry {entry}"
                header_name, pattern = entry
                assert isinstance(header_name, str), f"{provider}: header name not str"
                assert pattern is None or isinstance(pattern, str), \
                    f"{provider}: pattern must be str or None"


class TestStatusStateMap:
    def test_200_is_open(self):
        assert STATUS_STATE_MAP[200] == "open"

    def test_401_is_filtered(self):
        assert STATUS_STATE_MAP[401] == "filtered"
        # 401 means endpoint EXISTS but requires auth

    def test_429_is_filtered(self):
        assert STATUS_STATE_MAP[429] == "filtered"
        # Rate-limited = endpoint exists!

    def test_valid_states(self):
        valid = {"open", "filtered", "closed"}
        for code, state in STATUS_STATE_MAP.items():
            assert state in valid, f"HTTP {code} → invalid state '{state}'"

    def test_400_is_open(self):
        assert STATUS_STATE_MAP[400] == "open"
        # Bad request = endpoint exists, just needs correct body


class TestTimingTemplates:
    def test_all_levels_present(self):
        for level in range(6):
            assert level in TIMING_TEMPLATES

    def test_tuple_format(self):
        for level, (concurrent, delay, timeout) in TIMING_TEMPLATES.items():
            assert isinstance(concurrent, int) and concurrent >= 1
            assert isinstance(delay,      int) and delay      >= 0
            assert isinstance(timeout,    int) and timeout    >= 1

    def test_increasing_concurrency(self):
        # Higher T level = more concurrent requests
        levels = sorted(TIMING_TEMPLATES.keys())
        concurrencies = [TIMING_TEMPLATES[l][0] for l in levels]
        assert concurrencies == sorted(concurrencies), \
            f"Concurrency should increase with level: {concurrencies}"

    def test_decreasing_delay(self):
        levels = sorted(TIMING_TEMPLATES.keys())
        delays = [TIMING_TEMPLATES[l][1] for l in levels]
        assert delays == sorted(delays, reverse=True), \
            f"Delay should decrease with level: {delays}"

    def test_timing_names_match(self):
        for level in range(6):
            assert level in TIMING_NAMES
            assert isinstance(TIMING_NAMES[level], str)
        assert TIMING_NAMES[3] == "normal"   # default
        assert TIMING_NAMES[0] == "paranoid"
        assert TIMING_NAMES[5] == "insane"


class TestModelPatterns:
    def test_key_models_present(self):
        for model in ["gpt-4o", "claude-3-opus", "gemini-1.5-pro", "llama-3.x", "mistral-7b"]:
            assert model in MODEL_PATTERNS, f"Missing model pattern: {model}"

    def test_patterns_are_lists(self):
        for model, patterns in MODEL_PATTERNS.items():
            assert isinstance(patterns, list) and len(patterns) > 0, \
                f"{model}: empty patterns list"

    def test_version_string(self):
        assert isinstance(VERSION, str)
        parts = VERSION.split(".")
        assert len(parts) == 3, f"Version '{VERSION}' should be semver X.Y.Z"
