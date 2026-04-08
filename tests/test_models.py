"""
Unit tests for llmsneak.models
No external dependencies required.
"""
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from llmsneak.models import (
    Confidence, EndpointResult, EndpointState,
    GuardResult, ModelFingerprintResult, ProviderResult,
    ScanResult,
)


class TestConfidence:
    def test_high(self):
        assert Confidence.from_score(1.0)  == Confidence.HIGH
        assert Confidence.from_score(0.75) == Confidence.HIGH
        assert Confidence.from_score(0.90) == Confidence.HIGH

    def test_medium(self):
        assert Confidence.from_score(0.50) == Confidence.MEDIUM
        assert Confidence.from_score(0.74) == Confidence.MEDIUM

    def test_low(self):
        assert Confidence.from_score(0.01) == Confidence.LOW
        assert Confidence.from_score(0.49) == Confidence.LOW

    def test_none(self):
        assert Confidence.from_score(0.0)   == Confidence.NONE
        assert Confidence.from_score(-1.0)  == Confidence.NONE

    def test_colors(self):
        assert Confidence.HIGH.color()   == "green"
        assert Confidence.MEDIUM.color() == "yellow"
        assert Confidence.LOW.color()    == "orange3"
        assert Confidence.NONE.color()   == "red"


class TestEndpointResult:
    def test_state_colors(self):
        for state, expected_color in [
            (EndpointState.OPEN,     "green"),
            (EndpointState.FILTERED, "yellow"),
            (EndpointState.CLOSED,   "red"),
            (EndpointState.UNKNOWN,  "dim"),
        ]:
            ep = EndpointResult("/test", state)
            assert ep.state_color() == expected_color, f"Wrong color for {state}"

    def test_defaults(self):
        ep = EndpointResult("/v1/chat/completions", EndpointState.OPEN)
        assert ep.service == ""
        assert ep.latency_ms == 0.0
        assert ep.status_code == 0
        assert ep.headers == {}
        assert ep.error is None


class TestProviderResult:
    def test_confidence_labels(self):
        for score, expected in [(0.9, "HIGH"), (0.6, "MEDIUM"), (0.3, "LOW"), (0.0, "NONE")]:
            pr = ProviderResult(provider="openai", confidence=score)
            assert pr.confidence_label == expected

    def test_confidence_colors(self):
        high = ProviderResult(confidence=0.9)
        assert high.confidence_color == "green"
        low = ProviderResult(confidence=0.1)
        assert low.confidence_color == "orange3"


class TestGuardResult:
    def test_refusal_rate_normal(self):
        gr = GuardResult(refusal_count=3, probe_count=10)
        assert abs(gr.refusal_rate - 0.3) < 1e-9

    def test_refusal_rate_zero_probes(self):
        gr = GuardResult(probe_count=0)
        assert gr.refusal_rate == 0.0          # no ZeroDivisionError

    def test_refusal_rate_full(self):
        gr = GuardResult(refusal_count=5, probe_count=5)
        assert gr.refusal_rate == 1.0

    def test_defaults(self):
        gr = GuardResult()
        assert gr.safety_layer_active is False
        assert gr.filter_type == "unknown"
        assert gr.system_prompt_present is False
        assert gr.system_prompt_leak is None


class TestScanResult:
    def _make(self):
        sr = ScanResult(target="https://test.example.com")
        sr.endpoints = [
            EndpointResult("/v1/chat/completions", EndpointState.OPEN,     "llm-chat",   10, 200),
            EndpointResult("/v1/models",           EndpointState.FILTERED, "llm-models",  5, 401),
            EndpointResult("/api/chat",            EndpointState.CLOSED,   "llm-chat",    2, 404),
            EndpointResult("/healthz",             EndpointState.UNKNOWN,  "llm-health",  0,   0),
        ]
        return sr

    def test_open_endpoints(self):
        sr = self._make()
        assert len(sr.open_endpoints) == 1
        assert sr.open_endpoints[0].path == "/v1/chat/completions"

    def test_filtered_endpoints(self):
        sr = self._make()
        assert len(sr.filtered_endpoints) == 1
        assert sr.filtered_endpoints[0].path == "/v1/models"

    def test_duration(self):
        sr = ScanResult(target="x", scan_start=time.time() - 5)
        sr.scan_end = time.time()
        assert sr.duration >= 4.9

    def test_duration_in_progress(self):
        sr = ScanResult(target="x", scan_start=time.time() - 2)
        # scan_end=0 (still running) → duration uses time.time()
        assert sr.duration >= 1.9
