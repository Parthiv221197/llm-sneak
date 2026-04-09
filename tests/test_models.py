"""Tests for llmsneak.models — run with pytest OR python3 -m unittest"""
import sys, time, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from llmsneak.models import (
    Confidence, EndpointResult, EndpointState,
    ProviderResult, GuardResult,
    AccessResult, MCPTool, MCPResult, ScanResult,
)

class TestConfidence(unittest.TestCase):
    def test_thresholds(self):
        self.assertEqual(Confidence.from_score(1.0),  Confidence.HIGH)
        self.assertEqual(Confidence.from_score(0.75), Confidence.HIGH)
        self.assertEqual(Confidence.from_score(0.74), Confidence.MEDIUM)
        self.assertEqual(Confidence.from_score(0.50), Confidence.MEDIUM)
        self.assertEqual(Confidence.from_score(0.49), Confidence.LOW)
        self.assertEqual(Confidence.from_score(0.01), Confidence.LOW)
        self.assertEqual(Confidence.from_score(0.0),  Confidence.NONE)
        self.assertEqual(Confidence.from_score(-1.0), Confidence.NONE)

    def test_colors(self):
        self.assertEqual(Confidence.HIGH.color(),   "green")
        self.assertEqual(Confidence.MEDIUM.color(), "yellow")
        self.assertEqual(Confidence.LOW.color(),    "orange3")
        self.assertEqual(Confidence.NONE.color(),   "red")


class TestEndpointResult(unittest.TestCase):
    def test_state_colors(self):
        cases = [
            (EndpointState.OPEN,     "green"),
            (EndpointState.FILTERED, "yellow"),
            (EndpointState.CLOSED,   "red"),
            (EndpointState.UNKNOWN,  "dim"),
        ]
        for state, expected in cases:
            ep = EndpointResult(path="/test", state=state)
            self.assertEqual(ep.state_color(), expected)

    def test_defaults(self):
        ep = EndpointResult(path="/v1/chat", state=EndpointState.OPEN)
        self.assertEqual(ep.service, "")
        self.assertEqual(ep.latency_ms, 0.0)
        self.assertEqual(ep.status_code, 0)
        self.assertEqual(ep.headers, {})
        self.assertIsNone(ep.error)


class TestGuardResult(unittest.TestCase):
    def test_refusal_rate(self):
        gr = GuardResult(refusal_count=3, probe_count=10)
        self.assertAlmostEqual(gr.refusal_rate, 0.3)

    def test_no_divide_by_zero(self):
        gr = GuardResult(probe_count=0)
        self.assertEqual(gr.refusal_rate, 0.0)

    def test_full_refusal(self):
        gr = GuardResult(refusal_count=5, probe_count=5)
        self.assertEqual(gr.refusal_rate, 1.0)


class TestMCPResult(unittest.TestCase):
    def test_risk_progression(self):
        mc = MCPResult()
        self.assertEqual(mc.highest_risk, "INFO")
        mc.tool_count = 1
        self.assertEqual(mc.highest_risk, "LOW")
        mc.has_web_access = True
        self.assertEqual(mc.highest_risk, "MEDIUM")
        mc.has_file_access = True
        self.assertEqual(mc.highest_risk, "HIGH")
        mc.has_shell_access = True
        self.assertEqual(mc.highest_risk, "CRITICAL")

    def test_post_init_not_none(self):
        mc = MCPResult()
        self.assertIsNotNone(mc.servers)
        self.assertIsNotNone(mc.evidence)

    def test_mcp_tool_schema_defaults(self):
        t = MCPTool(name="bash")
        self.assertEqual(t.input_schema, {})
        self.assertEqual(t.risk_level, "LOW")


class TestScanResult(unittest.TestCase):
    def _build(self):
        sr = ScanResult(target="https://test.example.com")
        sr.endpoints = [
            EndpointResult("/v1/chat",   EndpointState.OPEN,     latency_ms=10, status_code=200),
            EndpointResult("/v1/models", EndpointState.FILTERED, latency_ms=5,  status_code=401),
            EndpointResult("/healthz",   EndpointState.CLOSED,   latency_ms=2,  status_code=404),
        ]
        return sr

    def test_open_endpoints(self):
        sr = self._build()
        self.assertEqual(len(sr.open_endpoints), 1)
        self.assertEqual(sr.open_endpoints[0].path, "/v1/chat")

    def test_filtered_endpoints(self):
        sr = self._build()
        self.assertEqual(len(sr.filtered_endpoints), 1)

    def test_duration_completed(self):
        sr = ScanResult(target="x", scan_start=time.time() - 5)
        sr.scan_end = time.time()
        self.assertGreaterEqual(sr.duration, 4.9)

    def test_duration_in_progress(self):
        sr = ScanResult(target="x", scan_start=time.time() - 2)
        self.assertEqual(sr.scan_end, 0.0)
        self.assertGreaterEqual(sr.duration, 1.9)

    def test_all_optional_none_by_default(self):
        sr = ScanResult(target="x")
        for field in ["access","provider","fingerprint","capabilities","guards","vulns","mcp"]:
            self.assertIsNone(getattr(sr, field), f"{field} should be None")

if __name__ == "__main__":
    unittest.main(verbosity=2)
