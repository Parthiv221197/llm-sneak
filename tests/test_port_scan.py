"""
Tests for llmsneak.phases.port_scan — all pure logic, no network I/O.

Run with: python3 -m unittest tests/test_port_scan.py -v
"""
import sys, types, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Mock httpx before any imports
_mock_httpx = types.ModuleType("httpx")
_mock_httpx.AsyncClient = object
_mock_httpx.Timeout     = lambda *a, **k: None
_mock_httpx.ConnectError = ConnectionError
sys.modules["httpx"] = _mock_httpx

# Mock llmsneak.utils.http
_mock_http = types.ModuleType("llmsneak.utils.http")
_mock_http.build_client = None
sys.modules["llmsneak.utils.http"] = _mock_http

from llmsneak.phases.port_scan import (
    extract_host, needs_port_scan,
    _classify_from_body, _check_headers,
)
from llmsneak.constants import LLM_PORTS, LLM_PORT_SCAN_ORDER, LLM_PROBE_PATHS
from llmsneak.models import PortResult, PortScanResult


class TestExtractHost(unittest.TestCase):

    def test_bare_ip(self):
        host, port = extract_host("10.0.0.50")
        self.assertEqual(host, "10.0.0.50")
        self.assertIsNone(port)

    def test_bare_hostname(self):
        host, port = extract_host("gpu-server.local")
        self.assertEqual(host, "gpu-server.local")
        self.assertIsNone(port)

    def test_host_with_port(self):
        host, port = extract_host("10.0.0.50:11434")
        self.assertEqual(host, "10.0.0.50")
        self.assertEqual(port, 11434)

    def test_http_url_no_port(self):
        host, port = extract_host("http://localhost")
        self.assertEqual(host, "localhost")
        self.assertIsNone(port)

    def test_http_url_with_port(self):
        host, port = extract_host("http://localhost:8080")
        self.assertEqual(host, "localhost")
        self.assertEqual(port, 8080)

    def test_https_url_no_port(self):
        host, port = extract_host("https://api.openai.com")
        self.assertEqual(host, "api.openai.com")
        self.assertIsNone(port)

    def test_https_url_with_port(self):
        host, port = extract_host("https://api.openai.com:443")
        self.assertEqual(host, "api.openai.com")
        self.assertEqual(port, 443)

    def test_localhost_only(self):
        host, port = extract_host("localhost")
        self.assertEqual(host, "localhost")
        self.assertIsNone(port)


class TestNeedsPortScan(unittest.TestCase):

    def test_bare_ip_needs_scan(self):
        self.assertTrue(needs_port_scan("10.0.0.50"))

    def test_bare_hostname_needs_scan(self):
        self.assertTrue(needs_port_scan("gpu-server.local"))

    def test_localhost_needs_scan(self):
        self.assertTrue(needs_port_scan("localhost"))

    def test_url_no_port_needs_scan(self):
        self.assertTrue(needs_port_scan("http://localhost"))

    def test_url_with_port_no_scan(self):
        self.assertFalse(needs_port_scan("localhost:11434"))

    def test_full_url_with_port_no_scan(self):
        self.assertFalse(needs_port_scan("http://localhost:11434"))

    def test_cloud_url_no_port_needs_scan(self):
        # Cloud URL with no port — needs scan to find the LLM endpoint
        self.assertTrue(needs_port_scan("https://api.openai.com"))

    def test_cloud_url_with_port_no_scan(self):
        self.assertFalse(needs_port_scan("https://api.openai.com:443"))


class TestClassifyFromBody(unittest.TestCase):

    def test_ollama_by_modified_at(self):
        svc, fmt = _classify_from_body(b'{"models": [{"modified_at": "2024"}]}')
        self.assertEqual(svc, "Ollama")
        self.assertEqual(fmt, "ollama")

    def test_ollama_by_name(self):
        svc, fmt = _classify_from_body(b'error: ollama model not found')
        self.assertEqual(svc, "Ollama")
        self.assertEqual(fmt, "ollama")

    def test_openai_compat_by_owned_by(self):
        svc, fmt = _classify_from_body(b'{"data":[{"owned_by":"meta"}]}')
        self.assertEqual(svc, "OpenAI-compatible")
        self.assertEqual(fmt, "openai")

    def test_vllm_by_name(self):
        svc, fmt = _classify_from_body(b'vllm version 0.4.0')
        self.assertEqual(svc, "vLLM")
        self.assertEqual(fmt, "openai")

    def test_tgi_by_generated_text(self):
        svc, fmt = _classify_from_body(b'{"generated_text": "hello"}')
        self.assertEqual(svc, "HuggingFace TGI")
        self.assertEqual(fmt, "openai")

    def test_llama_cpp(self):
        svc, fmt = _classify_from_body(b'{"model": "llama.cpp model loaded"}')
        self.assertEqual(svc, "llama.cpp")
        self.assertEqual(fmt, "openai")

    def test_unknown_returns_empty(self):
        svc, fmt = _classify_from_body(b'{"hello": "world"}')
        self.assertEqual(svc, "")
        self.assertEqual(fmt, "")

    def test_case_insensitive(self):
        svc, fmt = _classify_from_body(b'OLLAMA version 0.3.12')
        self.assertEqual(svc, "Ollama")


class TestCheckHeaders(unittest.TestCase):

    def test_openai_header_detected(self):
        evidence = _check_headers({"openai-processing-ms": "247"})
        self.assertTrue(len(evidence) > 0)
        self.assertIn("openai-processing-ms", evidence[0])

    def test_anthropic_header_detected(self):
        evidence = _check_headers({"anthropic-ratelimit-requests-limit": "50"})
        self.assertTrue(len(evidence) > 0)

    def test_irrelevant_headers_ignored(self):
        evidence = _check_headers({"content-type": "text/html", "server": "nginx"})
        self.assertEqual(evidence, [])

    def test_empty_headers(self):
        evidence = _check_headers({})
        self.assertEqual(evidence, [])


class TestLLMPortsDatabase(unittest.TestCase):

    def test_ollama_port_present(self):
        self.assertIn(11434, LLM_PORTS)
        svc, fmt, scheme = LLM_PORTS[11434]
        self.assertEqual(svc, "Ollama")
        self.assertEqual(fmt, "ollama")

    def test_lm_studio_present(self):
        self.assertIn(1234, LLM_PORTS)

    def test_vllm_present(self):
        self.assertIn(8000, LLM_PORTS)

    def test_all_ports_have_valid_scheme(self):
        for port, (_, _, scheme) in LLM_PORTS.items():
            self.assertIn(scheme, ("http", "https"), f"Port {port}: invalid scheme {scheme!r}")

    def test_all_ports_have_service_name(self):
        for port, (svc, _, _) in LLM_PORTS.items():
            self.assertTrue(svc, f"Port {port}: empty service name")

    def test_scan_order_references_known_ports(self):
        for port in LLM_PORT_SCAN_ORDER:
            self.assertIn(port, LLM_PORTS, f"Port {port} in scan order but not in LLM_PORTS")

    def test_minimum_port_count(self):
        self.assertGreaterEqual(len(LLM_PORTS), 15)

    def test_probe_paths_have_descriptions(self):
        for path, desc in LLM_PROBE_PATHS:
            self.assertTrue(path.startswith("/"), f"Path {path!r} missing leading /")
            self.assertTrue(desc, f"Path {path!r} has empty description")


class TestPortResult(unittest.TestCase):

    def test_state_colors(self):
        cases = [
            ("open-llm",  "bold green"),
            ("open",      "green"),
            ("filtered",  "yellow"),
            ("closed",    "red"),
            ("unknown",   "dim"),
        ]
        for state, expected in cases:
            pr = PortResult(port=11434, host="localhost", state=state)
            self.assertEqual(pr.state_color(), expected)

    def test_defaults(self):
        pr = PortResult(port=8080, host="10.0.0.50")
        self.assertFalse(pr.is_llm)
        self.assertEqual(pr.state, "closed")
        self.assertEqual(pr.evidence, [])


class TestPortScanResult(unittest.TestCase):

    def test_best_target_ollama_first(self):
        psr = PortScanResult(host="10.0.0.50")
        psr.open_llm_ports = [
            PortResult(8080, "10.0.0.50", "open-llm", "vLLM",  "openai", "http",
                       "http://10.0.0.50:8080", is_llm=True),
            PortResult(11434,"10.0.0.50", "open-llm", "Ollama","ollama", "http",
                       "http://10.0.0.50:11434", is_llm=True),
        ]
        # Ollama should be preferred even though it's second in the list
        self.assertEqual(psr.best_target, "http://10.0.0.50:11434")

    def test_best_target_first_when_no_ollama(self):
        psr = PortScanResult(host="10.0.0.50")
        psr.open_llm_ports = [
            PortResult(8000, "10.0.0.50", "open-llm", "vLLM", "openai", "http",
                       "http://10.0.0.50:8000", is_llm=True),
        ]
        self.assertEqual(psr.best_target, "http://10.0.0.50:8000")

    def test_best_target_none_when_empty(self):
        psr = PortScanResult(host="10.0.0.50")
        self.assertIsNone(psr.best_target)

    def test_all_found_combines_lists(self):
        psr = PortScanResult(host="10.0.0.50")
        psr.open_llm_ports = [PortResult(11434,"x","open-llm","Ollama","ollama","http","http://x:11434",is_llm=True)]
        psr.open_ports     = [PortResult(80,"x","open","HTTP","openai","http","http://x:80")]
        self.assertEqual(len(psr.all_found), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
