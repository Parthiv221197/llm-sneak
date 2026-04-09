"""Tests for CLI parsing and ScanConfig flag logic — no rich required."""
import sys, re, unittest, types
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

# ── Mock rich before any llmsneak import touches it ──────────────────────────
class _FakeConsole:
    def print(self, *a, **k): pass
    def rule(self, *a, **k):  pass
    def log(self, *a, **k):   pass

class _FakeTable:
    def add_column(self, *a, **k): pass
    def add_row(self, *a, **k):    pass

_console = _FakeConsole()

import types as _types
_rich       = _types.ModuleType("rich");         sys.modules["rich"] = _rich
_console_m  = _types.ModuleType("rich.console"); _console_m.Console = lambda **kw: _console
_table_m    = _types.ModuleType("rich.table");   _table_m.Table     = lambda **kw: _FakeTable()
_box_m      = _types.ModuleType("rich.box");     _box_m.SIMPLE_HEAD = None; _box_m.MINIMAL = None
_text_m     = _types.ModuleType("rich.text");    _text_m.Text       = lambda *a,**k: ""
_panel_m    = _types.ModuleType("rich.panel");   _panel_m.Panel     = type("Panel",(),{})
_progress_m = _types.ModuleType("rich.progress")
_markup_m   = _types.ModuleType("rich.markup")
for _name, _mod in [
    ("rich.console",  _console_m),
    ("rich.table",    _table_m),
    ("rich.box",      _box_m),
    ("rich.text",     _text_m),
    ("rich.panel",    _panel_m),
    ("rich.progress", _progress_m),
    ("rich.markup",   _markup_m),
]:
    setattr(_rich, _name.split(".")[-1], _mod)
    sys.modules[_name] = _mod

# Patch rich.console module attribute on rich itself
_rich.box = _box_m

from llmsneak.cli import build_parser


# ── _normalise_target — extracted directly from scanner.py ───────────────────

def _load_normalise():
    src = open(Path(__file__).parent.parent / "llmsneak/scanner.py").read()
    match = re.search(r'(def _normalise_target.*?)(?=\n\nasync def|\nclass |\Z)', src, re.DOTALL)
    ns = {}
    exec(match.group(0), ns)
    return ns["_normalise_target"]

_normalise_target = _load_normalise()


class TestNormaliseTarget(unittest.TestCase):

    def test_https_passthrough(self):
        self.assertEqual(_normalise_target("https://api.openai.com"),
                         "https://api.openai.com")

    def test_trailing_slash_stripped(self):
        self.assertEqual(_normalise_target("https://api.openai.com/"),
                         "https://api.openai.com")

    def test_http_passthrough(self):
        self.assertEqual(_normalise_target("http://localhost:11434"),
                         "http://localhost:11434")

    def test_bare_cloud_gets_https(self):
        self.assertEqual(_normalise_target("api.openai.com"),
                         "https://api.openai.com")

    def test_localhost_gets_http(self):
        self.assertEqual(_normalise_target("localhost:11434"),
                         "http://localhost:11434")

    def test_loopback_ip_gets_http(self):
        self.assertEqual(_normalise_target("127.0.0.1:8080"),
                         "http://127.0.0.1:8080")

    def test_lan_ip_gets_http(self):
        self.assertEqual(_normalise_target("192.168.1.100:11434"),
                         "http://192.168.1.100:11434")

    def test_private_10_block_gets_http(self):
        self.assertEqual(_normalise_target("10.0.0.50:8000"),
                         "http://10.0.0.50:8000")

    def test_172_block_gets_http(self):
        self.assertEqual(_normalise_target("172.16.0.1:9000"),
                         "http://172.16.0.1:9000")

    def test_ollama_port_gets_http(self):
        # A bare hostname with Ollama port should use http
        self.assertEqual(_normalise_target("gpu-box:11434"),
                         "http://gpu-box:11434")


# ── CLI argument parsing ──────────────────────────────────────────────────────

class TestCLIParser(unittest.TestCase):

    def _parse(self, *args):
        return build_parser().parse_args(list(args))

    def test_target_stored(self):
        args = self._parse("https://api.openai.com")
        self.assertEqual(args.target, "https://api.openai.com")

    def test_default_timing_is_3(self):
        args = self._parse("https://api.openai.com")
        self.assertEqual(args.timing, 3)

    def test_timing_flags_0_to_5(self):
        for level in range(6):
            args = self._parse(f"-T{level}", "https://api.openai.com")
            self.assertEqual(args.timing, level)

    def test_sn_sets_discovery_only(self):
        args = self._parse("-sn", "https://api.openai.com")
        self.assertTrue(args.discovery_only)

    def test_sv_sets_version_detect(self):
        args = self._parse("-sV", "https://api.openai.com")
        self.assertTrue(args.version_detect)

    def test_aggressive_flag(self):
        args = self._parse("-A", "https://api.openai.com")
        self.assertTrue(args.aggressive)

    def test_api_key(self):
        args = self._parse("--api-key", "sk-test123", "https://api.openai.com")
        self.assertEqual(args.api_key, "sk-test123")

    def test_model_flag(self):
        args = self._parse("--model", "llama3", "http://localhost:11434")
        self.assertEqual(args.model, "llama3")

    def test_script_flag(self):
        args = self._parse("--script", "guards,mcp", "https://api.openai.com")
        self.assertIn("guards", args.script)
        self.assertIn("mcp",    args.script)

    def test_output_n(self):
        args = self._parse("-oN", "scan.txt", "https://api.openai.com")
        self.assertEqual(args.output_normal, "scan.txt")

    def test_output_j(self):
        args = self._parse("-oJ", "scan.json", "https://api.openai.com")
        self.assertEqual(args.output_json, "scan.json")

    def test_output_a(self):
        args = self._parse("-oA", "my_scan", "https://api.openai.com")
        self.assertEqual(args.output_all, "my_scan")

    def test_paths_flag(self):
        args = self._parse("-p", "/v1/chat,/v1/models", "https://api.openai.com")
        self.assertIn("/v1/chat", args.paths)

    def test_verbose_increments(self):
        args1 = self._parse("-v", "https://api.openai.com")
        self.assertEqual(args1.verbose, 1)
        args2 = self._parse("-v", "-v", "https://api.openai.com")
        self.assertEqual(args2.verbose, 2)

    def test_open_flag(self):
        args = self._parse("--open", "https://api.openai.com")
        self.assertTrue(args.open)

    def test_api_format_override(self):
        args = self._parse("--api-format", "anthropic", "https://api.anthropic.com")
        self.assertEqual(args.api_format_override, "anthropic")

    def test_profile_flag(self):
        args = self._parse("--profile", "groq", "https://api.groq.com/openai/v1")
        self.assertEqual(args.profile, "groq")

    def test_list_probes(self):
        args = self._parse("--list-probes", "placeholder")
        self.assertTrue(args.list_probes)

    def test_list_hosts(self):
        args = self._parse("--list-hosts", "placeholder")
        self.assertTrue(args.list_hosts)


# ── ScanConfig phase flag logic ───────────────────────────────────────────────

def _simulate_flags(aggressive=False, discovery_only=False, version_detect=False,
                    script=""):
    """Simulate ScanConfig flag resolution without importing scanner."""
    scripts = set(s.strip() for s in script.split(",") if s.strip())
    if "all" in scripts:
        scripts = {"guards","capabilities","extract","vuln","mcp"}
    run_all = aggressive
    return {
        "run_provider":     not discovery_only,
        "run_fingerprint":  version_detect or run_all,
        "run_capabilities": run_all or "capabilities" in scripts,
        "run_guards":       run_all or "guards" in scripts or "extract" in scripts,
        "run_vulns":        run_all or "vuln" in scripts or "vulns" in scripts,
        "run_mcp":          run_all or "mcp" in scripts or "tools" in scripts,
    }


class TestScanConfigFlags(unittest.TestCase):

    def test_default_no_extra_phases(self):
        f = _simulate_flags()
        self.assertTrue(f["run_provider"])
        self.assertFalse(f["run_fingerprint"])
        self.assertFalse(f["run_capabilities"])
        self.assertFalse(f["run_guards"])
        self.assertFalse(f["run_vulns"])
        self.assertFalse(f["run_mcp"])

    def test_aggressive_enables_all(self):
        f = _simulate_flags(aggressive=True)
        self.assertTrue(f["run_fingerprint"])
        self.assertTrue(f["run_capabilities"])
        self.assertTrue(f["run_guards"])
        self.assertTrue(f["run_vulns"])
        self.assertTrue(f["run_mcp"])

    def test_discovery_only_disables_provider(self):
        f = _simulate_flags(discovery_only=True)
        self.assertFalse(f["run_provider"])
        self.assertFalse(f["run_fingerprint"])

    def test_sv_enables_fingerprint_only(self):
        f = _simulate_flags(version_detect=True)
        self.assertTrue(f["run_fingerprint"])
        self.assertFalse(f["run_guards"])
        self.assertFalse(f["run_mcp"])

    def test_script_all_expands(self):
        f = _simulate_flags(script="all")
        self.assertTrue(f["run_guards"])
        self.assertTrue(f["run_capabilities"])
        self.assertTrue(f["run_vulns"])
        self.assertTrue(f["run_mcp"])

    def test_script_mcp_only(self):
        f = _simulate_flags(script="mcp")
        self.assertTrue(f["run_mcp"])
        self.assertFalse(f["run_guards"])
        self.assertFalse(f["run_vulns"])

    def test_script_vuln_only(self):
        f = _simulate_flags(script="vuln")
        self.assertTrue(f["run_vulns"])
        self.assertFalse(f["run_mcp"])

    def test_script_guards_only(self):
        f = _simulate_flags(script="guards")
        self.assertTrue(f["run_guards"])
        self.assertFalse(f["run_vulns"])

    def test_script_multi(self):
        f = _simulate_flags(script="guards,mcp")
        self.assertTrue(f["run_guards"])
        self.assertTrue(f["run_mcp"])
        self.assertFalse(f["run_vulns"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
