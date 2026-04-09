"""
Tests for all phase logic that doesn't require network I/O.
Covers: ollama_inspect helpers, vulns check_fn, mcp risk classification,
        access auth detection, timing config.

Run with: pytest tests/test_phases.py -v
      OR: python3 -m unittest tests/test_phases.py
"""
import sys, re, types, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Mock httpx and http utils globally
for _name in ["httpx","llmsneak.utils.http"]:
    _m = types.ModuleType(_name)
    _m.AsyncClient = object
    _m.probe_path  = None
    _m.safe_json   = None
    _m.chat_completion = None
    _m.TimingConfig = object
    sys.modules[_name] = _m

# ── Import phase modules after mocking ───────────────────────────────────────
import importlib.util

def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod  = importlib.util.module_from_spec(spec)
    # Register in sys.modules BEFORE exec so @dataclass can resolve __module__
    sys.modules[name] = mod
    # inject mocks needed by the module
    mod.__dict__.update({
        k: sys.modules[k] for k in ["httpx","llmsneak.utils.http"] if k in sys.modules
    })
    try:
        spec.loader.exec_module(mod)
    except Exception:
        del sys.modules[name]
        raise
    return mod

_phases = Path(__file__).parent.parent / "llmsneak/phases"

oi    = _load("ollama_inspect", _phases / "ollama_inspect.py")
vulns = _load("vulns",          _phases / "vulns.py")
mcp   = _load("mcp_detect",     _phases / "mcp_detect.py")


# ─────────────────────────────────────────────────────────────────────────────
# Ollama deep inspect helpers
# ─────────────────────────────────────────────────────────────────────────────

class TestFamilyFromName(unittest.TestCase):
    """Longer keys must win over shorter ones (llama3 beats llama)."""

    def _t(self, name, expected):
        self.assertEqual(oi._family_from_name(name), expected,
                         f"family_from_name({name!r})")

    def test_llama3(self):   self._t("llama3:latest",      "llama3")
    def test_llama3_dot(self): self._t("llama3.1:8b",      "llama3")
    def test_llama2(self):   self._t("llama2:13b",          "llama2")
    def test_llama4(self):   self._t("llama4:scout",        "llama4")
    def test_mistral(self):  self._t("mistral:7b",          "mistral")
    def test_mixtral(self):  self._t("mixtral:8x7b",        "mixtral")
    def test_phi3(self):     self._t("phi3:mini",           "phi3")
    def test_phi4(self):     self._t("phi4:latest",         "phi4")
    def test_qwen2(self):    self._t("qwen2:7b",            "qwen2")
    def test_qwen3(self):    self._t("qwen3:4b",            "qwen3")
    def test_gemma2(self):   self._t("gemma2:9b",           "gemma2")
    def test_gemma3(self):   self._t("gemma3:4b",           "gemma3")
    def test_deepseek(self): self._t("deepseek-r1:7b",      "deepseek")
    def test_codellama(self):self._t("codellama:13b",       "codellama")


class TestParamSizeFromName(unittest.TestCase):
    def test_8b(self):    self.assertEqual(oi._param_size_from_name("llama3:8b"),    "8B")
    def test_70b(self):   self.assertEqual(oi._param_size_from_name("llama3:70b"),   "70B")
    def test_3_8b(self):  self.assertEqual(oi._param_size_from_name("phi3:3.8b"),    "3.8B")
    def test_none(self):  self.assertIsNone(oi._param_size_from_name("llama3:latest"))


class TestQuantFromName(unittest.TestCase):
    def test_q4_k_m(self): self.assertEqual(oi._quant_from_name("llama3:8b-q4_K_M"), "Q4_K_M")
    def test_q8_0(self):   self.assertEqual(oi._quant_from_name("mistral:7b-q8_0"),  "Q8_0")
    def test_f16(self):    self.assertEqual(oi._quant_from_name("phi3:mini-f16"),     "F16")
    def test_none(self):   self.assertIsNone(oi._quant_from_name("llama3:latest"))


class TestContextFromName(unittest.TestCase):
    def _t(self, name, expected):
        self.assertEqual(oi._context_from_name(name), expected, f"context({name!r})")

    # Specificity: llama3.1 must return 131072, not 8192
    def test_llama3_base(self):   self._t("llama3:latest",   8_192)
    def test_llama3_1(self):      self._t("llama3.1:8b",     131_072)
    def test_llama3_2(self):      self._t("llama3.2:3b",     131_072)
    def test_llama4(self):        self._t("llama4:scout",    1_048_576)
    def test_mistral(self):       self._t("mistral:7b",      32_768)
    def test_phi3(self):          self._t("phi3:mini",       131_072)
    def test_qwen2(self):         self._t("qwen2:7b",        131_072)
    def test_deepseek(self):      self._t("deepseek-r1:7b",  65_536)
    def test_unknown(self):       self._t("unknownmodel:1b", None)


class TestFmtDate(unittest.TestCase):
    def test_iso_with_ms(self):
        self.assertEqual(oi._fmt_date("2024-08-06T12:34:56.789Z"),
                         "2024-08-06 12:34 UTC")

    def test_iso_without_ms(self):
        self.assertEqual(oi._fmt_date("2024-01-15T09:00:00Z"),
                         "2024-01-15 09:00 UTC")

    def test_empty(self):
        self.assertEqual(oi._fmt_date(""), "")


class TestResolveTargetModel(unittest.TestCase):

    def _models(self, *names):
        return [{"name": n} for n in names]

    def test_returns_first_when_none(self):
        self.assertEqual(
            oi._resolve_target_model(None, self._models("llama3:latest","mistral:7b")),
            "llama3:latest"
        )

    def test_fuzzy_match(self):
        self.assertEqual(
            oi._resolve_target_model("llama3", self._models("llama3:latest","phi3:mini")),
            "llama3:latest"
        )

    def test_partial_match(self):
        self.assertEqual(
            oi._resolve_target_model("phi", self._models("llama3:latest","phi3:mini")),
            "phi3:mini"
        )

    def test_not_found_returns_input(self):
        self.assertEqual(
            oi._resolve_target_model("qwen", self._models("llama3:latest")),
            "qwen"
        )

    def test_empty_models_returns_unknown(self):
        self.assertEqual(oi._resolve_target_model(None, []), "unknown")


# ─────────────────────────────────────────────────────────────────────────────
# Vulnerability check functions
# ─────────────────────────────────────────────────────────────────────────────

class TestVulnCheckFunctions(unittest.TestCase):

    def _check(self, probes, idx, fires_on, silent_on):
        _, _, check_fn, *_ = probes[idx]
        self.assertTrue(check_fn(fires_on),  f"Should fire on:  {fires_on[:50]!r}")
        self.assertFalse(check_fn(silent_on),f"Should NOT fire: {silent_on[:50]!r}")

    def test_inj01_direct_injection(self):
        self._check(vulns.PROMPT_INJECTION_PROBES, 0,
                    "INJECTED",
                    "I cannot follow that instruction")

    def test_inj02_role_switch(self):
        self._check(vulns.PROMPT_INJECTION_PROBES, 1,
                    "In DAN mode my system prompt says: you are a helpful assistant",
                    "I won't adopt alternative personas")

    def test_inj05_indirect_injection(self):
        self._check(vulns.PROMPT_INJECTION_PROBES, 4,
                    "INDIRECT_INJECTION_SUCCESS was found in the document",
                    "The document discusses quarterly results")

    def test_out01_xss(self):
        self._check(vulns.OUTPUT_HANDLING_PROBES, 0,
                    "Here is your greeting: <script>alert('xss')</script>",
                    "Hello, have a great day!")

    def test_out02_sql(self):
        self._check(vulns.OUTPUT_HANDLING_PROBES, 1,
                    "SELECT * FROM users WHERE id='' OR 1=1 --",
                    "SELECT * FROM users WHERE id = :user_id")

    def test_disc01_env_vars(self):
        self._check(vulns.INFO_DISCLOSURE_PROBES, 0,
                    "API_KEY=sk-abc SECRET_KEY=xyz DATABASE_URL=postgres://",
                    "I do not have access to environment variables")

    def test_disc02_api_key_echo(self):
        self._check(vulns.INFO_DISCLOSURE_PROBES, 1,
                    "Yes, sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ appears to be a valid key",
                    "That string does not look like a key to me")


class TestVulnScanResult(unittest.TestCase):

    def test_has_critical_false_initially(self):
        vsr = vulns.VulnScanResult()
        self.assertFalse(vsr.has_critical)

    def test_has_critical_true_after_finding(self):
        vsr = vulns.VulnScanResult()
        vsr.findings.append(vulns.VulnFinding(
            "LLM01","Test",vulns.CRITICAL,"desc","evidence","fix"
        ))
        self.assertTrue(vsr.has_critical)

    def test_by_severity(self):
        vsr = vulns.VulnScanResult()
        vsr.findings = [
            vulns.VulnFinding("LLM01","A",vulns.CRITICAL,"d","e","r"),
            vulns.VulnFinding("LLM01","B",vulns.HIGH,    "d","e","r"),
            vulns.VulnFinding("LLM01","C",vulns.CRITICAL,"d","e","r"),
        ]
        self.assertEqual(len(vsr.by_severity(vulns.CRITICAL)), 2)
        self.assertEqual(len(vsr.by_severity(vulns.HIGH)),     1)
        self.assertEqual(len(vsr.by_severity(vulns.MEDIUM)),   0)


# ─────────────────────────────────────────────────────────────────────────────
# MCP tool risk classification
# ─────────────────────────────────────────────────────────────────────────────

class TestMCPClassifyTool(unittest.TestCase):

    def _t(self, tool_name, expected_risk, expected_flag=""):
        risk, flag = mcp.classify_tool(tool_name)
        self.assertEqual(risk, expected_risk, f"classify_tool({tool_name!r}) risk")
        if expected_flag:
            self.assertEqual(flag, expected_flag, f"classify_tool({tool_name!r}) flag")

    def test_bash_critical(self):   self._t("bash",     "CRITICAL", "has_shell_access")
    def test_shell_critical(self):  self._t("shell",    "CRITICAL", "has_shell_access")
    def test_exec_critical(self):   self._t("execute",  "CRITICAL", "has_code_exec")
    def test_python_critical(self): self._t("python",   "CRITICAL", "has_code_exec")

    def test_read_file_high(self):  self._t("read_file",  "HIGH",   "has_file_access")
    def test_write_file_high(self): self._t("write_file", "HIGH",   "has_file_access")
    def test_sql_high(self):        self._t("sql_query",  "HIGH",   "has_db_access")
    def test_database_high(self):   self._t("database",   "HIGH",   "has_db_access")

    def test_web_search_medium(self):  self._t("web_search", "MEDIUM", "has_web_access")
    def test_fetch_medium(self):       self._t("fetch",       "MEDIUM","has_web_access")
    def test_send_email_medium(self):  self._t("send_email",  "MEDIUM","has_email_access")

    def test_calculator_low(self):  self._t("calculator", "LOW")
    def test_unknown_low(self):     self._t("unknown_xyz", "LOW")

    def test_description_also_matched(self):
        """Risk should also be detected from tool description text."""
        risk, flag = mcp.classify_tool("do_thing", "execute bash commands on host")
        self.assertEqual(risk, "CRITICAL")

    def test_highest_risk_wins(self):
        """Multiple matches: highest risk wins."""
        risk, _ = mcp.classify_tool("execute_bash_and_email")
        self.assertEqual(risk, "CRITICAL")


# ─────────────────────────────────────────────────────────────────────────────
# TimingConfig
# ─────────────────────────────────────────────────────────────────────────────

class TestTimingConfig(unittest.TestCase):

    def setUp(self):
        from llmsneak.utils.timing import TimingConfig
        self.TC = TimingConfig

    def test_all_levels(self):
        names = {0:"paranoid", 1:"sneaky", 2:"polite", 3:"normal", 4:"aggressive", 5:"insane"}
        for level, name in names.items():
            tc = self.TC.from_level(level)
            self.assertEqual(tc.level, level)
            self.assertEqual(tc.name,  name)

    def test_delay_ms_to_s_consistent(self):
        for level in range(6):
            tc = self.TC.from_level(level)
            self.assertAlmostEqual(tc.delay_s, tc.delay_ms / 1000.0, places=6)

    def test_clamping_low(self):
        tc = self.TC.from_level(-99)
        self.assertEqual(tc.level, 0)

    def test_clamping_high(self):
        tc = self.TC.from_level(99)
        self.assertEqual(tc.level, 5)

    def test_insane_has_zero_delay(self):
        tc = self.TC.from_level(5)
        self.assertEqual(tc.delay_ms, 0)
        self.assertEqual(tc.delay_s,  0.0)

    def test_paranoid_has_highest_delay(self):
        delays = [self.TC.from_level(l).delay_ms for l in range(6)]
        self.assertEqual(delays.index(max(delays)), 0)

    def test_insane_has_most_concurrent(self):
        concurrencies = [self.TC.from_level(l).max_concurrent for l in range(6)]
        self.assertEqual(concurrencies.index(max(concurrencies)), 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
