"""
Tests for llmsneak.cli argument parsing and llmsneak.scanner._normalise_target.
No network calls — all pure logic.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from llmsneak.cli import build_parser
from llmsneak.scanner import _normalise_target, ScanConfig


class TestNormaliseTarget:
    """Verify URL scheme inference works correctly for all target formats."""

    def test_https_passthrough(self):
        assert _normalise_target("https://api.openai.com") == "https://api.openai.com"

    def test_http_passthrough(self):
        assert _normalise_target("http://localhost:11434") == "http://localhost:11434"

    def test_trailing_slash_stripped(self):
        assert _normalise_target("https://api.openai.com/") == "https://api.openai.com"

    def test_bare_hostname_gets_https(self):
        result = _normalise_target("api.openai.com")
        assert result == "https://api.openai.com"

    def test_localhost_gets_http(self):
        result = _normalise_target("localhost:11434")
        assert result.startswith("http://")

    def test_127_0_0_1_gets_http(self):
        result = _normalise_target("127.0.0.1:8080")
        assert result.startswith("http://")

    def test_ollama_port_gets_http(self):
        result = _normalise_target("myserver:11434")
        assert result.startswith("http://")

    def test_lmstudio_port_gets_http(self):
        result = _normalise_target("localhost:1234")
        assert result.startswith("http://")

    def test_vllm_port_gets_http(self):
        result = _normalise_target("gpu-server:8000")
        assert result.startswith("http://")

    def test_internal_192_gets_http(self):
        result = _normalise_target("192.168.1.100:11434")
        assert result.startswith("http://")

    def test_cloud_api_gets_https(self):
        for host in ["api.anthropic.com", "generativelanguage.googleapis.com"]:
            result = _normalise_target(host)
            assert result.startswith("https://"), f"{host} should get https"


class TestCliParser:
    """Verify argparse flags parse correctly."""

    def _parse(self, *args):
        parser = build_parser()
        return parser.parse_args(list(args))

    def test_target_required(self):
        import pytest
        with pytest.raises(SystemExit):
            self._parse()   # no target → error

    def test_basic_target(self):
        args = self._parse("https://api.openai.com")
        assert args.target == "https://api.openai.com"

    def test_default_timing(self):
        args = self._parse("https://api.openai.com")
        assert args.timing == 3

    def test_timing_flag(self):
        args = self._parse("-T4", "https://api.openai.com")
        assert args.timing == 4

    def test_sn_flag(self):
        args = self._parse("-sn", "https://api.openai.com")
        assert args.discovery_only is True

    def test_sv_flag(self):
        args = self._parse("-sV", "https://api.openai.com")
        assert args.version_detect is True

    def test_aggressive_flag(self):
        args = self._parse("-A", "https://api.openai.com")
        assert args.aggressive is True

    def test_api_key(self):
        args = self._parse("--api-key", "sk-test123", "https://api.openai.com")
        assert args.api_key == "sk-test123"

    def test_model_flag(self):
        args = self._parse("--model", "llama3", "http://localhost:11434")
        assert args.model == "llama3"

    def test_script_flag(self):
        args = self._parse("--script", "guards,capabilities", "https://api.openai.com")
        assert "guards" in args.script
        assert "capabilities" in args.script

    def test_output_flags(self):
        args = self._parse("-oN", "out.txt", "-oJ", "out.json",
                           "https://api.openai.com")
        assert args.output_normal == "out.txt"
        assert args.output_json   == "out.json"

    def test_output_all_flag(self):
        args = self._parse("-oA", "my_scan", "https://api.openai.com")
        assert args.output_all == "my_scan"

    def test_paths_flag(self):
        args = self._parse("-p", "/v1/chat/completions,/v1/models",
                           "https://api.openai.com")
        assert args.paths == "/v1/chat/completions,/v1/models"

    def test_verbose_count(self):
        args = self._parse("-v", "https://api.openai.com")
        assert args.verbose == 1
        args2 = self._parse("-v", "-v", "https://api.openai.com")
        assert args2.verbose == 2

    def test_open_flag(self):
        args = self._parse("--open", "https://api.openai.com")
        assert args.open is True

    def test_t_out_of_range(self):
        import pytest
        with pytest.raises(SystemExit):
            self._parse("-T6", "https://api.openai.com")  # max is 5


class TestScanConfig:
    """Verify ScanConfig builds correctly from parsed args."""

    def _cfg(self, *args):
        parser = build_parser()
        parsed = parser.parse_args(list(args))
        return ScanConfig(parsed)

    def test_basic_target_normalised(self):
        cfg = self._cfg("localhost:11434")
        assert cfg.target.startswith("http://")

    def test_aggressive_enables_all_phases(self):
        cfg = self._cfg("-A", "https://api.openai.com")
        assert cfg.run_provider
        assert cfg.run_fingerprint
        assert cfg.run_capabilities
        assert cfg.run_guards

    def test_discovery_only_disables_all(self):
        cfg = self._cfg("-sn", "https://api.openai.com")
        assert cfg.discovery_only is True
        assert cfg.run_fingerprint is False
        assert cfg.run_capabilities is False
        assert cfg.run_guards is False

    def test_script_all_enables_all(self):
        cfg = self._cfg("--script", "all", "https://api.openai.com")
        assert cfg.run_capabilities is True
        assert cfg.run_guards is True

    def test_custom_paths_parsed(self):
        cfg = self._cfg("-p", "/v1/chat/completions,/api/chat", "https://api.openai.com")
        assert cfg.custom_paths is not None
        paths = [p for p, _ in cfg.custom_paths]
        assert "/v1/chat/completions" in paths
        assert "/api/chat" in paths

    def test_timing_config(self):
        cfg = self._cfg("-T4", "https://api.openai.com")
        assert cfg.timing.level == 4
        assert cfg.timing.name == "aggressive"
        assert cfg.timing.max_concurrent == 5
