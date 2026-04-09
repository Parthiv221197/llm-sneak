"""Tests for llmsneak.constants — run with pytest OR python3 -m unittest"""
import sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from llmsneak.constants import (
    KNOWN_ENDPOINTS, PROVIDER_HEADER_SIGNATURES,
    STATUS_STATE_MAP, TIMING_TEMPLATES, TIMING_NAMES, VERSION,
)


class TestEndpoints(unittest.TestCase):

    def test_minimum_count(self):
        self.assertGreaterEqual(len(KNOWN_ENDPOINTS), 30)

    def test_all_paths_start_with_slash(self):
        bad = [p for p,_ in KNOWN_ENDPOINTS if not p.startswith("/")]
        self.assertFalse(bad, f"Paths without leading /: {bad}")

    def test_no_empty_service_labels(self):
        bad = [(p,s) for p,s in KNOWN_ENDPOINTS if not s.strip()]
        self.assertFalse(bad, f"Empty service labels: {bad}")

    def test_critical_paths_present(self):
        paths = {p for p,_ in KNOWN_ENDPOINTS}
        for required in ["/v1/chat/completions","/v1/messages","/api/chat","/api/tags","/mcp"]:
            self.assertIn(required, paths, f"Missing: {required}")


class TestStatusStateMap(unittest.TestCase):

    def test_200_open(self):
        self.assertEqual(STATUS_STATE_MAP[200], "open")

    def test_400_open(self):
        """Bad Request → endpoint exists, needs correct body."""
        self.assertEqual(STATUS_STATE_MAP[400], "open")

    def test_401_filtered(self):
        """Unauthorized → endpoint exists, needs auth."""
        self.assertEqual(STATUS_STATE_MAP[401], "filtered")

    def test_403_filtered(self):
        self.assertEqual(STATUS_STATE_MAP[403], "filtered")

    def test_429_filtered(self):
        """Rate limited → endpoint exists."""
        self.assertEqual(STATUS_STATE_MAP[429], "filtered")

    def test_500_open(self):
        """Server error → endpoint exists."""
        self.assertEqual(STATUS_STATE_MAP[500], "open")

    def test_all_values_valid(self):
        valid = {"open", "filtered", "closed"}
        for code, state in STATUS_STATE_MAP.items():
            self.assertIn(state, valid, f"HTTP {code} → invalid state '{state}'")


class TestTimingTemplates(unittest.TestCase):

    def test_all_six_levels_present(self):
        for level in range(6):
            self.assertIn(level, TIMING_TEMPLATES)

    def test_fields_are_positive_ints(self):
        for level, (concurrent, delay, timeout) in TIMING_TEMPLATES.items():
            self.assertGreaterEqual(concurrent, 1)
            self.assertGreaterEqual(delay,      0)
            self.assertGreaterEqual(timeout,    1)

    def test_concurrency_increases(self):
        vals = [TIMING_TEMPLATES[l][0] for l in range(6)]
        self.assertEqual(vals, sorted(vals))

    def test_delay_decreases(self):
        vals = [TIMING_TEMPLATES[l][1] for l in range(6)]
        self.assertEqual(vals, sorted(vals, reverse=True))

    def test_names_correct(self):
        self.assertEqual(TIMING_NAMES[0], "paranoid")
        self.assertEqual(TIMING_NAMES[3], "normal")
        self.assertEqual(TIMING_NAMES[5], "insane")


class TestProviderSignatures(unittest.TestCase):

    def test_required_providers_present(self):
        for p in ["openai","anthropic","google","azure","ollama"]:
            self.assertIn(p, PROVIDER_HEADER_SIGNATURES)

    def test_signature_format(self):
        for provider, sigs in PROVIDER_HEADER_SIGNATURES.items():
            self.assertIsInstance(sigs, list)
            for entry in sigs:
                self.assertEqual(len(entry), 2)
                header_name, pattern = entry
                self.assertIsInstance(header_name, str)
                self.assertTrue(pattern is None or isinstance(pattern, str))


class TestVersion(unittest.TestCase):

    def test_semver_format(self):
        parts = VERSION.split(".")
        self.assertEqual(len(parts), 3, f"Version '{VERSION}' should be X.Y.Z")
        for part in parts:
            self.assertTrue(part.isdigit(), f"Part '{part}' not numeric")


if __name__ == "__main__":
    unittest.main(verbosity=2)
