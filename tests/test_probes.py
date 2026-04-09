"""Tests for llmsneak.probes.loader — run with pytest OR python3 -m unittest"""
import sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from llmsneak.probes.loader import Matcher, Probe, load_all_packs


class TestMatcherTypes(unittest.TestCase):

    def _m(self, type_, **kwargs):
        return Matcher({"type": type_, "scores": {}, **kwargs})

    def test_contains_case_insensitive(self):
        m = self._m("contains", value="hello")
        self.assertTrue(m.evaluate("Hello World"))
        self.assertFalse(m.evaluate("Goodbye"))

    def test_contains_any(self):
        m = self._m("contains_any", value=["apple","banana"])
        self.assertTrue(m.evaluate("I like apple"))
        self.assertTrue(m.evaluate("banana split"))
        self.assertFalse(m.evaluate("orange juice"))

    def test_contains_any_string_not_list(self):
        m = self._m("contains_any", value="hello")
        self.assertTrue(m.evaluate("hello world"))

    def test_regex_match(self):
        m = self._m("regex", pattern=r"\d{3}")
        self.assertTrue(m.evaluate("code 123"))
        self.assertFalse(m.evaluate("no digits"))

    def test_regex_case_insensitive(self):
        m = self._m("regex", pattern=r"hello")
        self.assertTrue(m.evaluate("HELLO WORLD"))

    def test_regex_dotall(self):
        m = self._m("regex", pattern=r"start.*end")
        self.assertTrue(m.evaluate("start\nmiddle\nend"))

    def test_starts_with(self):
        m = self._m("starts_with", value="Paris")
        self.assertTrue(m.evaluate("  Paris is great"))
        self.assertFalse(m.evaluate("London is great"))

    def test_length_gt(self):
        m = self._m("length_gt", value="5")
        self.assertTrue(m.evaluate("hello world"))
        self.assertFalse(m.evaluate("hello"))  # exact boundary: 5 is not > 5

    def test_length_lt(self):
        m = self._m("length_lt", value="5")
        self.assertTrue(m.evaluate("hi"))
        self.assertFalse(m.evaluate("hello"))  # exact boundary: 5 is not < 5

    def test_not_contains(self):
        m = self._m("not_contains", value="forbidden")
        self.assertTrue(m.evaluate("clean text"))
        self.assertFalse(m.evaluate("this is forbidden"))

    def test_unknown_type_returns_false(self):
        m = self._m("completely_unknown_type_xyz")
        self.assertFalse(m.evaluate("anything"))

    def test_invert(self):
        m = Matcher({"type":"contains","value":"bad","invert":True,"scores":{}})
        self.assertTrue(m.evaluate("good response"))
        self.assertFalse(m.evaluate("bad response"))


class TestMatcherScoring(unittest.TestCase):

    def test_scores_added_on_match(self):
        m = Matcher({"type":"contains","value":"yes","scores":{"gpt-4o":0.3,"claude":0.2}})
        scores = {}
        m.apply_scores("yes it works", scores)
        self.assertAlmostEqual(scores["gpt-4o"], 0.3)
        self.assertAlmostEqual(scores["claude"],  0.2)

    def test_scores_not_added_on_miss(self):
        m = Matcher({"type":"contains","value":"xyz","scores":{"m":0.5}})
        scores = {}
        m.apply_scores("no match", scores)
        self.assertEqual(scores, {})

    def test_scores_accumulate(self):
        m = Matcher({"type":"contains","value":"a","scores":{"m":0.3}})
        scores = {}
        m.apply_scores("a", scores)
        m.apply_scores("a", scores)
        self.assertAlmostEqual(scores["m"], 0.6)


class TestProbeScoring(unittest.TestCase):

    def _probe(self):
        return Probe({
            "id": "test",
            "messages": [{"role":"user","content":"Count R in strawberry"}],
            "matchers": [
                {"type":"contains","value":"3","scores":{"gpt-4o":0.25,"claude":0.20}},
                {"type":"contains","value":"2","scores":{"gpt-3.5":0.35}},
            ],
        })

    def test_first_matcher(self):
        r = self._probe().score_response("The answer is 3")
        self.assertAlmostEqual(r.get("gpt-4o", 0), 0.25)
        self.assertNotIn("gpt-3.5", r)

    def test_second_matcher(self):
        r = self._probe().score_response("I count 2 Rs")
        self.assertAlmostEqual(r.get("gpt-3.5", 0), 0.35)
        self.assertNotIn("gpt-4o", r)

    def test_no_match(self):
        self.assertEqual(self._probe().score_response("I don't know"), {})

    def test_defaults(self):
        p = Probe({"id":"x","messages":[{"role":"user","content":"hi"}],"matchers":[]})
        self.assertEqual(p.api_format, "openai")
        self.assertEqual(p.tags, [])
        self.assertIsNone(p.system)


class TestPackLoading(unittest.TestCase):

    def setUp(self):
        self.packs = load_all_packs()

    def test_minimum_pack_count(self):
        self.assertGreaterEqual(len(self.packs), 10)

    def test_minimum_probe_count(self):
        total = sum(len(p.probes) for p in self.packs)
        self.assertGreaterEqual(total, 60)

    def test_no_duplicate_ids(self):
        ids = [p.id for pack in self.packs for p in pack.probes]
        dupes = [x for x in ids if ids.count(x) > 1]
        self.assertFalse(dupes, f"Duplicate probe IDs: {set(dupes)}")

    def test_required_probes_present(self):
        ids = {p.id for pack in self.packs for p in pack.probes}
        required = {
            "quirk-strawberry-r",
            "bfp-math-decimal-compare",
            "bfp-claude-ethical-nuance",
            "bfp-gpt4-markdown-eagerness",
        }
        missing = required - ids
        self.assertFalse(missing, f"Missing probes: {missing}")

    def test_all_probes_have_messages(self):
        for pack in self.packs:
            for probe in pack.probes:
                self.assertTrue(probe.messages, f"{probe.id}: no messages")
                for msg in probe.messages:
                    self.assertIn("role",    msg, f"{probe.id}: message missing role")
                    self.assertIn("content", msg, f"{probe.id}: message missing content")

    def test_all_matchers_have_scores(self):
        for pack in self.packs:
            for probe in pack.probes:
                for m in probe.matchers:
                    self.assertIsInstance(m.scores, dict, f"{probe.id}: scores not dict")
                    self.assertGreater(len(m.scores), 0, f"{probe.id}: empty scores")

    def test_nonexistent_dir_returns_builtins(self):
        packs = load_all_packs(Path("/nonexistent/path/xyz"))
        self.assertGreaterEqual(len(packs), 10)

    def test_by_tags(self):
        for pack in self.packs:
            quirk_probes = pack.by_tags(["quirk"])
            for p in quirk_probes:
                self.assertIn("quirk", p.tags)


if __name__ == "__main__":
    unittest.main(verbosity=2)
