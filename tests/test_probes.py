"""
Unit tests for llmsneak.probes.loader
Tests every matcher type, scoring, pack loading, and edge cases.
No external dependencies required.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from llmsneak.probes.loader import Matcher, Probe, ProbePack, load_all_packs


# ── Matcher tests ─────────────────────────────────────────────────────────────

class TestMatcherContains:
    def test_match(self):
        m = Matcher({"type": "contains", "value": "hello", "scores": {}})
        assert m.evaluate("Hello World") is True     # case-insensitive

    def test_no_match(self):
        m = Matcher({"type": "contains", "value": "xyz", "scores": {}})
        assert m.evaluate("Hello World") is False

    def test_case_insensitive(self):
        m = Matcher({"type": "contains", "value": "HELLO", "scores": {}})
        assert m.evaluate("hello") is True


class TestMatcherContainsAny:
    def test_first_matches(self):
        m = Matcher({"type": "contains_any", "value": ["apple","banana"], "scores": {}})
        assert m.evaluate("I like apple") is True

    def test_second_matches(self):
        m = Matcher({"type": "contains_any", "value": ["apple","banana"], "scores": {}})
        assert m.evaluate("banana split") is True

    def test_none_match(self):
        m = Matcher({"type": "contains_any", "value": ["apple","banana"], "scores": {}})
        assert m.evaluate("orange juice") is False


class TestMatcherRegex:
    def test_match(self):
        m = Matcher({"type": "regex", "pattern": r"\d{3}", "scores": {}})
        assert m.evaluate("abc 123") is True

    def test_no_match(self):
        m = Matcher({"type": "regex", "pattern": r"\d{3}", "scores": {}})
        assert m.evaluate("abc def") is False

    def test_case_insensitive_flag(self):
        m = Matcher({"type": "regex", "pattern": r"hello", "scores": {}})
        assert m.evaluate("HELLO WORLD") is True

    def test_dotall(self):
        m = Matcher({"type": "regex", "pattern": r"start.*end", "scores": {}})
        assert m.evaluate("start\nmiddle\nend") is True


class TestMatcherStartsWith:
    def test_match(self):
        m = Matcher({"type": "starts_with", "value": "Paris", "scores": {}})
        assert m.evaluate("Paris is the capital") is True

    def test_no_match(self):
        m = Matcher({"type": "starts_with", "value": "London", "scores": {}})
        assert m.evaluate("Paris is the capital") is False

    def test_strips_whitespace(self):
        m = Matcher({"type": "starts_with", "value": "Paris", "scores": {}})
        assert m.evaluate("  Paris is the capital") is True


class TestMatcherLengths:
    def test_length_gt_true(self):
        m = Matcher({"type": "length_gt", "value": "5", "scores": {}})
        assert m.evaluate("hello world") is True

    def test_length_gt_false(self):
        m = Matcher({"type": "length_gt", "value": "100", "scores": {}})
        assert m.evaluate("short") is False

    def test_length_lt_true(self):
        m = Matcher({"type": "length_lt", "value": "100", "scores": {}})
        assert m.evaluate("short text") is True

    def test_length_lt_false(self):
        m = Matcher({"type": "length_lt", "value": "3", "scores": {}})
        assert m.evaluate("hello world") is False


class TestMatcherNotContains:
    def test_match_when_absent(self):
        m = Matcher({"type": "not_contains", "value": "forbidden", "scores": {}})
        assert m.evaluate("clean response") is True

    def test_no_match_when_present(self):
        m = Matcher({"type": "not_contains", "value": "forbidden", "scores": {}})
        assert m.evaluate("this is forbidden content") is False


class TestMatcherInvert:
    def test_invert_true(self):
        m = Matcher({"type": "contains", "value": "bad", "invert": True, "scores": {}})
        assert m.evaluate("good response") is True

    def test_invert_false(self):
        m = Matcher({"type": "contains", "value": "bad", "invert": True, "scores": {}})
        assert m.evaluate("bad response") is False


class TestMatcherScoring:
    def test_scores_added_on_match(self):
        m = Matcher({"type": "contains", "value": "3",
                     "scores": {"gpt-4o": 0.25, "claude-3": 0.20}})
        scores = {}
        m.apply_scores("The answer is 3", scores)
        assert scores.get("gpt-4o")  == 0.25
        assert scores.get("claude-3") == 0.20

    def test_scores_not_added_on_miss(self):
        m = Matcher({"type": "contains", "value": "xyz",
                     "scores": {"model-a": 0.5}})
        scores = {}
        m.apply_scores("no match here", scores)
        assert scores == {}

    def test_scores_accumulate(self):
        m1 = Matcher({"type": "contains", "value": "a", "scores": {"m": 0.3}})
        m2 = Matcher({"type": "contains", "value": "b", "scores": {"m": 0.2}})
        scores = {}
        m1.apply_scores("ab text", scores)
        m2.apply_scores("ab text", scores)
        assert abs(scores["m"] - 0.5) < 1e-9

    def test_unknown_matcher_type_no_crash(self):
        m = Matcher({"type": "unknown_type_xyz", "scores": {"m": 0.5}})
        assert m.evaluate("anything") is False   # returns False, no exception


# ── Probe tests ───────────────────────────────────────────────────────────────

class TestProbe:
    def _make_probe(self):
        return Probe({
            "id": "test-probe",
            "description": "Test probe",
            "messages": [{"role": "user", "content": "How many R's in strawberry?"}],
            "matchers": [
                {"type": "contains", "value": "3",
                 "scores": {"gpt-4o": 0.25, "claude-3": 0.20}},
                {"type": "contains", "value": "2",
                 "scores": {"gpt-3.5": 0.35}},
            ],
            "tags": ["quirk", "counting"],
            "api_format": "openai",
        })

    def test_score_response_match_first(self):
        probe = self._make_probe()
        result = probe.score_response("The answer is 3")
        assert result.get("gpt-4o") == 0.25
        assert result.get("claude-3") == 0.20
        assert "gpt-3.5" not in result

    def test_score_response_match_second(self):
        probe = self._make_probe()
        result = probe.score_response("I count 2 R's")
        assert result.get("gpt-3.5") == 0.35
        assert "gpt-4o" not in result

    def test_score_response_no_match(self):
        probe = self._make_probe()
        result = probe.score_response("I don't know")
        assert result == {}

    def test_score_response_both_match(self):
        probe = self._make_probe()
        # "3 or 2" — both matchers fire
        result = probe.score_response("either 3 or 2 depending on how you count")
        assert "gpt-4o" in result
        assert "gpt-3.5" in result

    def test_defaults(self):
        probe = Probe({
            "id": "minimal",
            "messages": [{"role": "user", "content": "hi"}],
            "matchers": [],
        })
        assert probe.api_format == "openai"
        assert probe.tags == []
        assert probe.system is None


# ── Pack loading tests ────────────────────────────────────────────────────────

class TestProbePackLoading:
    def test_loads_five_packs(self):
        packs = load_all_packs()
        assert len(packs) == 5, f"Expected 5 packs, got {len(packs)}"

    def test_probe_count(self):
        packs = load_all_packs()
        total = sum(len(p.probes) for p in packs)
        assert total >= 30, f"Expected ≥30 probes, got {total}"

    def test_no_duplicate_ids(self):
        packs = load_all_packs()
        all_ids = [p.id for pack in packs for p in pack.probes]
        assert len(all_ids) == len(set(all_ids)), f"Duplicate probe IDs: {[x for x in all_ids if all_ids.count(x)>1]}"

    def test_known_probes_exist(self):
        packs = load_all_packs()
        all_ids = {p.id for pack in packs for p in pack.probes}
        required = {
            "quirk-strawberry-r",
            "style-ai-self-reference",
            "claude-identity-direct",
            "openai-model-reveal-attempt",
            "gemini-identity",
            "llama-identity",
        }
        missing = required - all_ids
        assert not missing, f"Missing expected probes: {missing}"

    def test_all_probes_have_messages(self):
        packs = load_all_packs()
        for pack in packs:
            for probe in pack.probes:
                assert probe.messages, f"Probe {probe.id} has no messages"
                for msg in probe.messages:
                    assert "role" in msg,    f"Probe {probe.id}: message missing 'role'"
                    assert "content" in msg, f"Probe {probe.id}: message missing 'content'"

    def test_all_matchers_have_scores(self):
        packs = load_all_packs()
        for pack in packs:
            for probe in pack.probes:
                for matcher in probe.matchers:
                    assert isinstance(matcher.scores, dict), \
                        f"Probe {probe.id}: matcher scores not a dict"

    def test_nonexistent_dir_returns_only_builtins(self):
        from pathlib import Path
        packs = load_all_packs(Path("/nonexistent_path_xyz"))
        assert len(packs) == 5   # still loads builtins

    def test_by_tags_filter(self):
        packs = load_all_packs()
        quirk_probes = [p for pack in packs for p in pack.by_tags(["quirk"])]
        assert len(quirk_probes) > 0
        for p in quirk_probes:
            assert "quirk" in p.tags
