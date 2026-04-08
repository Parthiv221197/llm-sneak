"""
Probe pack loader and matcher engine.

Probe packs are YAML files under llmsneak/probes/packs/ or a user-supplied
--probe-dir.  Each pack declares a list of probes with matchers that
accumulate per-model confidence scores.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

import yaml


# ---------------------------------------------------------------------------
# Schema (mirrors YAML structure as Python dataclasses)
# ---------------------------------------------------------------------------

class Matcher:
    """Evaluates a model response against one match rule."""

    def __init__(self, spec: dict):
        self.type:   str        = spec.get("type", "contains")
        self.value:  str        = spec.get("value", "")
        self.pattern: str       = spec.get("pattern", "")
        self.scores: dict[str, float] = spec.get("scores", {})
        self.invert: bool       = spec.get("invert", False)

    def evaluate(self, text: str) -> bool:
        """Return True if text matches this rule."""
        result: bool
        t = self.type

        if t == "contains":
            result = self.value.lower() in text.lower()
        elif t == "contains_any":
            values = self.value if isinstance(self.value, list) else [self.value]
            result = any(v.lower() in text.lower() for v in values)
        elif t == "regex":
            result = bool(re.search(self.pattern, text, re.IGNORECASE | re.DOTALL))
        elif t == "starts_with":
            result = text.strip().lower().startswith(self.value.lower())
        elif t == "length_gt":
            result = len(text) > int(self.value)
        elif t == "length_lt":
            result = len(text) < int(self.value)
        elif t == "not_contains":
            result = self.value.lower() not in text.lower()
        else:
            result = False

        return not result if self.invert else result

    def apply_scores(self, text: str, scores: dict[str, float]) -> None:
        """If matcher fires, add its score deltas to the running scores dict."""
        if self.evaluate(text):
            for model, delta in self.scores.items():
                scores[model] = scores.get(model, 0.0) + delta


class Probe:
    """A single behavioral probe to be sent to the target."""

    def __init__(self, spec: dict):
        self.id:          str            = spec["id"]
        self.description: str            = spec.get("description", "")
        self.messages:    list[dict]     = spec.get("messages", [])
        self.matchers:    list[Matcher]  = [Matcher(m) for m in spec.get("matchers", [])]
        self.tags:        list[str]      = spec.get("tags", [])
        self.api_format:  str            = spec.get("api_format", "openai")
        self.requires_key: bool          = spec.get("requires_key", True)
        self.skip_if_no_key: bool        = spec.get("skip_if_no_key", True)
        self.system:      Optional[str]  = spec.get("system")

    def score_response(self, text: str) -> dict[str, float]:
        """Run all matchers against text; return {model: delta} dict."""
        scores: dict[str, float] = {}
        for m in self.matchers:
            m.apply_scores(text, scores)
        return scores


class ProbePack:
    """A loaded probe pack (one YAML file)."""

    def __init__(self, spec: dict):
        self.name:        str         = spec.get("name", "unnamed")
        self.provider:    str         = spec.get("provider", "generic")
        self.version:     str         = spec.get("version", "1.0")
        self.description: str         = spec.get("description", "")
        self.probes:      list[Probe] = [Probe(p) for p in spec.get("probes", [])]

    def by_tags(self, tags: list[str]) -> list[Probe]:
        if not tags:
            return self.probes
        return [p for p in self.probes if any(t in p.tags for t in tags)]


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

BUILTIN_PACKS_DIR = Path(__file__).parent / "packs"


def load_all_packs(extra_dir: Optional[Path] = None) -> list[ProbePack]:
    """Load all probe packs from the builtin directory and optional extra dir."""
    packs: list[ProbePack] = []
    dirs = [BUILTIN_PACKS_DIR]
    if extra_dir:
        dirs.append(Path(extra_dir))

    for d in dirs:
        if not d.exists():
            continue
        for yaml_file in sorted(d.glob("*.yaml")):
            try:
                raw = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
                if raw and "probes" in raw:
                    packs.append(ProbePack(raw))
            except Exception as e:
                print(f"[warn] Failed to load probe pack {yaml_file.name}: {e}")

    return packs


def list_packs(extra_dir: Optional[Path] = None) -> list[dict[str, Any]]:
    """Return summary info for all available probe packs."""
    return [
        {
            "name":     p.name,
            "provider": p.provider,
            "probes":   len(p.probes),
            "version":  p.version,
        }
        for p in load_all_packs(extra_dir)
    ]
