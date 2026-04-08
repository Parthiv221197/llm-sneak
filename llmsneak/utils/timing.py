"""Timing configuration resolved from -T templates."""
from dataclasses import dataclass
from llmsneak.constants import TIMING_TEMPLATES, TIMING_NAMES


@dataclass
class TimingConfig:
    level:         int
    name:          str
    max_concurrent: int
    delay_ms:      int
    timeout_s:     int

    @classmethod
    def from_level(cls, level: int) -> "TimingConfig":
        level = max(0, min(5, level))
        concurrent, delay, timeout = TIMING_TEMPLATES[level]
        return cls(
            level=level,
            name=TIMING_NAMES[level],
            max_concurrent=concurrent,
            delay_ms=delay,
            timeout_s=timeout,
        )

    @property
    def delay_s(self) -> float:
        return self.delay_ms / 1000.0
