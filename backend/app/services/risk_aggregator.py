"""
Commit 102: Risk Score Aggregator
=====================================
Combines multiple risk signals from different defense modules into
a single composite risk score using configurable weights.

Formula: weighted average of all provided scores.
Supports an "override" mode where any single score above a hard
threshold forces the composite to be at least that threshold.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class RiskInput:
    name: str
    score: float        # 0.0 – 1.0
    weight: float = 1.0


@dataclass
class AggregatedRisk:
    composite_score: float
    dominant_signal: Optional[str]
    signal_scores: dict[str, float]
    verdict: str   # "allow" | "warn" | "block"

    def to_dict(self) -> dict:
        return {
            "composite_score": round(self.composite_score, 3),
            "dominant_signal": self.dominant_signal,
            "verdict": self.verdict,
            "signal_scores": {k: round(v, 3) for k, v in self.signal_scores.items()},
        }


def aggregate(
    signals: list[RiskInput],
    warn_threshold: float = 0.35,
    block_threshold: float = 0.65,
    hard_override: float = 0.85,
) -> AggregatedRisk:
    if not signals:
        return AggregatedRisk(0.0, None, {}, "allow")

    total_weight = sum(s.weight for s in signals)
    composite = sum(s.score * s.weight for s in signals) / max(total_weight, 1e-9)

    # Hard override: any single score above threshold floors the composite
    max_signal = max(signals, key=lambda s: s.score)
    if max_signal.score >= hard_override:
        composite = max(composite, max_signal.score * 0.9)

    composite = min(1.0, composite)
    dominant = max_signal.name if max_signal.score > 0.1 else None

    if composite >= block_threshold:
        verdict = "block"
    elif composite >= warn_threshold:
        verdict = "warn"
    else:
        verdict = "allow"

    return AggregatedRisk(
        composite_score=float(composite),
        dominant_signal=dominant,
        signal_scores={s.name: s.score for s in signals},
        verdict=verdict,
    )
