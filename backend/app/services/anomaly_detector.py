"""
Commit 28: Anomaly Detector
============================
Detects unusual behavioural patterns in incoming requests beyond
what static regex rules can catch. Operates on per-IP request history
stored in a rolling time window.

Detection signals:
  1. Velocity spike   — too many requests per minute from one IP
  2. Burst detection  — N requests within a very short window (e.g. 5 req/2s)
  3. Threat ratio     — IP sends > X% threatening prompts
  4. Prompt similarity — identical or near-identical prompts in quick succession
  5. Payload cycling  — rapid variation in prompt length (evasion attempt)
"""

import hashlib
import logging
import time
import unicodedata
from collections import defaultdict, deque
from dataclasses import dataclass, field
from threading import RLock
from typing import Optional

logger = logging.getLogger(__name__)


# ── Signals & Results ──────────────────────────────────────────────────────────

@dataclass
class AnomalySignal:
    signal: str
    detail: str
    score: float          # 0.0 – 1.0, higher = more suspicious


@dataclass
class AnomalyResult:
    is_anomalous: bool
    signals: list[AnomalySignal] = field(default_factory=list)
    risk_score: float = 0.0

    @property
    def top_signal(self) -> str:
        if not self.signals:
            return "none"
        return max(self.signals, key=lambda s: s.score).signal


# ── Per-IP history entry ────────────────────────────────────────────────────────

@dataclass
class _Request:
    timestamp: float
    prompt_hash: str
    prompt_length: int
    is_threat: bool


# ── Anomaly Detector ────────────────────────────────────────────────────────────

class AnomalyDetector:
    """
    Tracks recent requests per IP and raises anomaly flags when
    behavioural patterns suggest coordinated or automated abuse.
    """

    def __init__(
        self,
        window_seconds: float = 60.0,
        velocity_threshold: int = 30,
        burst_threshold: int = 5,
        burst_window: float = 2.0,
        threat_ratio_threshold: float = 0.7,
        similarity_window: float = 10.0,
        anomaly_score_cutoff: float = 0.5,
    ):
        self._window = window_seconds
        self._velocity_limit = velocity_threshold
        self._burst_limit = burst_threshold
        self._burst_window = burst_window
        self._threat_ratio = threat_ratio_threshold
        self._similarity_window = similarity_window
        self._cutoff = anomaly_score_cutoff

        # ip -> deque of _Request (most recent at right)
        self._history: dict[str, deque[_Request]] = defaultdict(
            lambda: deque(maxlen=500)
        )
        self._lock = RLock()
        self._total_checked = 0
        self._total_anomalies = 0
        logger.info("🔭 AnomalyDetector initialised")

    # ── Private helpers ────────────────────────────────────────────────────────

    def _prompt_hash(self, prompt: str) -> str:
        norm = unicodedata.normalize("NFKC", prompt).lower().strip()
        return hashlib.md5(" ".join(norm.split()).encode()).hexdigest()

    def _prune(self, ip: str, now: float) -> None:
        dq = self._history[ip]
        while dq and (now - dq[0].timestamp) > self._window:
            dq.popleft()

    def _recent(self, ip: str, now: float, secs: float) -> list[_Request]:
        return [r for r in self._history[ip] if (now - r.timestamp) <= secs]

    # ── Public API ─────────────────────────────────────────────────────────────

    def record(self, ip: str, prompt: str, is_threat: bool) -> None:
        """Record a completed request for later anomaly analysis."""
        now = time.time()
        entry = _Request(
            timestamp=now,
            prompt_hash=self._prompt_hash(prompt),
            prompt_length=len(prompt),
            is_threat=is_threat,
        )
        with self._lock:
            self._history[ip].append(entry)
            self._prune(ip, now)

    def check(self, ip: str, prompt: str) -> AnomalyResult:
        """
        Analyse the current state FOR `ip` and return an AnomalyResult.
        Call this BEFORE recording the new request.
        """
        now = time.time()
        signals: list[AnomalySignal] = []

        with self._lock:
            self._prune(ip, now)
            self._total_checked += 1
            window_reqs = list(self._history[ip])

            # ── Signal 1: Velocity spike ───────────────────────────────────────
            if len(window_reqs) >= self._velocity_limit:
                ratio = len(window_reqs) / self._velocity_limit
                score = float(min(ratio - 1.0, 1.0))
                signals.append(AnomalySignal(
                    signal="velocity_spike",
                    detail=f"{len(window_reqs)} req in {self._window:.0f}s (limit {self._velocity_limit})",
                    score=score,
                ))

            # ── Signal 2: Burst detection ──────────────────────────────────────
            burst_reqs = self._recent(ip, now, self._burst_window)
            if len(burst_reqs) >= self._burst_limit:
                score = float(min(len(burst_reqs) / self._burst_limit, 1.0))
                signals.append(AnomalySignal(
                    signal="burst",
                    detail=f"{len(burst_reqs)} req in {self._burst_window:.1f}s",
                    score=score,
                ))

            # ── Signal 3: High threat ratio ────────────────────────────────────
            if len(window_reqs) >= 5:
                threat_count = sum(1 for r in window_reqs if r.is_threat)
                ratio = threat_count / len(window_reqs)
                if ratio >= self._threat_ratio:
                    signals.append(AnomalySignal(
                        signal="high_threat_ratio",
                        detail=f"{threat_count}/{len(window_reqs)} = {ratio:.0%} threats",
                        score=min(ratio, 1.0),
                    ))

            # ── Signal 4: Prompt repetition ────────────────────────────────────
            current_hash = self._prompt_hash(prompt)
            similar_reqs = self._recent(ip, now, self._similarity_window)
            repeat_count = sum(1 for r in similar_reqs if r.prompt_hash == current_hash)
            if repeat_count >= 3:
                score = float(min(repeat_count / 5.0, 1.0))
                signals.append(AnomalySignal(
                    signal="prompt_repetition",
                    detail=f"Same prompt seen {repeat_count}x in {self._similarity_window:.0f}s",
                    score=score,
                ))

            # ── Signal 5: Payload length cycling ──────────────────────────────
            if len(window_reqs) >= 6:
                lengths = [r.prompt_length for r in window_reqs[-6:]]
                variance = max(lengths) - min(lengths)
                if variance > 2000:
                    score = float(min(variance / 4000, 1.0))
                    signals.append(AnomalySignal(
                        signal="payload_cycling",
                        detail=f"Prompt length variance {variance} chars over last 6 requests",
                        score=score,
                    ))

        aggregate = sum(s.score for s in signals) / max(len(signals), 1) if signals else 0.0
        is_anomalous = aggregate >= self._cutoff

        if is_anomalous:
            self._total_anomalies += 1
            logger.warning(
                "⚠️  Anomaly detected — ip=%s  score=%.2f  signals=%s",
                ip, aggregate, [s.signal for s in signals]
            )

        return AnomalyResult(
            is_anomalous=is_anomalous,
            signals=signals,
            risk_score=float(round(aggregate, 3)),
        )

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "total_ips_tracked": len(self._history),
                "total_checked": self._total_checked,
                "total_anomalies": self._total_anomalies,
                "anomaly_rate_pct": round(
                    self._total_anomalies / max(self._total_checked, 1) * 100, 1
                ),
            }

    def clear_ip(self, ip: str) -> int:
        """Clear history for a specific IP. Returns entries removed."""
        with self._lock:
            count = len(self._history.get(ip, []))
            self._history.pop(ip, None)
            return count


# ── Singleton ──────────────────────────────────────────────────────────────────
anomaly_detector = AnomalyDetector()
