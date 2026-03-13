"""
Commit 79: Request Anomaly Detector
======================================
Statistical anomaly detection for request patterns.
Detects deviations from a learned baseline using:
  1. Request rate anomalies      (sudden spike above rolling average)
  2. Payload size anomalies      (very large or very small prompts)
  3. Time-of-day anomalies       (requests at unusual hours for this IP)
  4. Similarity anomalies        (nearly identical prompts in rapid succession)
  5. Character distribution      (non-ASCII spike, invisible chars)
  6. Punctuation density         (injection attempts often have unusual punct)
  7. Response-to-request size    (very short responses → possible refusals)

Uses exponentially weighted moving average (EWMA) for baselines.
No external dependencies — pure Python statistics.
"""

import logging
import math
import time
from collections import deque
from dataclasses import dataclass, field
from threading import RLock
from typing import Optional

logger = logging.getLogger(__name__)

EWMA_ALPHA         = 0.2
MIN_SAMPLES        = 10
SPIKE_THRESHOLD    = 3.0
SIZE_Z_THRESHOLD   = 3.0
MIN_ASCII_FRACTION = 0.70
SIMILARITY_WINDOW  = 5


def _simple_hash(text: str) -> int:
    h = 0
    for ch in text:
        h = (h * 31 + ord(ch)) & 0xFFFFFFFF
    return h


def _char_ngrams(text: str, n: int = 3) -> set[str]:
    t = text.lower()
    return {t[i:i+n] for i in range(len(t) - n + 1)}  # type: ignore[index]


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return float(inter) / float(union) if union else 0.0


@dataclass
class _EWMA:
    mean: float = 0.0
    variance: float = 1.0
    count: int = 0

    def update(self, value: float) -> None:
        self.count += 1
        if self.count == 1:
            self.mean = value
            return
        delta = float(value - self.mean)
        self.mean = float(self.mean + EWMA_ALPHA * delta)  # type: ignore[operator]
        self.variance = float((1 - EWMA_ALPHA) * (self.variance + EWMA_ALPHA * delta * delta))  # type: ignore[operator]

    def z_score(self, value: float) -> float:
        std = math.sqrt(max(self.variance, 1e-6))
        return float(abs(value - self.mean) / std)


@dataclass
class _IPProfile:
    rate_ewma: _EWMA
    size_ewma: _EWMA
    request_times: deque
    prompt_hashes: deque
    prompt_ngrams: deque
    day_requests: dict[int, int]


@dataclass
class AnomalyFlag:
    anomaly_type: str
    score: float
    detail: str


@dataclass
class AnomalyResult:
    flags: list[AnomalyFlag]
    aggregate_score: float
    is_anomalous: bool
    details: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "is_anomalous": self.is_anomalous,
            "aggregate_score": round(float(self.aggregate_score), 3),  # type: ignore[call-overload]
            "flag_count": len(self.flags),
            "flags": [
                {"type": f.anomaly_type, "score": round(float(f.score), 3), "detail": f.detail}  # type: ignore[call-overload]
                for f in self.flags
            ],
        }


class RequestAnomalyDetector:
    """EWMA-based statistical anomaly detector for per-IP request patterns."""

    ANOMALY_THRESHOLD = 0.35

    def __init__(self) -> None:
        self._profiles: dict[str, _IPProfile] = {}
        self._lock = RLock()
        self._total_analyzed = 0
        self._anomalies_detected = 0
        self._type_counts: dict[str, int] = {}
        logger.info("📊 RequestAnomalyDetector ready — alpha=%.2f min_samples=%d",
                    EWMA_ALPHA, MIN_SAMPLES)

    def _get_profile(self, ip: str) -> _IPProfile:
        if ip not in self._profiles:
            self._profiles[ip] = _IPProfile(
                rate_ewma=_EWMA(),
                size_ewma=_EWMA(),
                request_times=deque(maxlen=200),
                prompt_hashes=deque(maxlen=SIMILARITY_WINDOW),
                prompt_ngrams=deque(maxlen=SIMILARITY_WINDOW),
                day_requests={},
            )
        return self._profiles[ip]

    def analyze(self, ip: str, prompt: str, response_length: Optional[int] = None) -> AnomalyResult:
        with self._lock:
            self._total_analyzed += 1
            profile = self._get_profile(ip)
            now = time.time()
            flags: list[AnomalyFlag] = []

            # 1. Rate anomaly
            cutoff = now - 60.0
            while profile.request_times and profile.request_times[0] < cutoff:
                profile.request_times.popleft()
            profile.request_times.append(now)
            rpm = float(len(profile.request_times))
            profile.rate_ewma.update(rpm)
            if profile.rate_ewma.count > MIN_SAMPLES:
                z = profile.rate_ewma.z_score(rpm)
                if z > SPIKE_THRESHOLD:
                    flags.append(AnomalyFlag("rate_spike", min(1.0, float(z / 10.0)), f"rpm={rpm:.0f} z={z:.1f}"))

            # 2. Payload size anomaly
            plen = float(len(prompt))
            profile.size_ewma.update(plen)
            if profile.size_ewma.count > MIN_SAMPLES:
                z = profile.size_ewma.z_score(plen)
                if z > SIZE_Z_THRESHOLD:
                    flags.append(AnomalyFlag("size_anomaly", min(1.0, float(z / 10.0)), f"len={plen:.0f} z={z:.1f}"))

            # 3. Time-of-day anomaly
            hour = int(time.localtime(now).tm_hour)
            profile.day_requests[hour] = profile.day_requests.get(hour, 0) + 1
            total_req = sum(profile.day_requests.values())
            if total_req >= MIN_SAMPLES:
                usual = sorted(profile.day_requests, key=lambda h: profile.day_requests[h], reverse=True)[:8]  # type: ignore[index]
                if hour not in usual:
                    flags.append(AnomalyFlag("unusual_hour", 0.2, f"hour={hour}"))

            # 4. Similarity anomaly
            ngrams = _char_ngrams(prompt[:500], n=3)  # type: ignore[index]
            ph = _simple_hash(prompt)
            if profile.prompt_hashes:
                if ph in profile.prompt_hashes:
                    flags.append(AnomalyFlag("exact_duplicate", 0.8, "identical to recent prompt"))
                else:
                    sim = max((_jaccard(ngrams, g) for g in profile.prompt_ngrams), default=0.0)
                    if sim >= 0.85:
                        flags.append(AnomalyFlag("near_duplicate", 0.6, f"similarity={sim:.2f}"))
            profile.prompt_hashes.append(ph)
            profile.prompt_ngrams.append(ngrams)

            # 5. Non-ASCII spike
            if len(prompt) > 20:
                ascii_count = sum(1 for c in prompt if ord(c) < 128)
                ascii_frac = float(ascii_count) / float(len(prompt))
                if ascii_frac < MIN_ASCII_FRACTION:
                    flags.append(AnomalyFlag("non_ascii_spike", float(1.0 - ascii_frac), f"ascii_frac={ascii_frac:.2f}"))

            # 6. Punctuation density
            if len(prompt) > 30:
                punct = sum(1 for c in prompt if c in "!@#$%^&*()[]{}|;:,.<>?/\\")
                pd = float(punct) / float(len(prompt))
                if pd > 0.15:
                    flags.append(AnomalyFlag("high_punctuation", min(1.0, pd * 5), f"dens={pd:.2f}"))

            # 7. Response refusal indicator
            if response_length is not None and response_length < 50:
                flags.append(AnomalyFlag("possible_refusal", 0.3, f"resp_len={response_length}"))

        agg: float = 0.0
        for f in flags:
            agg = float(agg + f.score)  # type: ignore[operator]
        agg = min(1.0, agg)
        is_anom = agg >= self.ANOMALY_THRESHOLD
        details = [f"{f.anomaly_type}:{f.detail}" for f in flags]

        with self._lock:
            if is_anom:
                self._anomalies_detected += 1
            for f in flags:
                self._type_counts[f.anomaly_type] = self._type_counts.get(f.anomaly_type, 0) + 1

        if is_anom:
            logger.warning("📊 Anomaly ip=%s score=%.2f flags=%s", ip, agg, [f.anomaly_type for f in flags])

        return AnomalyResult(flags=flags, aggregate_score=agg, is_anomalous=is_anom, details=details)

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "total_analyzed": self._total_analyzed,
                "anomalies_detected": self._anomalies_detected,
                "tracked_ips": len(self._profiles),
                "anomaly_type_counts": dict(self._type_counts),
            }


request_anomaly_detector = RequestAnomalyDetector()
