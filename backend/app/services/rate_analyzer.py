"""
Commit 49: Rate Analyzer
==========================
Advanced sliding-window rate analytics beyond simple rate limiting.
Computes per-IP request statistics and detects unusual rate patterns.

Tracks:
  - Requests per second / per minute / per hour (rolling)
  - Percentile distribution (p50, p90, p99 inter-arrival times)
  - Burst coefficient (ratio of peak rate to average rate)
  - Idle detection (long gaps between requests)
  - Request regularity score (bot-like vs human-like cadence)
  - Global platform rate statistics
"""

import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from threading import RLock
from typing import Optional

logger = logging.getLogger(__name__)

# ── Config ─────────────────────────────────────────────────────────────────────
WINDOW_SECONDS   = 3600.0    # 1-hour rolling window
BURST_WINDOW     = 5.0       # 5s window for burst detection
MAX_SAMPLES      = 1000      # max timestamps kept per IP


# ── Per-IP stats ───────────────────────────────────────────────────────────────
@dataclass
class IPRateStats:
    ip: str
    req_per_sec: float
    req_per_min: float
    req_per_hour: float
    burst_coefficient: float    # peak_rate / avg_rate
    p50_interval_ms: float      # median inter-request interval
    p90_interval_ms: float
    p99_interval_ms: float
    regularity_score: float     # 0 = random (human), 1 = perfectly regular (bot)
    total_in_window: int
    is_burst: bool
    is_bot_like: bool


@dataclass
class GlobalRateStats:
    total_requests_tracked: int
    unique_ips: int
    global_req_per_sec: float
    global_req_per_min: float
    busiest_ip: Optional[str]
    busiest_ip_rpm: float


class RateAnalyzer:
    """
    Sliding-window rate analyzer for detailed per-IP traffic statistics.
    Runs alongside the simple rate limiter to provide richer analytics.
    """

    def __init__(self, window: float = WINDOW_SECONDS):
        self._timestamps: dict[str, deque] = defaultdict(lambda: deque(maxlen=MAX_SAMPLES))
        self._global_ts: deque = deque(maxlen=10000)
        self._lock = RLock()
        self._window = window
        self._total_tracked = 0
        logger.info("📈 RateAnalyzer initialised (window=%.0fs)", window)

    def record(self, ip: str) -> None:
        """Record a request timestamp for an IP."""
        now = time.time()
        with self._lock:
            self._timestamps[ip].append(now)
            self._global_ts.append(now)
            self._total_tracked += 1

    def _recent(self, ts_list: deque, window: float) -> list[float]:
        now = time.time()
        return [t for t in ts_list if (now - t) <= window]

    def _percentile(self, data: list[float], pct: float) -> float:
        if not data:
            return 0.0
        sorted_data = sorted(data)
        idx = max(0, int(len(sorted_data) * pct / 100) - 1)
        return sorted_data[idx]

    def _compute_intervals(self, timestamps: list[float]) -> list[float]:
        """Compute inter-arrival intervals in milliseconds."""
        if len(timestamps) < 2:
            return []
        sorted_ts = sorted(timestamps)
        return [(sorted_ts[i+1] - sorted_ts[i]) * 1000 for i in range(len(sorted_ts) - 1)]

    def _regularity_score(self, intervals: list[float]) -> float:
        """
        Compute how regular the inter-arrival times are.
        A perfectly regular (bot) pattern = 1.0
        A random (human) pattern = 0.0
        Uses coefficient of variation (stdev/mean).
        """
        if len(intervals) < 3:
            return 0.0
        mean = sum(intervals) / len(intervals)
        if mean == 0:
            return 1.0
        variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
        stdev = variance ** 0.5
        cv = stdev / mean   # Coefficient of variation
        # Low CV = regular = bot-like; High CV = irregular = human-like
        return round(max(0.0, 1.0 - min(cv, 1.0)), 3)

    def get_ip_stats(self, ip: str) -> Optional[IPRateStats]:
        """Compute rate analytics for a single IP."""
        with self._lock:
            ts_deque = self._timestamps.get(ip)
            if ts_deque is None:
                return None
            all_ts = list(ts_deque)

        now = time.time()
        in_window = [t for t in all_ts if (now - t) <= self._window]
        in_minute = [t for t in all_ts if (now - t) <= 60.0]
        in_second = [t for t in all_ts if (now - t) <= 1.0]
        in_burst  = [t for t in all_ts if (now - t) <= BURST_WINDOW]

        intervals = self._compute_intervals(in_window[-100:])

        req_per_sec = len(in_second)
        req_per_min = len(in_minute)
        req_per_hour = len(in_window)

        avg_rate = req_per_min / 60.0 if req_per_min > 0 else 0.0
        burst_rate = len(in_burst) / BURST_WINDOW
        burst_coeff = round(burst_rate / max(avg_rate, 0.001), 2)

        reg_score = self._regularity_score(intervals)

        return IPRateStats(
            ip=ip,
            req_per_sec=round(req_per_sec, 2),
            req_per_min=round(req_per_min, 2),
            req_per_hour=round(req_per_hour, 2),
            burst_coefficient=burst_coeff,
            p50_interval_ms=round(self._percentile(intervals, 50), 1),
            p90_interval_ms=round(self._percentile(intervals, 90), 1),
            p99_interval_ms=round(self._percentile(intervals, 99), 1),
            regularity_score=reg_score,
            total_in_window=req_per_hour,
            is_burst=burst_coeff > 5.0,
            is_bot_like=reg_score > 0.8 and req_per_min > 10,
        )

    def get_global_stats(self) -> GlobalRateStats:
        """Compute platform-wide rate statistics."""
        now = time.time()
        with self._lock:
            global_minute = [t for t in self._global_ts if (now - t) <= 60.0]
            global_second = [t for t in self._global_ts if (now - t) <= 1.0]
            all_ips = list(self._timestamps.keys())
            unique_ips = len(all_ips)

        # Find busiest IP
        busiest_ip = None
        busiest_rpm = 0.0
        for ip_str in all_ips:
            stats = self.get_ip_stats(ip_str)
            if stats and stats.req_per_min > busiest_rpm:
                busiest_rpm = stats.req_per_min
                busiest_ip = ip_str

        return GlobalRateStats(
            total_requests_tracked=self._total_tracked,
            unique_ips=unique_ips,
            global_req_per_sec=round(len(global_second), 2),
            global_req_per_min=round(len(global_minute), 2),
            busiest_ip=busiest_ip,
            busiest_ip_rpm=round(busiest_rpm, 2),
        )

    def get_bot_like_ips(self, limit: int = 20) -> list[dict]:
        """Return IPs with bot-like regular request patterns."""
        with self._lock:
            all_ips = list(self._timestamps.keys())
        results = []
        for ip_str in all_ips:
            stats = self.get_ip_stats(ip_str)
            if stats and stats.is_bot_like:
                results.append({
                    "ip": ip_str,
                    "regularity_score": stats.regularity_score,
                    "req_per_min": stats.req_per_min,
                    "p50_interval_ms": stats.p50_interval_ms,
                })
        return sorted(results, key=lambda x: x["regularity_score"], reverse=True)[:limit]

    def get_stats(self) -> dict:
        gs = self.get_global_stats()
        return {
            "total_tracked": self._total_tracked,
            "unique_ips": gs.unique_ips,
            "global_req_per_sec": gs.global_req_per_sec,
            "global_req_per_min": gs.global_req_per_min,
            "busiest_ip": gs.busiest_ip,
        }


# ── Singleton ──────────────────────────────────────────────────────────────────
rate_analyzer = RateAnalyzer()
