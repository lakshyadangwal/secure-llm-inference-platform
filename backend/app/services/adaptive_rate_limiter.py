"""
Commit 68: Adaptive Rate Limiter
====================================
A smart rate limiter that adjusts its thresholds dynamically based on
each IP's current threat score. Clean IPs get generous limits;
suspicious or flagged IPs are progressively throttled.

Tiers (based on threat_score 0.0 – 1.0):
  CLEAN       (0.0 – 0.19): 60 rpm  / 2000 rpd
  SUSPICIOUS  (0.2 – 0.39): 30 rpm  / 1000 rpd
  ELEVATED    (0.4 – 0.59): 15 rpm  / 400  rpd
  HIGH        (0.6 – 0.79): 5  rpm  / 100  rpd
  CRITICAL    (0.8 – 1.0 ): 1  rpm  / 20   rpd  (near-block)

Also supports:
  - Per-endpoint multipliers (e.g., /chat gets 0.5x, /health gets 10x)
  - Global platform-wide circuit breaker (auto-engages at traffic spikes)
  - Trusted IP bypass list
"""

import logging
import time
from collections import deque
from dataclasses import dataclass, field
from threading import RLock
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class RateTier:
    name: str
    min_score: float
    max_score: float
    max_rpm: int          # requests per minute
    max_rpd: int          # requests per day
    max_burst: int        # max requests in any 5-second window


_TIERS: list[RateTier] = [
    RateTier("clean",      0.00, 0.19, 60,  2000, 10),
    RateTier("suspicious", 0.20, 0.39, 30,  1000, 6),
    RateTier("elevated",   0.40, 0.59, 15,  400,  3),
    RateTier("high",       0.60, 0.79, 5,   100,  2),
    RateTier("critical",   0.80, 1.00, 1,   20,   1),
]

# Per-endpoint rpm multipliers
_ENDPOINT_MULTIPLIERS: dict[str, float] = {
    "/api/v1/chat":       0.5,
    "/api/v1/query":      0.5,
    "/api/v1/analyze":    0.7,
    "/api/intel/":        0.8,
    "/api/v1/health":     5.0,
    "/api/v1/stats":      2.0,
    "/api/v1/diagnose":   1.5,
}


def _get_tier(threat_score: float) -> RateTier:
    for t in _TIERS:
        if t.min_score <= threat_score <= t.max_score:
            return t
    return _TIERS[-1]


@dataclass
class RateLimitDecision:
    allowed: bool
    tier: str
    rpm_used: int
    rpm_limit: int
    rpd_used: int
    rpd_limit: int
    retry_after_seconds: float
    reason: str

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "tier": self.tier,
            "rpm_used": self.rpm_used,
            "rpm_limit": self.rpm_limit,
            "rpd_used": self.rpd_used,
            "rpd_limit": self.rpd_limit,
            "retry_after_seconds": round(float(self.retry_after_seconds), 1),  # type: ignore[call-overload]
            "reason": self.reason,
        }


@dataclass
class _IPState:
    minute_window: deque  # deque of request timestamps (last 60s)
    day_window: deque     # deque of request timestamps (last 86400s)
    burst_window: deque   # deque of request timestamps (last 5s)
    threat_score: float = 0.0
    last_updated: float = field(default_factory=time.time)


class AdaptiveRateLimiter:
    """
    Adaptive rate limiter — adjusts limits based on IP threat score.
    Supports endpoint-specific multipliers and a global circuit breaker.
    """

    # Global circuit breaker
    _GLOBAL_RPM_LIMIT = 5000          # total platform requests per minute
    _CIRCUIT_BREAKER_THRESHOLD = 0.9  # engage at 90 % of global limit

    def __init__(self, trusted_ips: Optional[list[str]] = None) -> None:
        self._states: dict[str, _IPState] = {}
        self._lock = RLock()
        self._trusted: set[str] = set(trusted_ips or [])
        self._global_window: deque = deque()
        self._circuit_open = False
        self._total_requests = 0
        self._total_throttled = 0
        self._total_blocked = 0
        logger.info("⏱️  AdaptiveRateLimiter initialised — %d tiers, %d endpoint multipliers",
                    len(_TIERS), len(_ENDPOINT_MULTIPLIERS))

    def update_threat_score(self, ip: str, score: float) -> None:
        """Update the threat score for an IP (called by other defense modules)."""
        score = max(0.0, min(1.0, score))
        with self._lock:
            if ip not in self._states:
                self._states[ip] = _IPState(
                    minute_window=deque(),
                    day_window=deque(),
                    burst_window=deque(),
                )
            self._states[ip].threat_score = score
            self._states[ip].last_updated = time.time()

    def check(self, ip: str, endpoint: str = "/") -> RateLimitDecision:
        """
        Check if a request from `ip` to `endpoint` should be allowed.
        """
        with self._lock:
            self._total_requests += 1

        if ip in self._trusted:
            return RateLimitDecision(True, "trusted", 0, 999999, 0, 999999, 0.0, "trusted_ip")

        now = time.time()
        minute_ago = now - 60.0
        day_ago    = now - 86400.0
        five_ago   = now - 5.0

        with self._lock:
            # Global circuit breaker
            while self._global_window and self._global_window[0] < minute_ago:
                self._global_window.popleft()
            self._global_window.append(now)
            global_rpm = len(self._global_window)
            if global_rpm >= self._GLOBAL_RPM_LIMIT * self._CIRCUIT_BREAKER_THRESHOLD:
                if not self._circuit_open:
                    logger.critical("⏱️  Global circuit breaker OPEN — global_rpm=%d", global_rpm)
                    self._circuit_open = True
                self._total_blocked += 1
                return RateLimitDecision(False, "global_circuit_breaker", global_rpm,
                                         self._GLOBAL_RPM_LIMIT, 0, 0, 5.0, "platform_overload")
            else:
                self._circuit_open = False

            # Get or create IP state
            if ip not in self._states:
                self._states[ip] = _IPState(
                    minute_window=deque(),
                    day_window=deque(),
                    burst_window=deque(),
                )
            state = self._states[ip]

            # Prune old entries
            while state.minute_window and state.minute_window[0] < minute_ago:
                state.minute_window.popleft()
            while state.day_window and state.day_window[0] < day_ago:
                state.day_window.popleft()
            while state.burst_window and state.burst_window[0] < five_ago:
                state.burst_window.popleft()

            tier = _get_tier(state.threat_score)

            # Apply endpoint multiplier to rpm
            ep_mult = 1.0
            for prefix, mult in _ENDPOINT_MULTIPLIERS.items():
                if endpoint.startswith(prefix):
                    ep_mult = mult
                    break
            effective_rpm = max(1, int(tier.max_rpm * ep_mult))  # type: ignore[call-overload]

            rpm_used = len(state.minute_window)
            rpd_used = len(state.day_window)
            burst_used = len(state.burst_window)

            # Check burst
            if burst_used >= tier.max_burst:
                self._total_throttled += 1
                return RateLimitDecision(False, tier.name, rpm_used, effective_rpm,
                                          rpd_used, tier.max_rpd, 5.0, "burst_limit_exceeded")
            # Check rpm
            if rpm_used >= effective_rpm:
                retry = 60.0 - (now - float(state.minute_window[0]))  # type: ignore[index]
                self._total_throttled += 1
                return RateLimitDecision(False, tier.name, rpm_used, effective_rpm,
                                          rpd_used, tier.max_rpd, max(1.0, retry), "rpm_limit_exceeded")
            # Check rpd
            if rpd_used >= tier.max_rpd:
                self._total_blocked += 1
                return RateLimitDecision(False, tier.name, rpm_used, effective_rpm,
                                          rpd_used, tier.max_rpd, 3600.0, "daily_quota_exceeded")

            # Allow — record request
            state.minute_window.append(now)
            state.day_window.append(now)
            state.burst_window.append(now)

        return RateLimitDecision(True, tier.name, rpm_used + 1, effective_rpm,
                                  rpd_used + 1, tier.max_rpd, 0.0, "allowed")

    def get_ip_info(self, ip: str) -> Optional[dict]:
        with self._lock:
            state = self._states.get(ip)
            if not state:
                return None
            tier = _get_tier(state.threat_score)
            return {
                "ip": ip,
                "tier": tier.name,
                "threat_score": state.threat_score,
                "rpm_used": len(state.minute_window),
                "rpd_used": len(state.day_window),
                "rpm_limit": tier.max_rpm,
                "rpd_limit": tier.max_rpd,
            }

    def add_trusted_ip(self, ip: str) -> None:
        with self._lock:
            self._trusted.add(ip)

    def remove_trusted_ip(self, ip: str) -> None:
        with self._lock:
            self._trusted.discard(ip)

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "total_requests": self._total_requests,
                "total_throttled": self._total_throttled,
                "total_blocked": self._total_blocked,
                "circuit_breaker_open": self._circuit_open,
                "tracked_ips": len(self._states),
                "trusted_ips": len(self._trusted),
                "tier_count": len(_TIERS),
            }


adaptive_rate_limiter = AdaptiveRateLimiter()
