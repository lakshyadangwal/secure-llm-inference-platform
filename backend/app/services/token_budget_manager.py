"""
Commit 55: Token Budget Manager
==================================
Tracks and enforces per-IP and per-session token budgets
to prevent resource exhaustion and quota-abuse attacks.

Features:
  - Per-IP daily token budget (rolling 24-hour window)
  - Per-session token budget within a single session
  - Per-minute burst budget (short-term throttle)
  - Configurable limits with hard cap
  - Automatic budget reset at 24-hour boundary
  - Graceful degradation: warn → throttle → block
  - Statistics per IP: tokens used, refused, avg per request
"""

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from threading import RLock
from typing import Optional

logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────
DAILY_BUDGET_DEFAULT    = 50_000    # tokens/IP/day
SESSION_BUDGET_DEFAULT  = 5_000     # tokens/session
MINUTE_BURST_DEFAULT    = 1_000     # tokens/IP/minute
WARN_AT_FRACTION        = 0.80      # warn when 80% consumed
THROTTLE_AT_FRACTION    = 0.95      # throttle at 95%
DAY_SECONDS             = 86_400.0
MINUTE_SECONDS          = 60.0


# ── Budget decision ────────────────────────────────────────────────────────

class BudgetDecision(str, Enum):
    ALLOW    = "allow"
    WARN     = "warn"        # budget getting low — proceed but notify
    THROTTLE = "throttle"    # budget almost exhausted — add latency signal
    BLOCK    = "block"       # budget exhausted — reject request


# ── IP budget record ───────────────────────────────────────────────────────

@dataclass
class IPBudget:
    ip: str
    daily_used: int = 0
    daily_reset_at: float = field(default_factory=lambda: time.time() + DAY_SECONDS)
    minute_used: int = 0
    minute_reset_at: float = field(default_factory=lambda: time.time() + MINUTE_SECONDS)
    session_used: int = 0
    total_requests: int = 0
    total_tokens_lifetime: int = 0
    total_refused: int = 0

    def reset_daily_if_needed(self) -> None:
        if time.time() >= self.daily_reset_at:
            self.daily_used = 0
            self.daily_reset_at = time.time() + DAY_SECONDS

    def reset_minute_if_needed(self) -> None:
        if time.time() >= self.minute_reset_at:
            self.minute_used = 0
            self.minute_reset_at = time.time() + MINUTE_SECONDS

    @property
    def daily_remaining(self) -> int:
        return max(0, DAILY_BUDGET_DEFAULT - self.daily_used)

    @property
    def minute_remaining(self) -> int:
        return max(0, MINUTE_BURST_DEFAULT - self.minute_used)

    @property
    def avg_tokens_per_request(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return round(float(self.total_tokens_lifetime) / self.total_requests, 1)  # type: ignore[call-overload]

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "daily_used": self.daily_used,
            "daily_remaining": self.daily_remaining,
            "minute_used": self.minute_used,
            "minute_remaining": self.minute_remaining,
            "session_used": self.session_used,
            "total_requests": self.total_requests,
            "total_tokens_lifetime": self.total_tokens_lifetime,
            "avg_tokens_per_request": self.avg_tokens_per_request,
            "total_refused": self.total_refused,
        }


# ── Budget manager ─────────────────────────────────────────────────────────

@dataclass
class BudgetCheckResult:
    decision: BudgetDecision
    reason: str
    daily_used: int
    daily_remaining: int
    minute_remaining: int
    fraction_used: float

    @property
    def is_allowed(self) -> bool:
        return self.decision in (BudgetDecision.ALLOW, BudgetDecision.WARN)

    def to_dict(self) -> dict:
        return {
            "decision": self.decision.value,
            "reason": self.reason,
            "daily_used": self.daily_used,
            "daily_remaining": self.daily_remaining,
            "minute_remaining": self.minute_remaining,
            "fraction_used": round(float(self.fraction_used), 3),  # type: ignore[call-overload]
        }


class TokenBudgetManager:
    """
    Per-IP token budget enforcement to prevent resource exhaustion.
    """

    def __init__(
        self,
        daily_budget: int = DAILY_BUDGET_DEFAULT,
        session_budget: int = SESSION_BUDGET_DEFAULT,
        minute_burst: int = MINUTE_BURST_DEFAULT,
    ):
        self._budgets: dict[str, IPBudget] = {}
        self._lock = RLock()
        self._daily_budget = daily_budget
        self._session_budget = session_budget
        self._minute_burst = minute_burst
        self._total_requests = 0
        self._total_tokens = 0
        self._total_blocked = 0
        logger.info(
            "💰 TokenBudgetManager initialised (daily=%d  session=%d  burst=%d/min)",
            daily_budget, session_budget, minute_burst,
        )

    def _get_or_create(self, ip: str) -> IPBudget:
        if ip not in self._budgets:
            self._budgets[ip] = IPBudget(ip=ip)
        budget = self._budgets[ip]
        budget.reset_daily_if_needed()
        budget.reset_minute_if_needed()
        return budget

    def check(self, ip: str, estimated_tokens: int) -> BudgetCheckResult:
        """
        Check if a request with `estimated_tokens` can proceed for `ip`.
        This does NOT consume budget — call consume() after request completes.

        Args:
            ip:               Client IP address.
            estimated_tokens: Estimated prompt + response tokens.

        Returns:
            BudgetCheckResult with decision.
        """
        with self._lock:
            budget = self._get_or_create(ip)

            # Minute burst check
            if budget.minute_used + estimated_tokens > self._minute_burst:
                budget.total_refused += 1
                self._total_blocked += 1
                return BudgetCheckResult(
                    decision=BudgetDecision.BLOCK,
                    reason="minute_burst_exhausted",
                    daily_used=budget.daily_used,
                    daily_remaining=budget.daily_remaining,
                    minute_remaining=budget.minute_remaining,
                    fraction_used=budget.daily_used / max(self._daily_budget, 1),
                )

            # Daily budget check
            if budget.daily_used + estimated_tokens > self._daily_budget:
                budget.total_refused += 1
                self._total_blocked += 1
                return BudgetCheckResult(
                    decision=BudgetDecision.BLOCK,
                    reason="daily_budget_exhausted",
                    daily_used=budget.daily_used,
                    daily_remaining=budget.daily_remaining,
                    minute_remaining=budget.minute_remaining,
                    fraction_used=1.0,
                )

            # Session budget check
            if budget.session_used + estimated_tokens > self._session_budget:
                budget.total_refused += 1
                self._total_blocked += 1
                return BudgetCheckResult(
                    decision=BudgetDecision.BLOCK,
                    reason="session_budget_exhausted",
                    daily_used=budget.daily_used,
                    daily_remaining=budget.daily_remaining,
                    minute_remaining=budget.minute_remaining,
                    fraction_used=budget.daily_used / max(self._daily_budget, 1),
                )

            fraction = (budget.daily_used + estimated_tokens) / max(self._daily_budget, 1)

            if fraction >= THROTTLE_AT_FRACTION:
                decision = BudgetDecision.THROTTLE
                reason = "budget_nearly_exhausted"
            elif fraction >= WARN_AT_FRACTION:
                decision = BudgetDecision.WARN
                reason = "budget_high_usage"
            else:
                decision = BudgetDecision.ALLOW
                reason = "ok"

            return BudgetCheckResult(
                decision=decision,
                reason=reason,
                daily_used=budget.daily_used,
                daily_remaining=budget.daily_remaining,
                minute_remaining=budget.minute_remaining,
                fraction_used=fraction,
            )

    def consume(self, ip: str, actual_tokens: int) -> None:
        """Record actual token consumption after a request completes."""
        with self._lock:
            budget = self._get_or_create(ip)
            budget.daily_used += actual_tokens
            budget.minute_used += actual_tokens
            budget.session_used += actual_tokens
            budget.total_requests += 1
            budget.total_tokens_lifetime += actual_tokens
            self._total_requests += 1
            self._total_tokens += actual_tokens

    def reset_session(self, ip: str) -> None:
        """Reset session budget for an IP (call on new session start)."""
        with self._lock:
            if ip in self._budgets:
                self._budgets[ip].session_used = 0

    def get_budget(self, ip: str) -> Optional[dict]:
        """Get current budget state for an IP."""
        with self._lock:
            if ip not in self._budgets:
                return None
            return self._budgets[ip].to_dict()

    def get_top_consumers(self, limit: int = 20) -> list[dict]:
        """Return IPs sorted by lifetime token consumption."""
        with self._lock:
            records = list(self._budgets.values())
        records.sort(key=lambda r: r.total_tokens_lifetime, reverse=True)
        top = list(records)[:limit]  # type: ignore[index]
        return [r.to_dict() for r in top]

    def get_stats(self) -> dict:
        with self._lock:
            blocked_ips = sum(
                1 for b in self._budgets.values()
                if b.daily_used >= self._daily_budget
            )
            return {
                "total_requests": self._total_requests,
                "total_tokens_consumed": self._total_tokens,
                "total_blocked_requests": self._total_blocked,
                "active_ips": len(self._budgets),
                "budget_exhausted_ips": blocked_ips,
                "daily_budget": self._daily_budget,
                "session_budget": self._session_budget,
                "minute_burst": self._minute_burst,
            }


# ── Singleton ──────────────────────────────────────────────────────────────────
token_budget_manager = TokenBudgetManager()
