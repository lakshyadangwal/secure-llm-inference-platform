"""
Commit 30: Circuit Breaker for Ollama
======================================
Prevents cascading failures by automatically stopping calls to Ollama
when the error rate or consecutive failure count exceeds thresholds.

States:
  CLOSED  → normal operation, all calls pass through
  OPEN    → Ollama is considered down, calls fail immediately
  HALF_OPEN → probe state: one call allowed through to test recovery

Transitions:
  CLOSED → OPEN       when failures >= failure_threshold
  OPEN   → HALF_OPEN  after reset_timeout_seconds
  HALF_OPEN → CLOSED  if the probe succeeds
  HALF_OPEN → OPEN    if the probe fails
"""

import logging
import time
from dataclasses import dataclass
from enum import Enum
from threading import RLock
from typing import Callable, TypeVar, Optional

logger = logging.getLogger(__name__)

T = TypeVar("T")


# ── State Enum ─────────────────────────────────────────────────────────────────

class CircuitState(str, Enum):
    CLOSED    = "closed"
    OPEN      = "open"
    HALF_OPEN = "half_open"


# ── Exceptions ─────────────────────────────────────────────────────────────────

class CircuitOpenError(RuntimeError):
    """Raised when a call is rejected because the circuit is OPEN."""
    def __init__(self, service: str, opened_at: float):
        age = round(time.time() - opened_at, 1)
        super().__init__(
            f"Circuit breaker for '{service}' is OPEN "
            f"(has been open for {age}s)"
        )


# ── Snapshot ────────────────────────────────────────────────────────────────────

@dataclass
class CircuitSnapshot:
    state: CircuitState
    failure_count: int
    success_count: int
    total_calls: int
    rejected_calls: int
    last_failure_at: Optional[float]
    opened_at: Optional[float]
    half_open_probe_at: Optional[float]


# ── Circuit Breaker ────────────────────────────────────────────────────────────

class CircuitBreaker:
    """
    Generic circuit breaker.

    Usage:
        cb = CircuitBreaker("ollama", failure_threshold=5, reset_timeout=30.0)

        try:
            result = cb.call(lambda: ollama_service.call(prompt))
        except CircuitOpenError:
            return "Service temporarily unavailable"
    """

    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        reset_timeout_seconds: float = 30.0,
        half_open_max_calls: int = 1,
    ):
        self.name = name
        self._failure_threshold = failure_threshold
        self._reset_timeout = reset_timeout_seconds
        self._half_open_max = half_open_max_calls

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._total_calls = 0
        self._rejected_calls = 0
        self._last_failure_at: Optional[float] = None
        self._opened_at: Optional[float] = None
        self._half_open_probe_at: Optional[float] = None
        self._half_open_calls = 0

        self._lock = RLock()
        logger.info(
            "⚡ CircuitBreaker '%s' initialised — threshold=%d  timeout=%.0fs",
            name, failure_threshold, reset_timeout_seconds
        )

    # ── State machine ──────────────────────────────────────────────────────────

    def _try_transition_to_half_open(self, now: float) -> None:
        if (
            self._state == CircuitState.OPEN
            and self._opened_at is not None
            and (now - self._opened_at) >= self._reset_timeout
        ):
            self._state = CircuitState.HALF_OPEN
            self._half_open_calls = 0
            self._half_open_probe_at = now
            logger.info("🟡 Circuit '%s' → HALF_OPEN (probing)", self.name)

    def _on_success(self) -> None:
        self._success_count += 1
        if self._state == CircuitState.HALF_OPEN:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._opened_at = None
            logger.info("🟢 Circuit '%s' → CLOSED (recovered)", self.name)
        elif self._state == CircuitState.CLOSED:
            # Reset failure count on success in closed state
            self._failure_count = max(0, self._failure_count - 1)

    def _on_failure(self, exc: Exception) -> None:
        self._failure_count += 1
        self._last_failure_at = time.time()
        logger.warning(
            "💥 Circuit '%s' failure #%d — %s: %s",
            self.name, self._failure_count, type(exc).__name__, exc
        )
        if self._state == CircuitState.HALF_OPEN:
            # Probe failed — reopen
            self._state = CircuitState.OPEN
            self._opened_at = time.time()
            logger.error("🔴 Circuit '%s' → OPEN (probe failed)", self.name)
        elif (
            self._state == CircuitState.CLOSED
            and self._failure_count >= self._failure_threshold
        ):
            self._state = CircuitState.OPEN
            self._opened_at = time.time()
            logger.error(
                "🔴 Circuit '%s' → OPEN after %d failures",
                self.name, self._failure_count
            )

    # ── Public API ─────────────────────────────────────────────────────────────

    def call(self, fn: Callable[[], T]) -> T:
        """
        Execute `fn` through the circuit breaker.

        Raises:
            CircuitOpenError: If the circuit is OPEN and the reset
                              timeout has not yet elapsed.
        """
        now = time.time()
        with self._lock:
            self._try_transition_to_half_open(now)

            if self._state == CircuitState.OPEN:
                self._rejected_calls += 1
                raise CircuitOpenError(self.name, self._opened_at or now)

            if self._state == CircuitState.HALF_OPEN:
                if self._half_open_calls >= self._half_open_max:
                    self._rejected_calls += 1
                    raise CircuitOpenError(self.name, self._opened_at or now)
                self._half_open_calls += 1

            self._total_calls += 1

        try:
            result = fn()
            with self._lock:
                self._on_success()
            return result
        except Exception as exc:
            with self._lock:
                self._on_failure(exc)
            raise

    def reset(self) -> None:
        """Manually reset the circuit breaker to CLOSED state."""
        with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._opened_at = None
            logger.info("🟢 Circuit '%s' manually reset → CLOSED", self.name)

    def get_snapshot(self) -> CircuitSnapshot:
        with self._lock:
            return CircuitSnapshot(
                state=self._state,
                failure_count=self._failure_count,
                success_count=self._success_count,
                total_calls=self._total_calls,
                rejected_calls=self._rejected_calls,
                last_failure_at=self._last_failure_at,
                opened_at=self._opened_at,
                half_open_probe_at=self._half_open_probe_at,
            )

    def get_stats(self) -> dict:
        s = self.get_snapshot()
        return {
            "name": self.name,
            "state": s.state.value,
            "failure_count": s.failure_count,
            "success_count": s.success_count,
            "total_calls": s.total_calls,
            "rejected_calls": s.rejected_calls,
            "failure_rate_pct": round(
                s.failure_count / max(s.total_calls, 1) * 100, 1
            ),
            "opened_at": s.opened_at,
        }


# ── Singleton for Ollama ───────────────────────────────────────────────────────
ollama_circuit_breaker = CircuitBreaker(
    name="ollama",
    failure_threshold=5,
    reset_timeout_seconds=30.0,
)
