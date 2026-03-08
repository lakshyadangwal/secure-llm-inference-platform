"""
Commit 81: Service Circuit Breaker
=====================================
Generic circuit breaker implementation for protecting downstream service calls
(LLM API, database, vector stores, external APIs) from cascading failures.

States:
  CLOSED  — normal operation; calls pass through
  OPEN    — too many failures; calls fail fast for a cooldown period
  HALF_OPEN — testing recovery; limited calls allowed through

Per-service configuration:
  - failure_threshold   : how many consecutive failures open the circuit
  - success_threshold   : how many successes in HALF_OPEN to close it
  - timeout_seconds     : how long the circuit stays OPEN before testing
  - max_half_open_calls : max concurrent calls allowed in HALF_OPEN

Supports:
  - Named circuits (one per downstream service)
  - Manual open/force-close for admin control
  - Event hooks (on_open, on_close, on_half_open callbacks)
  - Sliding window failure rate mode (alternative to consecutive count)
"""

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from threading import RLock
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


class CircuitState(str, Enum):
    CLOSED    = "closed"
    OPEN      = "open"
    HALF_OPEN = "half_open"


@dataclass
class CircuitConfig:
    failure_threshold:    int   = 5       # consecutive failures to open
    success_threshold:    int   = 2       # successes in HALF_OPEN to close
    timeout_seconds:      float = 30.0    # OPEN cooldown before HALF_OPEN
    max_half_open_calls:  int   = 3       # concurrent probes in HALF_OPEN
    window_size:          int   = 20      # sliding window size for failure rate
    failure_rate_open:    float = 0.6     # failure rate above which OPEN (window mode)
    use_sliding_window:   bool  = False


@dataclass
class CircuitMetrics:
    total_calls:      int = 0
    successful_calls: int = 0
    failed_calls:     int = 0
    rejected_calls:   int = 0   # fast-failed because OPEN
    times_opened:     int = 0
    times_closed:     int = 0


class CircuitOpenError(Exception):
    """Raised when a call is rejected due to an open circuit."""
    pass


class _CircuitInstance:
    def __init__(self, name: str, config: CircuitConfig) -> None:
        self.name = name
        self.config = config
        self.state = CircuitState.CLOSED
        self.consecutive_failures = 0
        self.consecutive_successes = 0
        self.opened_at: Optional[float] = None
        self.half_open_calls = 0
        self.recent_outcomes: list[bool] = []  # True=success / False=failure (window mode)
        self.metrics = CircuitMetrics()
        self._on_open:      Optional[Callable[[str], None]] = None
        self._on_close:     Optional[Callable[[str], None]] = None
        self._on_half_open: Optional[Callable[[str], None]] = None
        self._lock = RLock()

    def set_hooks(
        self,
        on_open: Optional[Callable[[str], None]] = None,
        on_close: Optional[Callable[[str], None]] = None,
        on_half_open: Optional[Callable[[str], None]] = None,
    ) -> None:
        self._on_open = on_open
        self._on_close = on_close
        self._on_half_open = on_half_open

    def allow_request(self) -> bool:
        """Return True if a request should be allowed through."""
        with self._lock:
            if self.state == CircuitState.CLOSED:
                return True
            if self.state == CircuitState.OPEN:
                elapsed = time.time() - (self.opened_at or 0.0)
                if elapsed >= self.config.timeout_seconds:
                    self._transition(CircuitState.HALF_OPEN)
                    self.half_open_calls = 0
                    return True
                return False
            # HALF_OPEN
            if self.half_open_calls < self.config.max_half_open_calls:
                self.half_open_calls += 1
                return True
            return False

    def record_success(self) -> None:
        with self._lock:
            self.metrics.total_calls += 1
            self.metrics.successful_calls += 1
            self.consecutive_failures = 0
            if self.config.use_sliding_window:
                self._push_outcome(True)
            if self.state == CircuitState.HALF_OPEN:
                self.consecutive_successes += 1
                if self.consecutive_successes >= self.config.success_threshold:
                    self._transition(CircuitState.CLOSED)

    def record_failure(self) -> None:
        with self._lock:
            self.metrics.total_calls += 1
            self.metrics.failed_calls += 1
            self.consecutive_successes = 0
            if self.config.use_sliding_window:
                self._push_outcome(False)
                fail_rate = self._failure_rate()
                if fail_rate >= self.config.failure_rate_open:
                    self._transition(CircuitState.OPEN)
            else:
                self.consecutive_failures += 1
                if self.consecutive_failures >= self.config.failure_threshold:
                    self._transition(CircuitState.OPEN)
            if self.state == CircuitState.HALF_OPEN:
                self._transition(CircuitState.OPEN)

    def record_rejected(self) -> None:
        with self._lock:
            self.metrics.rejected_calls += 1

    def force_open(self) -> None:
        with self._lock:
            self._transition(CircuitState.OPEN)

    def force_close(self) -> None:
        with self._lock:
            self._transition(CircuitState.CLOSED)
            self.consecutive_failures = 0

    def get_status(self) -> dict:
        with self._lock:
            return {
                "name": self.name,
                "state": self.state.value,
                "consecutive_failures": self.consecutive_failures,
                "consecutive_successes": self.consecutive_successes,
                "metrics": {
                    "total": self.metrics.total_calls,
                    "successful": self.metrics.successful_calls,
                    "failed": self.metrics.failed_calls,
                    "rejected": self.metrics.rejected_calls,
                    "times_opened": self.metrics.times_opened,
                },
            }

    def _transition(self, new_state: CircuitState) -> None:
        old = self.state
        self.state = new_state
        if new_state == CircuitState.OPEN:
            self.opened_at = time.time()
            self.metrics.times_opened += 1
            logger.warning("🔴 Circuit '%s' OPENED", self.name)
            if self._on_open:
                try:
                    self._on_open(self.name)
                except Exception:
                    pass
        elif new_state == CircuitState.CLOSED:
            self.metrics.times_closed += 1
            logger.info("🟢 Circuit '%s' CLOSED", self.name)
            if self._on_close:
                try:
                    self._on_close(self.name)
                except Exception:
                    pass
        elif new_state == CircuitState.HALF_OPEN:
            logger.info("🟡 Circuit '%s' HALF_OPEN (testing recovery)", self.name)
            if self._on_half_open:
                try:
                    self._on_half_open(self.name)
                except Exception:
                    pass

    def _push_outcome(self, success: bool) -> None:
        self.recent_outcomes.append(success)
        if len(self.recent_outcomes) > self.config.window_size:
            self.recent_outcomes = self.recent_outcomes[-self.config.window_size:]

    def _failure_rate(self) -> float:
        if not self.recent_outcomes:
            return 0.0
        failures = self.recent_outcomes.count(False)
        return float(failures) / float(len(self.recent_outcomes))


class ServiceCircuitBreaker:
    """
    Registry and manager for named circuit breakers.
    One instance per process; manages all downstream service circuits.
    """

    def __init__(self) -> None:
        self._circuits: dict[str, _CircuitInstance] = {}
        self._lock = RLock()
        logger.info("⚡ ServiceCircuitBreaker initialised")

    def register(self, name: str, config: Optional[CircuitConfig] = None) -> _CircuitInstance:
        """Register a new circuit. Returns existing if already registered."""
        with self._lock:
            if name not in self._circuits:
                self._circuits[name] = _CircuitInstance(name, config or CircuitConfig())
                logger.info("⚡ Circuit '%s' registered", name)
            return self._circuits[name]

    def allow(self, name: str) -> bool:
        """Check if a request to service `name` should be allowed."""
        with self._lock:
            circuit = self._circuits.get(name)
        if circuit is None:
            return True
        allowed = circuit.allow_request()
        if not allowed:
            circuit.record_rejected()
        return allowed

    def success(self, name: str) -> None:
        with self._lock:
            circuit = self._circuits.get(name)
        if circuit:
            circuit.record_success()

    def failure(self, name: str) -> None:
        with self._lock:
            circuit = self._circuits.get(name)
        if circuit:
            circuit.record_failure()

    def force_open(self, name: str) -> None:
        with self._lock:
            c = self._circuits.get(name)
        if c:
            c.force_open()

    def force_close(self, name: str) -> None:
        with self._lock:
            c = self._circuits.get(name)
        if c:
            c.force_close()

    def get_all_statuses(self) -> list[dict]:
        with self._lock:
            circuits = list(self._circuits.values())
        return [c.get_status() for c in circuits]

    def get_stats(self) -> dict:
        statuses = self.get_all_statuses()
        open_count = sum(1 for s in statuses if s["state"] == CircuitState.OPEN.value)
        return {
            "circuit_count": len(statuses),
            "open_circuits": open_count,
            "circuits": statuses,
        }


# Register default platform circuits
service_circuit_breaker = ServiceCircuitBreaker()
service_circuit_breaker.register("llm_api",         CircuitConfig(failure_threshold=3, timeout_seconds=15.0))
service_circuit_breaker.register("database",         CircuitConfig(failure_threshold=5, timeout_seconds=30.0))
service_circuit_breaker.register("vector_store",     CircuitConfig(failure_threshold=4, timeout_seconds=20.0))
service_circuit_breaker.register("external_api",     CircuitConfig(failure_threshold=5, timeout_seconds=60.0))
service_circuit_breaker.register("threat_feed",      CircuitConfig(failure_threshold=3, timeout_seconds=120.0))
