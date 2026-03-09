"""
Commit 93: Defense Health Monitor
=====================================
Lightweight health monitor that pings all registered defense modules
and returns an aggregated status summary.

Each module registers itself with a name and a callable that
returns a dict (its get_stats() method). The monitor calls all
callables and decides:
  - HEALTHY   — all modules responsive
  - DEGRADED  — some modules returned errors or bad stats
  - UNHEALTHY — majority of modules failed

Also tracks consecutive failure counts per module to detect
sustained outages vs. transient glitches.
"""

import logging
import time
from dataclasses import dataclass
from enum import Enum
from threading import RLock
from typing import Callable, Optional

logger = logging.getLogger(__name__)


class ModuleHealth(str, Enum):
    OK      = "ok"
    DEGRADED = "degraded"
    DOWN    = "down"


class SystemHealth(str, Enum):
    HEALTHY   = "healthy"
    DEGRADED  = "degraded"
    UNHEALTHY = "unhealthy"


@dataclass
class ModuleStatus:
    name: str
    health: ModuleHealth
    last_checked: float
    consecutive_failures: int
    last_stats: Optional[dict]
    error: Optional[str]

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "health": self.health.value,
            "last_checked": self.last_checked,
            "consecutive_failures": self.consecutive_failures,
            "error": self.error,
        }


@dataclass
class HealthReport:
    system_health: SystemHealth
    healthy_count: int
    degraded_count: int
    down_count: int
    modules: list[ModuleStatus]
    timestamp: float

    def to_dict(self) -> dict:
        return {
            "system_health": self.system_health.value,
            "healthy_count": self.healthy_count,
            "degraded_count": self.degraded_count,
            "down_count": self.down_count,
            "timestamp": self.timestamp,
            "modules": [m.to_dict() for m in self.modules],
        }


class DefenseHealthMonitor:
    """
    Registry and runner for defense module health checks.
    Call `register()` for each module, then `check_all()` to get a report.
    """

    def __init__(self) -> None:
        self._modules: dict[str, Callable[[], dict]] = {}
        self._statuses: dict[str, ModuleStatus] = {}
        self._lock = RLock()
        logger.info("🏥 DefenseHealthMonitor initialised")

    def register(self, name: str, stats_fn: Callable[[], dict]) -> None:
        """Register a module with its stats callable."""
        with self._lock:
            self._modules[name] = stats_fn
            self._statuses[name] = ModuleStatus(
                name=name,
                health=ModuleHealth.OK,
                last_checked=0.0,
                consecutive_failures=0,
                last_stats=None,
                error=None,
            )
        logger.info("🏥 Registered module: %s", name)

    def check_module(self, name: str) -> ModuleStatus:
        """Run the health check for a single module."""
        with self._lock:
            fn = self._modules.get(name)
            status = self._statuses.get(name)

        if fn is None or status is None:
            return ModuleStatus(
                name=name, health=ModuleHealth.DOWN,
                last_checked=time.time(),
                consecutive_failures=999,
                last_stats=None,
                error="Module not registered",
            )

        try:
            stats = fn()
            health = ModuleHealth.OK
            error = None
            with self._lock:
                status.consecutive_failures = 0
        except Exception as exc:
            stats = None
            error = str(exc)
            with self._lock:
                status.consecutive_failures += 1
            health = ModuleHealth.DEGRADED if status.consecutive_failures < 3 else ModuleHealth.DOWN
            logger.warning("🏥 Module %s health check failed: %s", name, exc)

        now = time.time()
        with self._lock:
            status.health = health
            status.last_checked = now
            status.last_stats = stats
            status.error = error

        return status

    def check_all(self) -> HealthReport:
        """Run health checks for all registered modules."""
        with self._lock:
            names = list(self._modules.keys())

        results: list[ModuleStatus] = [self.check_module(n) for n in names]

        healthy  = sum(1 for r in results if r.health == ModuleHealth.OK)
        degraded = sum(1 for r in results if r.health == ModuleHealth.DEGRADED)
        down     = sum(1 for r in results if r.health == ModuleHealth.DOWN)
        total = max(1, len(results))

        if down / total >= 0.5:
            sys_health = SystemHealth.UNHEALTHY
        elif (down + degraded) / total >= 0.3:
            sys_health = SystemHealth.DEGRADED
        else:
            sys_health = SystemHealth.HEALTHY

        return HealthReport(
            system_health=sys_health,
            healthy_count=healthy,
            degraded_count=degraded,
            down_count=down,
            modules=results,
            timestamp=time.time(),
        )

    def get_stats(self) -> dict:
        with self._lock:
            return {"registered_modules": len(self._modules)}


defense_health_monitor = DefenseHealthMonitor()

# Auto-register known defense module singletons if available
def _auto_register() -> None:
    try:
        from app.services.jailbreak_pattern_db import JailbreakPatternDB  # type: ignore[import]
        from app.services.adaptive_rate_limiter import AdaptiveRateLimiter  # type: ignore[import]
    except ImportError:
        pass

_auto_register()
