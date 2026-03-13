"""
Commits 9 & 13:
  9:  per-threat-type statistics tracking
  13: request ID tracking across log entries
In-memory stats store backed by a typed dataclass — no Pylance ambiguity.
"""

import time
import uuid
from dataclasses import dataclass, field
from threading import Lock


# ──────────────────────────────────────────────
# Typed stats container  (fixes mixed-type dict errors)
# ──────────────────────────────────────────────

@dataclass
class _StatsData:
    total_attempts: int = 0
    total_blocked: int = 0
    total_leaked: int = 0
    block_rate: float = 100.0
    per_threat_type: dict[str, int] = field(default_factory=dict)
    started_at: float = field(default_factory=time.time)


_lock = Lock()
_stats = _StatsData()


# ──────────────────────────────────────────────
# Public helpers
# ──────────────────────────────────────────────

def _init_threat_keys() -> None:
    """Populate per_threat_type keys from threat pattern categories."""
    try:
        from app.config.threat_patterns import THREAT_PATTERNS
        for key in THREAT_PATTERNS:
            if key not in _stats.per_threat_type:
                _stats.per_threat_type[key] = 0
    except ImportError:
        pass  # Graceful fallback if config not yet loaded


# Initialise on import
_init_threat_keys()


def new_request_id() -> str:
    """Commit 13: Generate a unique request ID for tracing log entries."""
    return str(uuid.uuid4())


def increment_attempt(blocked: bool, threat_type: str = "none") -> None:
    """Record one request outcome and update block rate."""
    with _lock:
        _stats.total_attempts += 1
        if blocked:
            _stats.total_blocked += 1
        else:
            _stats.total_leaked += 1

        # Commit 9: per-threat-type tracking
        if threat_type and threat_type != "none":
            if threat_type not in _stats.per_threat_type:
                _stats.per_threat_type[threat_type] = 0
            _stats.per_threat_type[threat_type] += 1

        total = _stats.total_attempts
        _stats.block_rate = float(round((_stats.total_blocked / total) * 100, 1)) if total else 100.0


def get_stats() -> dict:
    """Return a snapshot of the current stats as a plain dict."""
    with _lock:
        return {
            "total_attempts": _stats.total_attempts,
            "total_blocked": _stats.total_blocked,
            "total_leaked": _stats.total_leaked,
            "block_rate": float(round(_stats.block_rate, 1)),
            "per_threat_type": dict(_stats.per_threat_type),
            "started_at": _stats.started_at,
        }


def reset_stats() -> None:
    """Reset all in-memory statistics to zero."""
    with _lock:
        _stats.total_attempts = 0
        _stats.total_blocked = 0
        _stats.total_leaked = 0
        _stats.block_rate = 100.0
        _stats.per_threat_type = {k: 0 for k in _stats.per_threat_type}
        _stats.started_at = time.time()
    _init_threat_keys()


def uptime_seconds() -> float:
    """Return seconds elapsed since the stats store was initialized."""
    return round(time.time() - _stats.started_at, 1)
