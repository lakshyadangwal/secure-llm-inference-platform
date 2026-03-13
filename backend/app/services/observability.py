"""
Observability Module — Commits 11–15 combined
=============================================
  11: per-threat-type statistics tracking
  12: rotating log file handler with max size limit
  13: structured JSON logging support
  14: request ID tracking across log entries
  15: /api/stats/reset endpoint support + block-rate computation

Single module that owns ALL observability concerns for the backend:
  - In-memory stats store (typed dataclass, thread-safe, per-threat counters)
  - Unique request ID generation for log correlation
  - Rotating file log handler (configurable max size + backup count)
  - Optional JSON log formatter for log aggregation tools (ELK, Splunk, etc.)
  - Stats snapshot, reset, and uptime helpers
"""

# ── Standard library ────────────────────────────────────────────────────────
import json
import logging
import logging.handlers
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import Lock
from typing import Optional

# ── Config ───────────────────────────────────────────────────────────────────
try:
    from app.config.settings import settings
    from app.config.threat_patterns import THREAT_PATTERNS
    _THREAT_KEYS: list[str] = list(THREAT_PATTERNS.keys())
except ImportError:
    # Graceful fallback so module can be imported standalone (e.g. unit tests)
    _THREAT_KEYS = ["jailbreak", "injection", "extraction", "encoding"]

    class _FallbackSettings:  # type: ignore[no-untyped-def]
        LOG_LEVEL = "INFO"
        LOG_MAX_BYTES = 5 * 1024 * 1024  # 5 MB
        LOG_BACKUP_COUNT = 3
        LOG_JSON_FORMAT = False

    settings = _FallbackSettings()  # type: ignore[assignment]


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  SECTION 1 — STATS STORE  (Commits 11 & 14)                            ║
# ╚══════════════════════════════════════════════════════════════════════════╝

@dataclass
class _StatsData:
    """
    Typed container for all runtime statistics.
    Using a dataclass instead of a plain dict eliminates ambiguous
    value types that cause Pylance type errors on arithmetic operations.
    """
    total_attempts: int = 0
    total_blocked: int = 0
    total_leaked: int = 0
    block_rate: float = 100.0
    # Commit 11: per-threat-type counter dict
    per_threat_type: dict[str, int] = field(default_factory=dict)
    started_at: float = field(default_factory=time.time)


_stats_lock = Lock()
_stats = _StatsData()


def _ensure_threat_keys() -> None:
    """Populate per_threat_type with known keys so counters start at zero."""
    for key in _THREAT_KEYS:
        if key not in _stats.per_threat_type:
            _stats.per_threat_type[key] = 0


_ensure_threat_keys()


# ── Commit 14: Request ID generation ────────────────────────────────────────

def new_request_id() -> str:
    """
    Generate a unique UUID4 request ID.
    Attach this to every log call for that request to enable full
    end-to-end tracing across log lines.

    Usage:
        rid = new_request_id()
        logger.info("[%s] Processing request", rid)
    """
    return str(uuid.uuid4())


# ── Stats mutation helpers ───────────────────────────────────────────────────

def increment_attempt(blocked: bool, threat_type: str = "none") -> None:
    """
    Record the outcome of one request and recompute the block rate.

    Args:
        blocked:     True if the request was blocked/safe, False if it breached.
        threat_type: Category of threat detected (or 'none' for benign).
    """
    with _stats_lock:
        _stats.total_attempts += 1

        if blocked:
            _stats.total_blocked += 1
        else:
            _stats.total_leaked += 1

        # Commit 11: per-threat-type tracking
        if threat_type and threat_type != "none":
            if threat_type not in _stats.per_threat_type:
                _stats.per_threat_type[threat_type] = 0
            _stats.per_threat_type[threat_type] += 1

        total: int = _stats.total_attempts
        raw_rate: float = (_stats.total_blocked / total * 100.0) if total > 0 else 100.0
        _stats.block_rate = float(round(raw_rate, 1))


def get_stats() -> dict:
    """Return a point-in-time snapshot of all statistics as a plain dict."""
    with _stats_lock:
        return {
            "total_attempts": _stats.total_attempts,
            "total_blocked": _stats.total_blocked,
            "total_leaked": _stats.total_leaked,
            "block_rate": float(round(_stats.block_rate, 1)),
            "per_threat_type": dict(_stats.per_threat_type),
            "started_at": _stats.started_at,
        }


def reset_stats() -> None:
    """
    Commit 15: Reset all in-memory statistics to initial values.
    Called by the POST /api/stats/reset endpoint.
    Resets counters, clears per-threat data, and resets the start timestamp.
    """
    with _stats_lock:
        _stats.total_attempts = 0
        _stats.total_blocked = 0
        _stats.total_leaked = 0
        _stats.block_rate = 100.0
        _stats.per_threat_type = {k: 0 for k in _THREAT_KEYS}
        _stats.started_at = time.time()


def uptime_seconds() -> float:
    """Return how many seconds the service has been running since init."""
    return float(round(time.time() - _stats.started_at, 1))


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  SECTION 2 — LOGGING INFRASTRUCTURE  (Commits 12 & 13)                 ║
# ╚══════════════════════════════════════════════════════════════════════════╝

# ── Commit 13: JSON log formatter ────────────────────────────────────────────

class JsonLogFormatter(logging.Formatter):
    """
    Formats each log record as a single-line JSON object.

    Designed for log aggregation pipelines (ELK Stack, Splunk, Datadog).
    Activate by setting LOG_JSON_FORMAT=true in your .env file.

    Output example:
        {"ts": "2025-01-01T12:00:00Z", "level": "WARNING",
         "logger": "app.security", "msg": "Threat detected",
         "request_id": "abc-123"}
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }

        # Guard: exc_info is a 3-tuple (type, value, tb) or (None, None, None)
        exc_info = record.exc_info
        if exc_info and exc_info[0] is not None:
            payload["exc"] = self.formatException(exc_info)  # type: ignore[arg-type]

        # request_id is injected as an extra field — not a std LogRecord attr
        request_id: object = getattr(record, "request_id", None)
        if request_id is not None:
            payload["request_id"] = request_id

        return json.dumps(payload, ensure_ascii=False)


# ── Commit 12: Rotating file handler setup ───────────────────────────────────

_active_log_file: str = ""


def setup_logging() -> str:
    """
    Configure application-wide logging with a rotating file handler.

    Commit 12: Uses RotatingFileHandler — caps log files at LOG_MAX_BYTES
               and keeps LOG_BACKUP_COUNT backups (e.g. backend.log.1, .2, .3).

    Commit 13: When LOG_JSON_FORMAT=true, all file log records are written
               as JSON objects instead of human-readable text.

    The console handler always uses plain text for readability.

    Returns:
        Absolute path to the currently active log file.
    """
    global _active_log_file

    # Create logs directory next to the backend/ root
    log_dir = os.path.join(os.path.dirname(__file__), "..", "..", "logs")
    os.makedirs(log_dir, exist_ok=True)

    timestamp: str = datetime.now().strftime("%Y%m%d_%H%M%S")
    _active_log_file = os.path.join(log_dir, f"backend_{timestamp}.log")

    # Choose formatter based on env config
    file_formatter: logging.Formatter
    if settings.LOG_JSON_FORMAT:
        file_formatter = JsonLogFormatter()
    else:
        file_formatter = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
        )

    # Commit 12: Rotating file handler
    file_handler = logging.handlers.RotatingFileHandler(
        _active_log_file,
        maxBytes=int(settings.LOG_MAX_BYTES),
        backupCount=int(settings.LOG_BACKUP_COUNT),
        encoding="utf-8",
    )
    file_handler.setFormatter(file_formatter)

    # Console handler — always plain text
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s")
    )

    # Apply to root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, str(settings.LOG_LEVEL), logging.INFO))
    root_logger.handlers.clear()
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    logging.getLogger(__name__).info(
        "📝 Logging ready — file=%s  json=%s  max=%dKB  backups=%d",
        _active_log_file,
        settings.LOG_JSON_FORMAT,
        int(settings.LOG_MAX_BYTES) // 1024,
        int(settings.LOG_BACKUP_COUNT),
    )

    return _active_log_file


def get_log_file() -> str:
    """Return the path of the currently active log file."""
    return _active_log_file


def get_log_tail(limit: int = 50) -> list[str]:
    """
    Read the last `limit` lines from the active log file.

    Args:
        limit: Maximum number of lines to return (default: 50).

    Returns:
        List of stripped log line strings.
    """
    if not _active_log_file or not os.path.exists(_active_log_file):
        return ["No log file available yet."]

    try:
        with open(_active_log_file, "r", encoding="utf-8") as fh:
            all_lines: list[str] = fh.readlines()
        tail: list[str] = all_lines[-limit:]
        return [line.rstrip() for line in tail]
    except OSError as exc:
        return [f"Error reading log file: {exc}"]
