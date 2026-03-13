"""
Commit 33: Audit Trail Route
==============================
GET /api/audit          — returns recent security audit events
GET /api/audit/summary  — aggregated counts by event type
GET /api/defense/metrics — full defense subsystem dashboard
"""

import logging
import time
from collections import deque
from threading import Lock
from fastapi import APIRouter, Query
from app.services.defense_metrics import defense_metrics

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Audit & Metrics"])

# ── In-memory audit log ────────────────────────────────────────────────────────

_audit_lock = Lock()
_audit_log: deque[dict] = deque(maxlen=1000)   # rolling 1000-event buffer


def record_audit_event(
    event_type: str,
    ip: str = "unknown",
    detail: str = "",
    severity: str = "info",
    request_id: str = "",
) -> None:
    """
    Append one event to the in-memory audit log.

    Args:
        event_type: Category string, e.g. 'threat_blocked', 'dlp_leak', 'anomaly'
        ip:         Source IP of the request
        detail:     Human-readable description of the event
        severity:   'info' | 'warning' | 'critical'
        request_id: UUID of the originating request (for correlation)
    """
    entry = {
        "ts": time.time(),
        "event_type": event_type,
        "ip": ip,
        "detail": detail,
        "severity": severity,
        "request_id": request_id,
    }
    with _audit_lock:
        _audit_log.append(entry)

    logger.debug(
        "📋 AUDIT [%s] ip=%s rid=%s — %s",
        event_type, ip, request_id[:8] if request_id else "", detail
    )


# ── Pre-populate with a startup event ─────────────────────────────────────────
record_audit_event(
    event_type="service_start",
    detail="Neuro-Sentry audit log initialised",
    severity="info",
)


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.get("/api/audit")
async def get_audit_log(
    limit: int = Query(default=50, ge=1, le=500, description="Max events to return"),
    event_type: str = Query(default="", description="Filter by event type"),
    severity: str = Query(default="", description="Filter by severity"),
):
    """
    Return the most recent security audit events.

    Query params:
      - limit:      number of events to return (1–500, default 50)
      - event_type: filter to a specific event category
      - severity:   filter to 'info', 'warning', or 'critical'
    """
    with _audit_lock:
        events = list(_audit_log)

    # Apply filters
    if event_type:
        events = [e for e in events if e["event_type"] == event_type]
    if severity:
        events = [e for e in events if e["severity"] == severity]

    # Most recent first
    events = list(reversed(events[-limit:]))

    return {
        "total_in_buffer": len(_audit_log),
        "returned": len(events),
        "filters": {"event_type": event_type or None, "severity": severity or None},
        "events": events,
    }


@router.get("/api/audit/summary")
async def get_audit_summary():
    """
    Return aggregated counts of each event type and severity
    over the current in-memory audit buffer.
    """
    with _audit_lock:
        events = list(_audit_log)

    by_type: dict[str, int] = {}
    by_severity: dict[str, int] = {}

    for e in events:
        et: str = str(e.get("event_type", "unknown"))
        sv: str = str(e.get("severity", "info"))
        by_type[et] = by_type.get(et, 0) + 1
        by_severity[sv] = by_severity.get(sv, 0) + 1

    critical_count: int = by_severity.get("critical", 0)
    health: str = (
        "critical" if critical_count > 10
        else "degraded" if critical_count > 0
        else "healthy"
    )

    return {
        "total_events": len(events),
        "by_event_type": by_type,
        "by_severity": by_severity,
        "health_signal": health,
    }


@router.get("/api/defense/metrics")
async def get_defense_metrics():
    """
    Full unified defense dashboard — aggregates metrics from all modules:
    stats store, DLP engine, threat cache, anomaly detector,
    input sanitizer, circuit breaker, and context guard.
    """
    return defense_metrics.to_dict()
