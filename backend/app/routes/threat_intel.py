"""
Commit 42: Threat Intelligence Route
Endpoints that surface threat intelligence data across all defense modules.

Endpoints:
  GET  /api/threat-intel/summary         — overall threat landscape overview
  GET  /api/threat-intel/top-threats     — most frequent threat types in the window
  GET  /api/threat-intel/attacker-ips    — IPs with highest threat activity
  GET  /api/threat-intel/honeypot        — honeypot trigger report
  GET  /api/threat-intel/behavioral      — high-risk behavioral profiles
  GET  /api/threat-intel/event-log       — security event bus history
  GET  /api/threat-intel/timeline        — last N threats with timestamps
  POST /api/threat-intel/config          — update defense config section
  GET  /api/threat-intel/config          — export current defense config
  GET  /api/threat-intel/config/history  — config change history
"""

import logging
import time
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/threat-intel", tags=["Threat Intelligence"])


# ── Pydantic bodies ────────────────────────────────────────────────────────────

class ConfigUpdateRequest(BaseModel):
    section: str
    updates: dict


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.get("/summary")
async def threat_intel_summary():
    """
    High-level threat intelligence summary covering all defense modules.
    """
    result: dict = {"generated_at": time.time()}

    try:
        from app.services.observability import get_stats, uptime_seconds
        stats = get_stats()
        result["core"] = {
            "total_attempts": stats["total_attempts"],
            "total_blocked": stats["total_blocked"],
            "block_rate_pct": stats["block_rate"],
            "uptime_seconds": uptime_seconds(),
        }
    except Exception as exc:
        result["core_error"] = str(exc)

    try:
        from app.services.anomaly_detector import anomaly_detector
        result["anomaly"] = anomaly_detector.get_stats()
    except Exception as exc:
        result["anomaly_error"] = str(exc)

    try:
        from app.services.prompt_honeypot import prompt_honeypot
        result["honeypot"] = prompt_honeypot.get_stats()
    except Exception as exc:
        result["honeypot_error"] = str(exc)

    try:
        from app.services.behavioral_profiler import behavioral_profiler
        result["behavioral"] = behavioral_profiler.get_stats()
    except Exception as exc:
        result["behavioral_error"] = str(exc)

    try:
        from app.services.security_event_bus import event_bus
        result["event_bus"] = event_bus.get_stats()
    except Exception as exc:
        result["event_bus_error"] = str(exc)

    try:
        from app.services.defense_orchestrator import orchestrator
        result["orchestrator"] = orchestrator.get_stats()
    except Exception as exc:
        result["orchestrator_error"] = str(exc)

    return result


@router.get("/top-threats")
async def top_threats(limit: int = Query(default=10, ge=1, le=50)):
    """
    Return the most frequently detected threat types from the stats store.
    """
    try:
        from app.services.observability import get_stats
        stats = get_stats()
        per_type = stats.get("per_threat_type", {})
        sorted_threats = sorted(per_type.items(), key=lambda x: x[1], reverse=True)[:limit]
        total = sum(v for _, v in sorted_threats)
        return {
            "total_threats": total,
            "threats": [
                {
                    "threat_type": k,
                    "count": v,
                    "share_pct": round(v / max(total, 1) * 100, 1),
                }
                for k, v in sorted_threats
            ],
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/attacker-ips")
async def attacker_ips(limit: int = Query(default=10, ge=1, le=100)):
    """
    Return IPs flagged by the behavioral profiler as high or critical risk.
    """
    try:
        from app.services.behavioral_profiler import behavioral_profiler
        high_risk = behavioral_profiler.get_all_high_risk()
        return {
            "total_high_risk_ips": len(high_risk),
            "ips": high_risk[:limit],
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/honeypot")
async def honeypot_report(limit: int = Query(default=10, ge=1, le=50)):
    """
    Return honeypot trigger statistics and top attacker IPs.
    """
    try:
        from app.services.prompt_honeypot import prompt_honeypot
        return {
            "stats": prompt_honeypot.get_stats(),
            "top_attackers": prompt_honeypot.get_top_attackers(limit=limit),
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/behavioral")
async def behavioral_report(limit: int = Query(default=20, ge=1, le=100)):
    """
    Return all high-risk behavioral profiles from the profiler.
    """
    try:
        from app.services.behavioral_profiler import behavioral_profiler
        profiles = behavioral_profiler.get_all_high_risk()
        return {
            "total": len(profiles),
            "profiles": profiles[:limit],
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/event-log")
async def event_log(
    event_type: str = Query(default="", description="Filter by event type"),
    limit: int = Query(default=50, ge=1, le=500),
):
    """Return recent events from the security event bus."""
    try:
        from app.services.security_event_bus import event_bus
        return {
            "stats": event_bus.get_stats(),
            "events": event_bus.get_history(event_type=event_type, limit=limit),
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/timeline")
async def threat_timeline(limit: int = Query(default=20, ge=1, le=100)):
    """Return a timeline of recent blocked events from the audit log."""
    try:
        from app.routes.audit import _audit_log, _audit_lock
        with _audit_lock:
            events = list(_audit_log)
        blocked = [e for e in events if "block" in str(e.get("event_type", ""))]
        blocked = list(reversed(blocked[-limit:]))
        return {
            "total_blocked_events": len(blocked),
            "timeline": blocked,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/config")
async def get_config():
    """Export the current defense configuration."""
    try:
        from app.services.defense_config import defense_config_manager
        return defense_config_manager.export()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/config")
async def update_config(body: ConfigUpdateRequest):
    """Hot-update one section of the defense configuration."""
    try:
        from app.services.defense_config import defense_config_manager
        success = defense_config_manager.update_section(body.section, body.updates)
        if not success:
            raise HTTPException(status_code=400, detail=f"Unknown config section: {body.section}")
        return {"status": "ok", "section": body.section, "applied": body.updates}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/config/history")
async def config_change_history():
    """Return the history of all configuration changes."""
    try:
        from app.services.defense_config import defense_config_manager
        history = defense_config_manager.get_change_history()
        return {
            "total_changes": len(history),
            "changes": list(reversed(history)),
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
