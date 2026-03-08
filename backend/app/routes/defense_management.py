"""
Commit 84: Defense Management API Routes
==========================================
FastAPI router exposing management and monitoring endpoints for
the batch-4 defense modules.

Endpoints:
  GET  /api/defense/health               — overall defense health snapshot
  GET  /api/defense/config               — current effective configuration
  POST /api/defense/config               — set a config key at runtime
  DELETE /api/defense/config/{key}       — reset a config key to default
  GET  /api/defense/audit/recent         — recent audit log entries
  GET  /api/defense/audit/query          — filtered audit log query
  GET  /api/defense/sessions/{id}        — session threat tracker status
  POST /api/defense/sessions             — create a new tracked session
  GET  /api/defense/ip/{ip}              — IP threat intelligence lookup
  POST /api/defense/ip/{ip}/flag         — flag an IP manually
  DELETE /api/defense/ip/{ip}/flag       — unflag an IP
  GET  /api/defense/circuits             — circuit breaker statuses
  POST /api/defense/circuits/{name}/open — force-open a circuit
  POST /api/defense/circuits/{name}/close — force-close a circuit
  POST /api/defense/scan/full            — full batch-4 pipeline scan
"""

import logging
import time
from typing import Any, Optional

try:
    from fastapi import APIRouter, HTTPException, Path, Body, Query  # type: ignore[import]
    from pydantic import BaseModel  # type: ignore[import]
except ImportError:
    raise

from app.services.defense_config_manager import defense_config_manager
from app.services.defense_audit_logger import (
    defense_audit_logger, AuditSeverity, AuditEventType,
)
from app.services.session_threat_tracker import session_threat_tracker
from app.services.ip_threat_intelligence import ip_threat_intelligence, IPSeverity
from app.services.service_circuit_breaker import service_circuit_breaker
from app.services.conversation_context_analyzer import conversation_context_analyzer
from app.services.content_classifier import content_classifier
from app.services.prompt_intent_classifier import prompt_intent_classifier
from app.services.request_anomaly_detector import request_anomaly_detector

router = APIRouter(prefix="/api/defense", tags=["defense-management"])
logger = logging.getLogger(__name__)


# ── Request models ─────────────────────────────────────────────────────────────

class SetConfigRequest(BaseModel):
    key: str
    value: Any
    changed_by: str = "admin_api"


class AuditQueryRequest(BaseModel):
    min_severity: Optional[str] = None
    module: Optional[str] = None
    ip: Optional[str] = None
    session_id: Optional[str] = None
    event_type: Optional[str] = None
    limit: int = 50


class CreateSessionRequest(BaseModel):
    ip: str
    session_id: Optional[str] = None


class FlagIPRequest(BaseModel):
    severity: str = "medium"   # low | medium | high | critical
    reason: str = ""
    ttl_seconds: Optional[float] = None


class FullScanRequest(BaseModel):
    text: str
    ip: Optional[str] = None
    session_id: Optional[str] = None


# ── Helper ─────────────────────────────────────────────────────────────────────

def _defense_health() -> dict:
    return {
        "defense_enabled":    defense_config_manager.get_bool("global.defense_enabled"),
        "audit_logging":      defense_config_manager.get_bool("global.audit_logging_enabled"),
        "rate_limiting":      defense_config_manager.get_bool("global.rate_limiting_enabled"),
        "output_filtering":   defense_config_manager.get_bool("global.output_filtering_enabled"),
        "config_version":     defense_config_manager.get_stats()["config_version"],
        "active_sessions":    session_threat_tracker.get_stats()["active_sessions"],
        "flagged_ips":        ip_threat_intelligence.get_stats()["flagged_ips"],
        "open_circuits":      service_circuit_breaker.get_stats()["open_circuits"],
    }


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.get("/health")
async def defense_health() -> dict:
    """Overall defense health snapshot."""
    return {"status": "ok", "timestamp": time.time(), "health": _defense_health()}


@router.get("/config")
async def get_config() -> dict:
    """Return current effective configuration (defaults + overrides)."""
    stats = defense_config_manager.get_stats()
    overrides = defense_config_manager.get_all_overrides()
    return {"stats": stats, "overrides": overrides}


@router.post("/config")
async def set_config(req: SetConfigRequest) -> dict:
    """Set a runtime config override."""
    defaults = defense_config_manager.get_all_defaults()
    if req.key not in defaults:
        raise HTTPException(status_code=400, detail=f"Unknown config key: '{req.key}'")
    defense_config_manager.set(req.key, req.value, changed_by=req.changed_by)
    defense_audit_logger.info(
        AuditEventType.ADMIN_ACTION, "defense_config_manager",
        details={"action": "set_config", "key": req.key, "value": str(req.value)},
    )
    return {"status": "ok", "key": req.key, "value": req.value}


@router.delete("/config/{key}")
async def reset_config(key: str = Path(..., description="Config key to reset")) -> dict:
    """Reset a config key to its default value."""
    defense_config_manager.reset(key, changed_by="admin_api")
    return {"status": "reset", "key": key}


@router.get("/audit/recent")
async def audit_recent(n: int = Query(20, ge=1, le=500)) -> dict:
    """Return the N most recent audit records."""
    records = defense_audit_logger.recent(n=n)
    return {"count": len(records), "records": records}


@router.post("/audit/query")
async def audit_query(req: AuditQueryRequest) -> dict:
    """Query the audit log with filters."""
    sev = None
    if req.min_severity:
        try:
            sev = AuditSeverity(req.min_severity)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid severity: {req.min_severity}")
    evt = None
    if req.event_type:
        try:
            evt = AuditEventType(req.event_type)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid event_type: {req.event_type}")
    records = defense_audit_logger.query(
        min_severity=sev,
        module=req.module,
        ip=req.ip,
        session_id=req.session_id,
        event_type=evt,
        limit=req.limit,
    )
    return {"count": len(records), "records": records}


@router.get("/sessions/{session_id}")
async def get_session(session_id: str = Path(...)) -> dict:
    """Get threat tracker status for a session."""
    status = session_threat_tracker.get_status(session_id)
    if status is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return status.to_dict()


@router.post("/sessions")
async def create_session(req: CreateSessionRequest) -> dict:
    """Create a new tracked session."""
    sid = session_threat_tracker.create_session(req.ip, session_id=req.session_id)
    return {"session_id": sid, "ip": req.ip, "status": "created"}


@router.get("/ip/{ip}")
async def lookup_ip(ip: str = Path(..., description="IP address to look up")) -> dict:
    """IP threat intelligence lookup."""
    result = ip_threat_intelligence.lookup(ip)
    return result.to_dict()


@router.post("/ip/{ip}/flag")
async def flag_ip(
    ip: str = Path(...),
    req: FlagIPRequest = Body(default=FlagIPRequest()),
) -> dict:
    """Manually flag an IP address."""
    try:
        sev = IPSeverity(req.severity)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid severity: {req.severity}")
    entry = ip_threat_intelligence.flag_ip(
        ip=ip, severity=sev, reason=req.reason,
        source="manual_admin", ttl_seconds=req.ttl_seconds,
    )
    defense_audit_logger.alert(
        AuditEventType.IP_FLAGGED, "ip_threat_intelligence",
        ip=ip, details={"severity": req.severity, "reason": req.reason},
    )
    return {"status": "flagged", "ip": ip, "severity": entry.severity.value}


@router.delete("/ip/{ip}/flag")
async def unflag_ip(ip: str = Path(...)) -> dict:
    """Remove a manual IP flag."""
    removed = ip_threat_intelligence.unflag_ip(ip)
    return {"status": "removed" if removed else "not_found", "ip": ip}


@router.get("/circuits")
async def circuit_statuses() -> dict:
    """Get all circuit breaker statuses."""
    return service_circuit_breaker.get_stats()


@router.post("/circuits/{name}/open")
async def open_circuit(name: str = Path(..., description="Circuit name")) -> dict:
    """Force-open a circuit."""
    service_circuit_breaker.force_open(name)
    defense_audit_logger.alert(
        AuditEventType.ADMIN_ACTION, "service_circuit_breaker",
        details={"action": "force_open", "circuit": name},
    )
    return {"status": "opened", "circuit": name}


@router.post("/circuits/{name}/close")
async def close_circuit(name: str = Path(..., description="Circuit name")) -> dict:
    """Force-close a circuit."""
    service_circuit_breaker.force_close(name)
    defense_audit_logger.info(
        AuditEventType.ADMIN_ACTION, "service_circuit_breaker",
        details={"action": "force_close", "circuit": name},
    )
    return {"status": "closed", "circuit": name}


@router.post("/scan/full")
async def full_batch4_scan(req: FullScanRequest) -> dict:
    """
    Run all batch-4 defense scanners on a text string.
    Optionally attach IP and session context.
    """
    text = req.text
    if not text or not text.strip():
        raise HTTPException(status_code=400, detail="text must not be empty")
    if len(text) > 32_768:
        raise HTTPException(status_code=400, detail="text exceeds 32 KB limit")

    start = time.time()
    results: dict[str, Any] = {}

    # Content classification
    try:
        results["content_classifier"] = content_classifier.classify(text).to_dict()
    except Exception as e:
        results["content_classifier"] = {"error": str(e)}

    # Intent classification
    try:
        results["intent_classifier"] = prompt_intent_classifier.classify(text).to_dict()
    except Exception as e:
        results["intent_classifier"] = {"error": str(e)}

    # Anomaly detection (IP-based)
    if req.ip:
        try:
            results["anomaly_detector"] = request_anomaly_detector.analyze(req.ip, text).to_dict()
        except Exception as e:
            results["anomaly_detector"] = {"error": str(e)}

    # IP intelligence
    if req.ip:
        try:
            results["ip_intelligence"] = ip_threat_intelligence.lookup(req.ip).to_dict()
        except Exception as e:
            results["ip_intelligence"] = {"error": str(e)}

    # Session context analysis
    if req.session_id:
        try:
            conversation_context_analyzer.add_turn(req.session_id, "user", text)
            results["context_analyzer"] = conversation_context_analyzer.analyze(req.session_id).to_dict()
        except Exception as e:
            results["context_analyzer"] = {"error": str(e)}

    elapsed = float((time.time() - start) * 1000)
    return {
        "text_length": len(text),
        "scan_latency_ms": round(elapsed, 2),
        "results": results,
    }
