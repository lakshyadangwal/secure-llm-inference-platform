"""
Commit 34: Admin Control Panel Routes
======================================
Endpoints for operational control of defense subsystems.
All routes are prefixed /api/admin and should be protected
behind authentication in production.

Endpoints:
  POST /api/admin/cache/flush           — clear the threat cache
  POST /api/admin/circuit/reset         — reset Ollama circuit breaker
  DELETE /api/admin/anomaly/ip/{ip}     — clear anomaly history for an IP
  GET  /api/admin/circuit/status        — circuit breaker live status
  GET  /api/admin/cache/status          — cache live status
  POST /api/admin/dlp/test              — run a test string through DLP
  POST /api/admin/sanitizer/test        — run a test string through sanitizer
  POST /api/admin/context/test          — run a test string through context guard
  GET  /api/admin/system/summary        — quick one-liner health summary
"""

import logging
from fastapi import APIRouter, HTTPException, Body
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/admin", tags=["Admin"])


# ── Request bodies ─────────────────────────────────────────────────────────────

class TestTextRequest(BaseModel):
    text: str


# ── Cache management ──────────────────────────────────────────────────────────

@router.post("/cache/flush")
async def flush_threat_cache():
    """Clear all entries from the in-memory threat cache."""
    try:
        from app.services.threat_cache import threat_cache
        removed = threat_cache.flush()
        logger.info("🧹 Admin: threat cache flushed (%d entries)", removed)
        return {"status": "ok", "entries_removed": removed}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/cache/status")
async def cache_status():
    """Return live threat cache statistics."""
    try:
        from app.services.threat_cache import threat_cache
        return threat_cache.get_stats()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ── Circuit breaker management ─────────────────────────────────────────────────

@router.post("/circuit/reset")
async def reset_circuit_breaker():
    """Manually reset the Ollama circuit breaker to CLOSED state."""
    try:
        from app.services.circuit_breaker import ollama_circuit_breaker
        ollama_circuit_breaker.reset()
        logger.info("⚡ Admin: Ollama circuit breaker reset to CLOSED")
        return {"status": "ok", "circuit": "closed"}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/circuit/status")
async def circuit_status():
    """Return live Ollama circuit breaker statistics."""
    try:
        from app.services.circuit_breaker import ollama_circuit_breaker
        return ollama_circuit_breaker.get_stats()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ── Anomaly detector management ────────────────────────────────────────────────

@router.delete("/anomaly/ip/{ip}")
async def clear_anomaly_history(ip: str):
    """
    Clear stored anomaly history for a specific IP address.
    Useful for un-flagging legitimate users after investigation.
    """
    try:
        from app.services.anomaly_detector import anomaly_detector
        removed = anomaly_detector.clear_ip(ip)
        logger.info("🔄 Admin: cleared anomaly history for IP %s (%d entries)", ip, removed)
        return {"status": "ok", "ip": ip, "entries_removed": removed}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/anomaly/stats")
async def anomaly_stats():
    """Return live anomaly detector statistics."""
    try:
        from app.services.anomaly_detector import anomaly_detector
        return anomaly_detector.get_stats()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ── Live test probes ───────────────────────────────────────────────────────────

@router.post("/dlp/test")
async def test_dlp(body: TestTextRequest):
    """
    Run a text string through the DLP engine and return
    the full scan result including any detected leaks.
    """
    try:
        from app.services.dlp_engine import dlp_engine
        result = dlp_engine.scan(body.text)
        return {
            "has_leak": result.has_leak,
            "leak_types": result.leak_types,
            "leaks": result.leaks,
            "redacted_text": result.redacted_text,
            "highest_severity": result.highest_severity,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/sanitizer/test")
async def test_sanitizer(body: TestTextRequest):
    """
    Run a text string through the input sanitizer and return
    the cleaned text plus a list of transforms applied.
    """
    try:
        from app.services.input_sanitizer import input_sanitizer
        result = input_sanitizer.sanitize(body.text)
        return {
            "sanitized_text": result.sanitized_text,
            "was_modified": result.was_modified,
            "transforms_applied": result.transforms_applied,
            "flagged": result.flagged,
            "flag_reasons": result.flag_reasons,
            "original_length": result.original_length,
            "sanitized_length": result.sanitized_length,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/context/test")
async def test_context_guard(body: TestTextRequest):
    """
    Run a text string through the context window guard and
    return violation details.
    """
    try:
        from app.services.context_guard import context_guard
        result = context_guard.check(body.text)
        return {
            "is_violation": result.is_violation,
            "estimated_tokens": result.estimated_tokens,
            "violations": result.violations,
            "details": result.details,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ── System summary ─────────────────────────────────────────────────────────────

@router.get("/system/summary")
async def system_summary():
    """
    One-call health summary covering all defense subsystems.
    Returns overall health, key metrics, and any active issues.
    """
    try:
        from app.services.defense_metrics import defense_metrics
        data = defense_metrics.to_dict()
        return {
            "overall_health": data["overall_health"],
            "health_issues": data["health_issues"],
            "block_rate_pct": data["core"]["block_rate_pct"],
            "total_requests": data["core"]["total_requests"],
            "circuit_state": data["circuit_breaker"].get("state", "unknown"),
            "cache_hit_rate": data["threat_cache"].get("hit_rate_pct", 0),
            "anomaly_rate": data["anomaly_detector"].get("anomaly_rate_pct", 0),
            "uptime_seconds": data["core"]["uptime_seconds"],
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
