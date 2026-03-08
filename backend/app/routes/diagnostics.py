"""
Commit 51: Diagnostics Route
================================
Safe internal diagnostics endpoints for system health inspection.
These endpoints expose no sensitive data — only structural metadata
about defense modules, versions, and runtime configuration.

Endpoints:
  GET /api/diag/ping              — liveness probe
  GET /api/diag/modules           — list all defense modules and their status
  GET /api/diag/sessions          — active session count and flagged sessions
  GET /api/diag/rate              — global rate analytics snapshot
  GET /api/diag/reputation/top    — top offender IPs by reputation score
  GET /api/diag/content-policy    — list all active content policies
  GET /api/diag/classifier/stats  — prompt intent classifier distribution
  GET /api/diag/signer/stats      — request signer statistics
  GET /api/diag/full              — combined full diagnostics snapshot
"""

import logging
import time
from fastapi import APIRouter, Query

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/diag", tags=["Diagnostics"])


# ── Liveness ───────────────────────────────────────────────────────────────────

@router.get("/ping")
async def ping():
    """Simple liveness probe. Returns 200 if the server is running."""
    return {"status": "ok", "ts": time.time()}


# ── Module registry ────────────────────────────────────────────────────────────

_MODULES = [
    ("security_service",     "app.services.security_service",     "SecurityService"),
    ("observability",        "app.services.observability",        "setup_logging"),
    ("dlp_engine",           "app.services.dlp_engine",           "dlp_engine"),
    ("threat_cache",         "app.services.threat_cache",         "threat_cache"),
    ("anomaly_detector",     "app.services.anomaly_detector",     "anomaly_detector"),
    ("input_sanitizer",      "app.services.input_sanitizer",      "input_sanitizer"),
    ("circuit_breaker",      "app.services.circuit_breaker",      "ollama_circuit_breaker"),
    ("context_guard",        "app.services.context_guard",        "context_guard"),
    ("defense_metrics",      "app.services.defense_metrics",      "defense_metrics"),
    ("defense_orchestrator", "app.services.defense_orchestrator", "orchestrator"),
    ("behavioral_profiler",  "app.services.behavioral_profiler",  "behavioral_profiler"),
    ("response_validator",   "app.services.response_validator",   "response_validator"),
    ("security_event_bus",   "app.services.security_event_bus",   "event_bus"),
    ("prompt_honeypot",      "app.services.prompt_honeypot",      "prompt_honeypot"),
    ("defense_config",       "app.services.defense_config",       "defense_config_manager"),
    ("content_policy",       "app.services.content_policy",       "content_policy_engine"),
    ("ip_reputation",        "app.services.ip_reputation",        "ip_reputation"),
    ("prompt_classifier",    "app.services.prompt_classifier",    "prompt_classifier"),
    ("session_manager",      "app.services.session_manager",      "session_manager"),
    ("rate_analyzer",        "app.services.rate_analyzer",        "rate_analyzer"),
    ("request_signer",       "app.services.request_signer",       "request_signer"),
]


@router.get("/modules")
async def list_modules():
    """
    List all defense modules and whether they can be imported successfully.
    Does NOT call any module functions — purely import probes.
    """
    results = []
    available = 0
    for name, module_path, attr in _MODULES:
        try:
            mod = __import__(module_path, fromlist=[attr])
            obj = getattr(mod, attr, None)
            status = "available" if obj is not None else "import_ok_attr_missing"
            available += 1
        except ImportError as exc:
            status = f"import_error: {exc}"
        except Exception as exc:
            status = f"error: {exc}"

        results.append({"module": name, "path": module_path, "status": status})

    return {
        "total": len(_MODULES),
        "available": available,
        "unavailable": len(_MODULES) - available,
        "modules": results,
    }


# ── Session diagnostics ────────────────────────────────────────────────────────

@router.get("/sessions")
async def session_diagnostics():
    """Return session manager statistics."""
    try:
        from app.services.session_manager import session_manager
        stats = session_manager.get_stats()
        flagged = session_manager.get_flagged()
        return {
            "stats": stats,
            "flagged_sessions": flagged[:10],   # cap at 10
        }
    except Exception as exc:
        return {"error": str(exc)}


# ── Rate analytics ─────────────────────────────────────────────────────────────

@router.get("/rate")
async def rate_diagnostics():
    """Return global rate analyzer statistics."""
    try:
        from app.services.rate_analyzer import rate_analyzer
        return {
            "global_stats": rate_analyzer.get_stats().__dict__
            if hasattr(rate_analyzer.get_stats(), "__dict__")
            else rate_analyzer.get_stats(),
            "bot_like_ips": rate_analyzer.get_bot_like_ips(limit=10),
        }
    except Exception as exc:
        return {"error": str(exc)}


# ── IP reputation ──────────────────────────────────────────────────────────────

@router.get("/reputation/top")
async def top_reputation(limit: int = Query(default=10, ge=1, le=100)):
    """Return top IPs by reputation score."""
    try:
        from app.services.ip_reputation import ip_reputation
        return {
            "stats": ip_reputation.get_stats(),
            "top_offenders": ip_reputation.get_top_offenders(limit=limit),
        }
    except Exception as exc:
        return {"error": str(exc)}


# ── Content policy ─────────────────────────────────────────────────────────────

@router.get("/content-policy")
async def content_policy_diagnostics():
    """List all registered content policies and engine stats."""
    try:
        from app.services.content_policy import content_policy_engine
        return {
            "stats": content_policy_engine.get_stats(),
            "policies": content_policy_engine.list_policies(),
        }
    except Exception as exc:
        return {"error": str(exc)}


# ── Classifier diagnostics ─────────────────────────────────────────────────────

@router.get("/classifier/stats")
async def classifier_diagnostics():
    """Return prompt intent classifier distribution stats."""
    try:
        from app.services.prompt_classifier import prompt_classifier
        return prompt_classifier.get_stats()
    except Exception as exc:
        return {"error": str(exc)}


# ── Signer stats ───────────────────────────────────────────────────────────────

@router.get("/signer/stats")
async def signer_diagnostics():
    """Return request signer statistics."""
    try:
        from app.services.request_signer import request_signer
        return request_signer.get_stats()
    except Exception as exc:
        return {"error": str(exc)}


# ── Full snapshot ──────────────────────────────────────────────────────────────

@router.get("/full")
async def full_diagnostics():
    """
    Aggregated full diagnostics snapshot from all defense modules.
    Safe to expose internally — no secrets or PII included.
    """
    snapshot: dict = {"ts": time.time(), "modules": {}}

    for name, module_path, attr in _MODULES:
        try:
            mod = __import__(module_path, fromlist=[attr])
            obj = getattr(mod, attr, None)
            if obj and hasattr(obj, "get_stats"):
                snapshot["modules"][name] = obj.get_stats()
            else:
                snapshot["modules"][name] = {"status": "available"}
        except Exception as exc:
            snapshot["modules"][name] = {"error": str(exc)}

    healthy = sum(1 for v in snapshot["modules"].values() if "error" not in v)
    snapshot["summary"] = {
        "total_modules": len(_MODULES),
        "healthy": healthy,
        "degraded": len(_MODULES) - healthy,
    }
    return snapshot
