"""
Commit 73: Security Dashboard API Route
==========================================
FastAPI router exposing a unified security dashboard endpoint that
aggregates live stats from all batch-3 defense modules.

Endpoints:
  GET  /api/security/dashboard          — full dashboard snapshot
  GET  /api/security/modules            — list all module names + status
  GET  /api/security/module/{name}      — single module stats
  POST /api/security/scan               — on-demand text scan through all modules
  POST /api/security/policy/evaluate    — evaluate a list of module signals
  POST /api/security/blocklist/{ip}     — add IP to policy blocklist
  DELETE /api/security/blocklist/{ip}   — remove IP from policy blocklist
  GET  /api/security/keyword-engine     — keyword engine stats + categories
  GET  /api/security/rate-limiter/{ip}  — rate limit status for a specific IP
"""

import logging
import time
from typing import Any, Optional

try:
    from fastapi import APIRouter, HTTPException, Path, Body  # type: ignore[import]
    from pydantic import BaseModel  # type: ignore[import]
except ImportError:  # pragma: no cover — handled at runtime
    raise

from app.services.obfuscation_detector import obfuscation_detector
from app.services.social_engineering_detector import social_engineering_detector
from app.services.output_filter import output_filter
from app.services.jailbreak_pattern_db import jailbreak_pattern_db
from app.services.adaptive_rate_limiter import adaptive_rate_limiter
from app.services.request_validator import request_validator
from app.services.defense_keyword_engine import defense_keyword_engine
from app.services.security_policy_enforcer import (
    security_policy_enforcer, ModuleSignal,
)
from app.services.language_threat_detector import language_threat_detector
from app.services.threat_pattern_library import scan_text, get_categories, get_pattern_count

router = APIRouter(prefix="/api/security", tags=["security-dashboard"])
logger = logging.getLogger(__name__)


# ── Request / response models ──────────────────────────────────────────────────

class ScanRequest(BaseModel):
    text: str
    include_output_filter: bool = False  # output filter needs an LLM response


class PolicyEvalRequest(BaseModel):
    signals: list[dict[str, Any]]   # [{module_name, risk_score, weight?, detail?}]
    ip: Optional[str] = None


class BlocklistRequest(BaseModel):
    reason: Optional[str] = None


# ── Helpers ────────────────────────────────────────────────────────────────────

def _collect_all_stats() -> dict[str, Any]:
    stats: dict[str, Any] = {}
    collectors: list[tuple[str, Any]] = [
        ("obfuscation_detector",       obfuscation_detector.get_stats),
        ("social_engineering_detector", social_engineering_detector.get_stats),
        ("output_filter",              output_filter.get_stats),
        ("jailbreak_pattern_db",       jailbreak_pattern_db.get_stats),
        ("adaptive_rate_limiter",      adaptive_rate_limiter.get_stats),
        ("request_validator",          request_validator.get_stats),
        ("defense_keyword_engine",     defense_keyword_engine.get_stats),
        ("security_policy_enforcer",   security_policy_enforcer.get_stats),
        ("language_threat_detector",   language_threat_detector.get_stats),
        ("threat_pattern_library",     lambda: {
            "total_patterns": get_pattern_count(),
            "categories": get_categories(),
        }),
    ]
    for name, fn in collectors:
        try:
            stats[name] = fn()
        except Exception as exc:  # pragma: no cover
            stats[name] = {"error": str(exc)}
    return stats


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.get("/dashboard")
async def get_dashboard() -> dict:
    """Full security dashboard — aggregated stats from all batch-3 modules."""
    ts = time.time()
    module_stats = _collect_all_stats()
    return {
        "status": "ok",
        "timestamp": ts,
        "module_count": len(module_stats),
        "modules": module_stats,
    }


@router.get("/modules")
async def list_modules() -> dict:
    """List all batch-3 defense modules and their availability."""
    modules = [
        "obfuscation_detector",
        "social_engineering_detector",
        "output_filter",
        "jailbreak_pattern_db",
        "adaptive_rate_limiter",
        "request_validator",
        "defense_keyword_engine",
        "security_policy_enforcer",
        "language_threat_detector",
        "threat_pattern_library",
    ]
    return {"modules": modules, "count": len(modules)}


@router.get("/module/{name}")
async def get_module_stats(name: str = Path(..., description="Module name")) -> dict:
    """Get stats for a single defense module."""
    all_stats = _collect_all_stats()
    if name not in all_stats:
        raise HTTPException(status_code=404, detail=f"Module '{name}' not found")
    return {"module": name, "stats": all_stats[name]}


@router.post("/scan")
async def scan_text_endpoint(req: ScanRequest) -> dict:
    """
    Run all batch-3 defense scanners on a text string.
    Returns aggregated risk scores from each module.
    """
    text = req.text
    if not text or not text.strip():
        raise HTTPException(status_code=400, detail="text must not be empty")
    if len(text) > 32_768:
        raise HTTPException(status_code=400, detail="text exceeds 32 KB limit")

    start = time.time()
    results: dict[str, Any] = {}

    # Obfuscation
    try:
        results["obfuscation"] = obfuscation_detector.analyze(text).to_dict()
    except Exception as e:  # pragma: no cover
        results["obfuscation"] = {"error": str(e)}

    # Social Engineering
    try:
        results["social_engineering"] = social_engineering_detector.analyze(text).to_dict()
    except Exception as e:
        results["social_engineering"] = {"error": str(e)}

    # Jailbreak
    try:
        results["jailbreak"] = jailbreak_pattern_db.scan(text).to_dict()
    except Exception as e:
        results["jailbreak"] = {"error": str(e)}

    # Keyword Engine
    try:
        results["keyword_engine"] = defense_keyword_engine.score(text).to_dict()
    except Exception as e:
        results["keyword_engine"] = {"error": str(e)}

    # Language Threat
    try:
        results["language_threat"] = language_threat_detector.analyze(text).to_dict()
    except Exception as e:
        results["language_threat"] = {"error": str(e)}

    # Threat Pattern Library
    try:
        matches = scan_text(text)
        results["threat_patterns"] = {
            "match_count": len(matches),
            "categories": list({m.category for m in matches}),
            "highest_severity": max((m.severity.value for m in matches), default=None),
        }
    except Exception as e:
        results["threat_patterns"] = {"error": str(e)}

    # Output filter (optional)
    if req.include_output_filter:
        try:
            results["output_filter"] = output_filter.filter(text).to_dict()
        except Exception as e:
            results["output_filter"] = {"error": str(e)}

    # Policy aggregation
    signals: list[ModuleSignal] = []
    for mod_name, key in [
        ("obfuscation_detector", "obfuscation"),
        ("social_engineering", "social_engineering"),
        ("jailbreak_scanner", "jailbreak"),
    ]:
        r = results.get(key, {})
        score = r.get("risk_score", 0.0) if isinstance(r, dict) else 0.0
        signals.append(ModuleSignal(module_name=mod_name, risk_score=float(score)))

    kw_r = results.get("keyword_engine", {})
    kw_score = kw_r.get("final_score", 0.0) if isinstance(kw_r, dict) else 0.0
    signals.append(ModuleSignal(module_name="keyword_watchlist", risk_score=float(kw_score)))

    policy_result = security_policy_enforcer.evaluate(signals)
    results["policy"] = policy_result.to_dict()

    elapsed_ms = float((time.time() - start) * 1000)
    return {
        "text_length": len(text),
        "scan_latency_ms": round(elapsed_ms, 2),
        "results": results,
    }


@router.post("/policy/evaluate")
async def evaluate_policy(req: PolicyEvalRequest) -> dict:
    """Evaluate a list of module signals through the security policy enforcer."""
    signals: list[ModuleSignal] = []
    for s in req.signals:
        signals.append(ModuleSignal(
            module_name=s.get("module_name", "unknown"),
            risk_score=float(s.get("risk_score", 0.0)),
            weight=float(s.get("weight", 1.0)),
            detail=s.get("detail", ""),
        ))
    result = security_policy_enforcer.evaluate(signals, ip=req.ip)
    return result.to_dict()


@router.post("/blocklist/{ip}")
async def add_to_blocklist(
    ip: str = Path(..., description="IP address to block"),
    body: BlocklistRequest = Body(default=BlocklistRequest()),
) -> dict:
    """Add an IP address to the policy hard-block list."""
    security_policy_enforcer.add_to_blocklist(ip)
    logger.warning("🛑 IP %s added to blocklist — reason: %s", ip, body.reason)
    return {"status": "blocked", "ip": ip, "reason": body.reason}


@router.delete("/blocklist/{ip}")
async def remove_from_blocklist(ip: str = Path(..., description="IP to unblock")) -> dict:
    """Remove an IP address from the policy block list."""
    security_policy_enforcer.remove_from_blocklist(ip)
    return {"status": "unblocked", "ip": ip}


@router.get("/keyword-engine")
async def keyword_engine_stats() -> dict:
    """Return keyword engine statistics and category list."""
    stats = defense_keyword_engine.get_stats()
    return {"stats": stats}


@router.get("/rate-limiter/{ip}")
async def rate_limiter_ip_info(ip: str = Path(..., description="IP address to query")) -> dict:
    """Get the current rate limit status for a specific IP."""
    info = adaptive_rate_limiter.get_ip_info(ip)
    if info is None:
        return {"ip": ip, "status": "no_history", "tier": "clean"}
    return info
