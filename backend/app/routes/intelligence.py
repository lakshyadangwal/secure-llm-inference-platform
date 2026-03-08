"""
Commit 60: Intelligence Route
================================
FastAPI router exposing threat intelligence and reporting endpoints.
Aggregates data from the new defense modules in this batch.

Endpoints:
  GET /api/intel/fingerprints         — top repeated payload fingerprints
  GET /api/intel/entropy/stats        — entropy analyzer statistics
  GET /api/intel/budget/top           — top token consumers
  GET /api/intel/budget/{ip}          — specific IP budget status
  GET /api/intel/watchlist            — list all watchlist entries
  GET /api/intel/watchlist/stats      — watchlist hit statistics
  POST /api/intel/watchlist           — add custom watchlist entry
  DELETE /api/intel/watchlist/{id}    — remove watchlist entry
  GET /api/intel/report/hourly        — generate and return hourly report
  GET /api/intel/report/daily         — generate and return daily report
  POST /api/intel/report/custom       — generate custom window report
  GET /api/intel/access/keys          — list all API keys (admin)
  POST /api/intel/access/keys         — create a new API key (admin)
  GET /api/intel/access/stats         — RBAC statistics
"""

import logging
from typing import Optional

from fastapi import APIRouter, Query, Body, HTTPException

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/intel", tags=["Threat Intelligence Extended"])


# ── Payload Fingerprinter ──────────────────────────────────────────────────────

@router.get("/fingerprints")
async def top_fingerprints(limit: int = Query(default=10, ge=1, le=50)):
    """Return the most-repeated payload fingerprints seen by the system."""
    try:
        from app.services.payload_fingerprinter import payload_fingerprinter
        return {
            "top_repeated": payload_fingerprinter.get_top_repeated(limit=limit),
            "stats": payload_fingerprinter.get_stats(),
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/fingerprints/probe")
async def probe_fingerprint(prompt: str = Body(embed=True)):
    """Compute a fingerprint for a test prompt and check for known attacks."""
    try:
        from app.services.payload_fingerprinter import payload_fingerprinter
        result = payload_fingerprinter.fingerprint(prompt, ip="probe")
        return result.to_dict()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ── Entropy Analyzer ───────────────────────────────────────────────────────────

@router.get("/entropy/stats")
async def entropy_stats():
    """Return entropy analyzer statistics."""
    try:
        from app.services.entropy_analyzer import entropy_analyzer
        return entropy_analyzer.get_stats()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/entropy/probe")
async def entropy_probe(text: str = Body(embed=True)):
    """Run entropy analysis on a test input."""
    try:
        from app.services.entropy_analyzer import entropy_analyzer
        result = entropy_analyzer.analyze(text)
        return result.to_dict()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ── Token Budget Manager ───────────────────────────────────────────────────────

@router.get("/budget/top")
async def top_token_consumers(limit: int = Query(default=10, ge=1, le=50)):
    """Return the top token-consuming IPs."""
    try:
        from app.services.token_budget_manager import token_budget_manager
        return {
            "top_consumers": token_budget_manager.get_top_consumers(limit=limit),
            "stats": token_budget_manager.get_stats(),
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/budget/{ip}")
async def get_ip_budget(ip: str):
    """Return the token budget status for a specific IP."""
    try:
        from app.services.token_budget_manager import token_budget_manager
        budget = token_budget_manager.get_budget(ip)
        if budget is None:
            raise HTTPException(status_code=404, detail=f"No budget record for IP: {ip}")
        return budget
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ── Keyword Watchlist ──────────────────────────────────────────────────────────

@router.get("/watchlist")
async def list_watchlist(category: Optional[str] = None):
    """List all watchlist entries, optionally filtered by category."""
    try:
        from app.services.keyword_watchlist import keyword_watchlist
        return {
            "entries": keyword_watchlist.list_entries(category=category),
            "stats": keyword_watchlist.get_stats(),
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/watchlist/stats")
async def watchlist_stats():
    """Return keyword watchlist statistics."""
    try:
        from app.services.keyword_watchlist import keyword_watchlist
        return keyword_watchlist.get_stats()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/watchlist")
async def add_watchlist_entry(
    entry_id: str = Body(embed=False),
    term: str = Body(embed=False),
    mode: str = Body(default="substring"),
    severity: str = Body(default="medium"),
    action: str = Body(default="warn"),
    category: str = Body(default="custom"),
    expires_in_seconds: Optional[float] = Body(default=None),
):
    """Add a custom entry to the keyword watchlist."""
    try:
        from app.services.keyword_watchlist import (
            keyword_watchlist, MatchMode, WatchSeverity, WatchAction
        )
        try:
            match_mode = MatchMode(mode)
            watch_sev = WatchSeverity(severity)
            watch_action = WatchAction(action)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

        entry = keyword_watchlist.add(
            entry_id=entry_id,
            term=term,
            mode=match_mode,
            severity=watch_sev,
            action=watch_action,
            category=category,
            expires_in_seconds=expires_in_seconds,
        )
        return {
            "status": "added",
            "entry_id": entry.entry_id,
            "term": entry.term,
            "mode": entry.mode.value,
            "severity": entry.severity.value,
            "action": entry.action.value,
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.delete("/watchlist/{entry_id}")
async def remove_watchlist_entry(entry_id: str):
    """Remove a watchlist entry by its ID."""
    try:
        from app.services.keyword_watchlist import keyword_watchlist
        removed = keyword_watchlist.remove(entry_id)
        if not removed:
            raise HTTPException(status_code=404, detail=f"Entry not found: {entry_id}")
        return {"status": "removed", "entry_id": entry_id}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/watchlist/probe")
async def probe_watchlist(text: str = Body(embed=True)):
    """Test a text against the watchlist without recording a hit."""
    try:
        from app.services.keyword_watchlist import keyword_watchlist
        result = keyword_watchlist.evaluate(text)
        return result.to_dict()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ── Threat Reporter ────────────────────────────────────────────────────────────

@router.get("/report/hourly")
async def hourly_report():
    """Generate and return a threat report for the last hour."""
    try:
        from app.services.threat_reporter import threat_reporter
        report = threat_reporter.hourly_report()
        return report.to_dict()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/report/daily")
async def daily_report():
    """Generate and return a threat report for the last 24 hours."""
    try:
        from app.services.threat_reporter import threat_reporter
        report = threat_reporter.daily_report()
        return report.to_dict()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/report/custom")
async def custom_report(window_hours: float = Body(default=1.0)):
    """Generate a threat report for a custom time window."""
    try:
        from app.services.threat_reporter import threat_reporter
        if window_hours <= 0 or window_hours > 168:
            raise HTTPException(status_code=400, detail="window_hours must be 0-168")
        report = threat_reporter.generate_report(
            window_seconds=window_hours * 3600.0,
            label="custom",
        )
        return report.to_dict()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/report/history")
async def report_history():
    """Return the list of recently generated reports."""
    try:
        from app.services.threat_reporter import threat_reporter
        return {"history": threat_reporter.get_report_history()}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ── Access Controller (RBAC) ───────────────────────────────────────────────────

@router.get("/access/stats")
async def access_stats():
    """Return RBAC access controller statistics."""
    try:
        from app.services.access_controller import access_controller
        return access_controller.get_stats()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/access/keys")
async def list_access_keys():
    """List all API keys (hashed names, roles, usage stats)."""
    try:
        from app.services.access_controller import access_controller
        return {"keys": access_controller.list_keys()}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/access/keys")
async def create_access_key(
    name: str = Body(embed=False),
    role: str = Body(default="readonly"),
):
    """Create a new API key with a role. Returns the raw key (shown once)."""
    try:
        from app.services.access_controller import access_controller, Role
        try:
            role_enum = Role(role)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid role: {role}")
        raw_key = access_controller.create_key(name=name, role=role_enum)
        return {"status": "created", "name": name, "role": role, "key": raw_key}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
