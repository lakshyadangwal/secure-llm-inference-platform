"""
Commits 12 & 16 (part): Stats route
GET /api/stats — return current stats
POST /api/stats/reset — reset stats (commit 12)
"""

import logging
import time
from fastapi import APIRouter, HTTPException
from app.models.schemas import StatsResponse, StatsResetRequest
from app.services.stats_store import get_stats, reset_stats, uptime_seconds
from app.services.ollama_service import ollama_service

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Stats"])


@router.get("/api/stats", response_model=StatsResponse)
async def get_stats_endpoint():
    """Return current system statistics including per-threat-type breakdown."""
    s = get_stats()
    return StatsResponse(
        totalAttempts=s["total_attempts"],
        totalBlocked=s["total_blocked"],
        totalLeaked=s["total_leaked"],
        blockRate=s["block_rate"],
        uptime="99.97%",
        neuralLoad=42,
        memoryMatrix=68,
        synapticLatency=3,
        model=ollama_service.model,
        perThreatType=s["per_threat_type"],
    )


@router.post("/api/stats/reset")
async def reset_stats_endpoint(body: StatsResetRequest):
    """
    Commit 12: Reset all in-memory statistics.
    Requires body: {"confirm": true} to protect against accidental resets.
    """
    if not body.confirm:
        raise HTTPException(
            status_code=400,
            detail="Set 'confirm': true in the request body to reset stats.",
        )
    reset_stats()
    logger.warning("📊 Stats have been manually reset via /api/stats/reset")
    return {
        "message": "Stats reset successfully.",
        "timestamp": time.time(),
    }
