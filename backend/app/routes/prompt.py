"""
Commit 16 (part): Prompt analysis route
Security-filtered prompt endpoint with full breach detection.
"""

import time
import logging
from fastapi import APIRouter, HTTPException
from app.models.schemas import PromptRequest, PromptResponse, StatsSnapshot
from app.services.security_service import check_for_threats
from app.services.ollama_service import ollama_service
from app.services.stats_store import new_request_id, increment_attempt, get_stats

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Prompt"])

BLOCKED_MESSAGE = (
    "I appreciate your interest, but I cannot fulfill this request. "
    "It appears to attempt circumventing my safety guidelines. "
    "I'm designed to be helpful, harmless, and honest."
)


@router.post("/api/prompt", response_model=PromptResponse)
async def analyze_prompt(request: PromptRequest):
    """
    Analyze a prompt through the security pipeline.
    Returns threat analysis, LLM response, and updated stats.
    """
    rid = new_request_id()
    logger.info(f"[{rid}] 🧪 /api/prompt  security={'ON' if request.security_enabled else 'OFF'}")

    threat = check_for_threats(request.prompt)
    breach_detected = False
    response_text = ""

    if request.security_enabled:
        if threat.is_threat:
            # Threat blocked
            response_text = BLOCKED_MESSAGE
            breach_detected = False
            increment_attempt(blocked=True, threat_type=threat.threat_type)
            logger.info(f"[{rid}] 🛡️  BLOCKED — type={threat.threat_type}  score={threat.severity_score}")
        else:
            # Safe request — forward to LLM
            increment_attempt(blocked=True, threat_type="none")
            try:
                response_text = ollama_service.call(request.prompt)
                logger.info(f"[{rid}] ✅ SAFE — responded with {len(response_text)} chars")
            except RuntimeError as exc:
                response_text = f"Error processing request: {exc}"
                logger.error(f"[{rid}] ❌ LLM error: {exc}")
    else:
        # Security OFF
        if threat.is_threat:
            breach_detected = True
            increment_attempt(blocked=False, threat_type=threat.threat_type)
            logger.warning(f"[{rid}] ⚠️  BREACH — security OFF  type={threat.threat_type}")
            try:
                response_text = ollama_service.call(request.prompt)
            except RuntimeError:
                response_text = (
                    "⚠️ SECURITY BREACH DETECTED ⚠️\n\n"
                    "System safeguards offline. Malicious prompt accepted.\n"
                    f"Threat type: {threat.threat_type}\n\n"
                    "In a real scenario, this would expose sensitive data."
                )
        else:
            increment_attempt(blocked=True, threat_type="none")
            try:
                response_text = ollama_service.call(request.prompt)
                logger.info(f"[{rid}] ✅ SAFE (security off)")
            except RuntimeError as exc:
                response_text = f"Error: {exc}"

    s = get_stats()
    return PromptResponse(
        response=response_text,
        breach_detected=breach_detected,
        threat_type=threat.threat_type,
        severity_score=threat.severity_score,
        security_enabled=request.security_enabled,
        model=ollama_service.model,
        stats=StatsSnapshot(
            totalAttempts=s["total_attempts"],
            totalBlocked=s["total_blocked"],
            totalLeaked=s["total_leaked"],
            blockRate=s["block_rate"],
            perThreatType=s["per_threat_type"],
        ),
        request_id=rid,
    )
