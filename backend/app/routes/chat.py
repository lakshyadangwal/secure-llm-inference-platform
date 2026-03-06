"""
Commit 16 (part): Chat route
Direct LLM chat endpoint — wraps OllamaService.
"""

import time
import logging
from fastapi import APIRouter, HTTPException
from app.models.schemas import ChatRequest, ChatResponse
from app.services.ollama_service import ollama_service
from app.services.stats_store import new_request_id

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Chat"])


@router.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """
    Direct chat endpoint — sends prompt straight to Ollama (no security filter).
    Used by the Direct Neural Link tab in the frontend.
    """
    rid = new_request_id()
    logger.info(f"[{rid}] 💬 /chat request")

    try:
        response_text = ollama_service.call(request.prompt)
        logger.info(f"[{rid}] ✅ /chat success  ({len(response_text)} chars)")
        return ChatResponse(
            response=response_text,
            status="success",
            model=ollama_service.model,
            timestamp=time.time(),
            request_id=rid,
        )
    except RuntimeError as exc:
        logger.error(f"[{rid}] ❌ /chat error: {exc}")
        raise HTTPException(status_code=500, detail=f"LLM Error: {exc}")
