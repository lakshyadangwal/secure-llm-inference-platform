"""
Neuro-Sentry Defense Backend — main.py (refactored)
Ties together all routers, middleware, and lifecycle hooks.

Commits assembled here:
  16: split into routers
  10/11: rotating + JSON logging
  18: settings from env
  20: startup warm-up
  21: shutdown stats dump
   2: rate limiting middleware
"""

import json
import os
import time
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config.settings import settings
from app.services.logging_setup import setup_logging
from app.services.ollama_service import ollama_service
from app.services.stats_store import get_stats
from app.middleware.rate_limiter import RateLimitMiddleware

# Import all routers
from app.routes import chat, prompt, stats, health, test_attack

# ── Initialise logging first ───────────────────────────────────────────
log_file = setup_logging()
logger = logging.getLogger(__name__)

# ── FastAPI app ────────────────────────────────────────────────────────
app = FastAPI(
    title="Neuro-Sentry Defense API",
    description="Backend API for LLM security testing with multi-layer defense pipeline",
    version="3.0.0",
)

# ── Middleware ─────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RateLimitMiddleware)

# ── Register routers ───────────────────────────────────────────────────
app.include_router(health.router)
app.include_router(chat.router)
app.include_router(prompt.router)
app.include_router(stats.router)
app.include_router(test_attack.router)


# ── Lifecycle events ───────────────────────────────────────────────────

@app.on_event("startup")
async def startup_event():
    logger.info("=" * 60)
    logger.info("🛡️  NEURO-SENTRY DEFENSE BACKEND v3.0 STARTING")
    logger.info("=" * 60)
    logger.info(f"🤖 Ollama Model : {ollama_service.model}")
    logger.info(f"📝 Log file     : {log_file}")
    logger.info(f"🌐 CORS origins : {settings.CORS_ORIGINS}")
    logger.info(f"🔒 Rate limit   : {settings.RATE_LIMIT_PER_MINUTE} req/min")
    logger.info("=" * 60)
    # Commit 20: warm up the model
    ollama_service.warm_up()


@app.on_event("shutdown")
async def shutdown_event():
    """
    Commit 21: On shutdown dump final statistics to a JSON file in logs/.
    """
    if settings.STATS_DUMP_ON_SHUTDOWN:
        final_stats = get_stats()
        final_stats["shutdown_at"] = time.time()

        dump_dir = os.path.join(os.path.dirname(__file__), "..", "logs")
        os.makedirs(dump_dir, exist_ok=True)
        dump_path = os.path.join(dump_dir, "final_stats.json")

        with open(dump_path, "w", encoding="utf-8") as f:
            json.dump(final_stats, f, indent=2)

        logger.info(f"💾 Final stats written to: {dump_path}")
    logger.info("🛑 Neuro-Sentry backend shut down.")


# ── Dev entry point ────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=True,
    )
