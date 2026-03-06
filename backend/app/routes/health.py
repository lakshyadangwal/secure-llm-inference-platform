"""
Commits 16 & 19 (part): Logs route
GET /api/logs     — recent log lines
GET /health       — basic health check
GET /health/deep  — full system diagnostics (commit 19)
GET /             — root info
"""

import os
import time
import shutil
import logging
import psutil
from fastapi import APIRouter
from app.models.schemas import HealthResponse, DeepHealthResponse, LogsResponse
from app.services.ollama_service import ollama_service
from app.services.logging_setup import get_log_file
from app.services.stats_store import uptime_seconds

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Health & Logs"])


@router.get("/")
async def root():
    """Root endpoint with service metadata."""
    return {
        "service": "Neuro-Sentry Defense API",
        "version": "3.0.0",
        "status": "online",
        "model": ollama_service.model,
    }


@router.get("/health", response_model=HealthResponse)
async def health():
    """Basic health check — confirms backend and Ollama are reachable."""
    return HealthResponse(
        status="online",
        ollama="online" if ollama_service.is_available() else "offline",
        model=ollama_service.model,
        timestamp=time.time(),
    )


@router.get("/health/deep", response_model=DeepHealthResponse)
async def deep_health():
    """
    Commit 19: Full system diagnostics.
    Returns disk space, memory usage, log file size, and uptime.
    """
    log_file = get_log_file()
    log_size_kb = 0.0
    if log_file and os.path.exists(log_file):
        log_size_kb = round(os.path.getsize(log_file) / 1024, 2)

    disk = shutil.disk_usage("/")
    disk_free_mb = round(disk.free / (1024 * 1024), 1)

    try:
        mem = psutil.virtual_memory()
        memory_used_percent = mem.percent
    except Exception:
        memory_used_percent = 0.0

    return DeepHealthResponse(
        status="online",
        ollama="online" if ollama_service.is_available() else "offline",
        model=ollama_service.model,
        timestamp=time.time(),
        disk_free_mb=disk_free_mb,
        memory_used_percent=memory_used_percent,
        log_file_size_kb=log_size_kb,
        uptime_seconds=uptime_seconds(),
    )


@router.get("/api/logs", response_model=LogsResponse)
async def get_logs(limit: int = 50):
    """Return the most recent `limit` lines from the active log file."""
    log_file = get_log_file()
    try:
        if log_file and os.path.exists(log_file):
            with open(log_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
            return LogsResponse(logs=[line.strip() for line in lines[-limit:]])
        return LogsResponse(logs=["No log file available yet."])
    except Exception as exc:
        return LogsResponse(logs=[f"Error reading logs: {exc}"])
