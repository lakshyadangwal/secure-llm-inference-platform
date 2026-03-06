"""
Commit 17: feat: add Pydantic response models for all endpoints
Typed request and response schemas used by every route.
"""

from pydantic import BaseModel, Field
from typing import Optional


# ──────────────────────────────────────────────
# REQUEST MODELS
# ──────────────────────────────────────────────

class ChatRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=4096, description="User prompt")


class PromptRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=4096, description="Prompt to analyze")
    security_enabled: bool = Field(True, description="Toggle security layer on/off")


class StatsResetRequest(BaseModel):
    confirm: bool = Field(False, description="Must be true to confirm reset")


# ──────────────────────────────────────────────
# RESPONSE MODELS
# ──────────────────────────────────────────────

class StatsSnapshot(BaseModel):
    totalAttempts: int
    totalBlocked: int
    totalLeaked: int
    blockRate: float
    perThreatType: dict[str, int] = {}


class ThreatResult(BaseModel):
    is_threat: bool
    threat_type: str
    severity_score: float = 0.0
    matched_pattern: Optional[str] = None


class ChatResponse(BaseModel):
    response: str
    status: str = "success"
    model: str
    timestamp: float
    request_id: str


class PromptResponse(BaseModel):
    response: str
    breach_detected: bool
    threat_type: str
    severity_score: float
    security_enabled: bool
    model: str
    stats: StatsSnapshot
    request_id: str


class StatsResponse(BaseModel):
    totalAttempts: int
    totalBlocked: int
    totalLeaked: int
    blockRate: float
    uptime: str
    neuralLoad: int
    memoryMatrix: int
    synapticLatency: int
    model: str
    perThreatType: dict[str, int] = {}


class HealthResponse(BaseModel):
    status: str
    ollama: str
    model: str
    timestamp: float


class DeepHealthResponse(BaseModel):
    status: str
    ollama: str
    model: str
    timestamp: float
    disk_free_mb: float
    memory_used_percent: float
    log_file_size_kb: float
    uptime_seconds: float


class LogsResponse(BaseModel):
    logs: list[str]


class TestAttackResponse(BaseModel):
    total_tests: int
    passed: int
    failed: int
    results: list[dict]
