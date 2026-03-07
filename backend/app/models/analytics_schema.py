from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime

class UsageMetric(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    model: str
    tokens_prompt: int
    tokens_completion: int
    latency_ms: float
    user_id: Optional[str] = None
    endpoint: str

class SecurityEvent(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event_type: str # "PII_BLOCKED", "JAILBREAK_ATTEMPT", "TOXICITY_DETECTED", "DLP_LEAK"
    severity: str # "info", "warning", "critical"
    details: str
    user_id: Optional[str] = None

class AnalyticsSummaryResponse(BaseModel):
    total_requests: int
    total_tokens: int
    avg_latency: float
    security_incidents: int
    active_users: int

class TimelinePoint(BaseModel):
    timestamp: str
    value: int

class TimeSeriesResponse(BaseModel):
    data: List[TimelinePoint]
