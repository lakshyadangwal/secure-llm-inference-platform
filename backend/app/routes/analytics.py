from fastapi import APIRouter, Depends, HTTPException
import logging

from app.models.analytics_schema import AnalyticsSummaryResponse, TimeSeriesResponse, SecurityEvent
from app.services.analytics import analytics_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/analytics", tags=["Analytics"])

@router.get("/summary", response_model=AnalyticsSummaryResponse)
async def get_analytics_summary():
    """Get high-level statistics for the dashboard"""
    return analytics_service.get_summary_stats()

@router.get("/timeseries/usage", response_model=TimeSeriesResponse)
async def get_usage_timeseries(hours: int = 24):
    """Get request/token usage over time"""
    data = analytics_service.get_usage_timeseries(hours=hours)
    return {"data": data}

@router.get("/security-events")
async def get_security_events(limit: int = 50):
    """Get recent security blocked events"""
    # Just returning the raw dicts from the service for now
    events = sorted(analytics_service.security_events, key=lambda x: x["timestamp"], reverse=True)
    return {"events": events[:limit]}
