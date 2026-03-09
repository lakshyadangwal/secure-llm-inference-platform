import pytest
from app.services.analytics import analytics_service

def test_analytics_usage_recording():
    initial_summary = analytics_service.get_summary()
    initial_reqs = initial_summary.total_requests
    
    analytics_service.record_usage(tokens=150, latency_ms=120)
    
    new_summary = analytics_service.get_summary()
    assert new_summary.total_requests == initial_reqs + 1
    assert new_summary.total_tokens >= 150

def test_analytics_security_event_recording():
    initial_summary = analytics_service.get_summary()
    initial_incidents = initial_summary.security_incidents
    
    analytics_service.record_security_event(event_type="PII_LEAK", severity="high", details="Test leak")
    
    new_summary = analytics_service.get_summary()
    assert new_summary.security_incidents == initial_incidents + 1
