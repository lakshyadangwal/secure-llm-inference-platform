import logging
from typing import List, Dict, Any
from datetime import datetime, timedelta
import random

logger = logging.getLogger(__name__)

class AnalyticsService:
    """
    Service to track and simulate platform usage and security analytics.
    In a real app, this would write to ClickHouse, Postgres, or Elasticsearch.
    Here we store in memory and generate mock data for missing periods.
    """
    def __init__(self):
        self.usage_metrics = []
        self.security_events = []
        self._generate_mock_history()

    def _generate_mock_history(self):
        """Generate some past 24h data to make the dashboard look alive"""
        now = datetime.utcnow()
        for i in range(24 * 60): # Every minute for last 24h
            ts = now - timedelta(minutes=i)
            # Add some general requests
            if random.random() < 0.3:
                self.usage_metrics.append({
                    "timestamp": ts,
                    "model": "llama3.1:latest",
                    "tokens_prompt": random.randint(10, 500),
                    "tokens_completion": random.randint(20, 1000),
                    "latency_ms": random.uniform(200.0, 3000.0)
                })
            # Add some security events
            if random.random() < 0.05:
                event_types = ["PII_BLOCKED", "JAILBREAK_ATTEMPT", "TOXICITY_DETECTED"]
                self.security_events.append({
                    "timestamp": ts,
                    "event_type": random.choice(event_types),
                    "severity": random.choice(["warning", "critical"]),
                    "details": "Mock historical event"
                })

    def track_usage(self, model: str, prompt_tokens: int, completion_tokens: int, latency_ms: float):
        self.usage_metrics.append({
            "timestamp": datetime.utcnow(),
            "model": model,
            "tokens_prompt": prompt_tokens,
            "tokens_completion": completion_tokens,
            "latency_ms": latency_ms
        })

    def track_security_event(self, event_type: str, severity: str, details: str):
        self.security_events.append({
            "timestamp": datetime.utcnow(),
            "event_type": event_type,
            "severity": severity,
            "details": details
        })
        logger.warning(f"🚨 Security Event Tracked: {event_type} - {severity}")

    def get_summary_stats(self) -> Dict[str, Any]:
        return {
            "total_requests": len(self.usage_metrics),
            "total_tokens": sum(m["tokens_prompt"] + m["tokens_completion"] for m in self.usage_metrics),
            "avg_latency": sum(m["latency_ms"] for m in self.usage_metrics) / max(len(self.usage_metrics), 1),
            "security_incidents": len(self.security_events),
            "active_users": 15 # Mock active users
        }

    def get_usage_timeseries(self, hours: int = 24) -> List[Dict[str, Any]]:
        # Bucket metrics by hour
        buckets = {}
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        for m in self.usage_metrics:
            if m["timestamp"] > cutoff:
                bucket_key = m["timestamp"].strftime("%Y-%m-%d %H:00")
                buckets[bucket_key] = buckets.get(bucket_key, 0) + 1
                
        # Format for charts
        return [{"timestamp": k, "value": v} for k, v in sorted(buckets.items())]

analytics_service = AnalyticsService()
