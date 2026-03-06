"""
Commit 32: Defense Metrics Aggregator
=======================================
Aggregates metrics from all defense modules into a single dashboard payload.
Combines data from:
  - Stats store (request counts, block rate)
  - DLP engine (output scan results)
  - Threat cache (hit rate, evictions)
  - Anomaly detector (IP risk levels)
  - Input sanitizer (transform frequency)
  - Circuit breaker (Ollama health)
  - Context guard (overflow attempts)
  - Observability module (uptime, logging)

Consumed by GET /api/defense/metrics
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class DefenseMetricsSnapshot:
    """Full point-in-time snapshot of all defense subsystem metrics."""
    generated_at: float = field(default_factory=time.time)
    # Core stats
    total_requests: int = 0
    total_blocked: int = 0
    total_leaked: int = 0
    block_rate_pct: float = 0.0
    uptime_seconds: float = 0.0
    # Per-subsystem
    threat_cache: dict = field(default_factory=dict)
    dlp: dict = field(default_factory=dict)
    anomaly: dict = field(default_factory=dict)
    sanitizer: dict = field(default_factory=dict)
    circuit_breaker: dict = field(default_factory=dict)
    context_guard: dict = field(default_factory=dict)
    per_threat_type: dict = field(default_factory=dict)
    # Health summary
    overall_health: str = "healthy"
    health_issues: list[str] = field(default_factory=list)


class DefenseMetrics:
    """
    Aggregator that pulls live stats from every defense module and
    computes an overall health status for the platform.
    """

    def __init__(self) -> None:
        self._snapshots_generated = 0
        logger.info("📊 DefenseMetrics aggregator ready")

    def collect(self) -> DefenseMetricsSnapshot:
        """
        Pull metrics from every module and build a unified snapshot.
        Gracefully handles any module import failures.
        """
        self._snapshots_generated += 1
        snap = DefenseMetricsSnapshot()
        health_issues: list[str] = []

        # ── Core stats ─────────────────────────────────────────────────────────
        try:
            from app.services.stats_store import get_stats, uptime_seconds
            core = get_stats()
            snap.total_requests = int(core.get("total_attempts", 0))
            snap.total_blocked  = int(core.get("total_blocked", 0))
            snap.total_leaked   = int(core.get("total_leaked", 0))
            snap.block_rate_pct = float(core.get("block_rate", 0.0))
            snap.per_threat_type = dict(core.get("per_threat_type", {}))
            snap.uptime_seconds = uptime_seconds()
        except Exception as exc:
            health_issues.append(f"stats_store_error: {exc}")

        # ── Threat cache ───────────────────────────────────────────────────────
        try:
            from app.services.threat_cache import threat_cache
            snap.threat_cache = threat_cache.get_stats()
            if snap.threat_cache.get("hit_rate_pct", 100) < 10 and snap.total_requests > 50:
                health_issues.append("low_cache_hit_rate")
        except Exception as exc:
            snap.threat_cache = {"error": str(exc)}

        # ── DLP engine ─────────────────────────────────────────────────────────
        try:
            from app.services.dlp_engine import dlp_engine
            snap.dlp = dlp_engine.get_stats()
            if float(snap.dlp.get("leak_rate", 0)) > 5.0:
                health_issues.append("high_dlp_leak_rate")
        except Exception as exc:
            snap.dlp = {"error": str(exc)}

        # ── Anomaly detector ───────────────────────────────────────────────────
        try:
            from app.services.anomaly_detector import anomaly_detector
            snap.anomaly = anomaly_detector.get_stats()
            if float(snap.anomaly.get("anomaly_rate_pct", 0)) > 20.0:
                health_issues.append("high_anomaly_rate")
        except Exception as exc:
            snap.anomaly = {"error": str(exc)}

        # ── Input sanitizer ────────────────────────────────────────────────────
        try:
            from app.services.input_sanitizer import input_sanitizer
            snap.sanitizer = input_sanitizer.get_stats()
            if float(snap.sanitizer.get("flag_rate_pct", 0)) > 30.0:
                health_issues.append("high_sanitizer_flag_rate")
        except Exception as exc:
            snap.sanitizer = {"error": str(exc)}

        # ── Circuit breaker ────────────────────────────────────────────────────
        try:
            from app.services.circuit_breaker import ollama_circuit_breaker
            snap.circuit_breaker = ollama_circuit_breaker.get_stats()
            if snap.circuit_breaker.get("state") == "open":
                health_issues.append("ollama_circuit_open")
            if float(snap.circuit_breaker.get("failure_rate_pct", 0)) > 20.0:
                health_issues.append("high_ollama_failure_rate")
        except Exception as exc:
            snap.circuit_breaker = {"error": str(exc)}

        # ── Context guard ──────────────────────────────────────────────────────
        try:
            from app.services.context_guard import context_guard
            snap.context_guard = context_guard.get_stats()
            if float(snap.context_guard.get("violation_rate_pct", 0)) > 15.0:
                health_issues.append("high_context_violation_rate")
        except Exception as exc:
            snap.context_guard = {"error": str(exc)}

        # ── Overall health ─────────────────────────────────────────────────────
        snap.health_issues = health_issues
        if len(health_issues) == 0:
            snap.overall_health = "healthy"
        elif len(health_issues) <= 2:
            snap.overall_health = "degraded"
        else:
            snap.overall_health = "critical"

        if health_issues:
            logger.warning(
                "⚠️  Defense health: %s — issues: %s",
                snap.overall_health, health_issues
            )

        return snap

    def to_dict(self) -> dict:
        """Return metrics as a plain dict suitable for JSON serialisation."""
        snap = self.collect()
        return {
            "generated_at": snap.generated_at,
            "overall_health": snap.overall_health,
            "health_issues": snap.health_issues,
            "core": {
                "total_requests": snap.total_requests,
                "total_blocked": snap.total_blocked,
                "total_leaked": snap.total_leaked,
                "block_rate_pct": snap.block_rate_pct,
                "uptime_seconds": snap.uptime_seconds,
                "per_threat_type": snap.per_threat_type,
            },
            "threat_cache": snap.threat_cache,
            "dlp": snap.dlp,
            "anomaly_detector": snap.anomaly,
            "input_sanitizer": snap.sanitizer,
            "circuit_breaker": snap.circuit_breaker,
            "context_guard": snap.context_guard,
            "meta": {
                "snapshots_generated": self._snapshots_generated,
            },
        }


# ── Singleton ──────────────────────────────────────────────────────────────────
defense_metrics = DefenseMetrics()
