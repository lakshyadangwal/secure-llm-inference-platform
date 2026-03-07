"""
Commit 36: Defense Orchestrator
================================
Central pipeline that chains ALL defense modules in the correct order
and produces a single unified decision for every incoming request.

Pipeline order (defense-in-depth):
  Stage 0  — Context Window Guard    (pre-filter, cheapest check)
  Stage 1  — Input Sanitizer         (clean raw text)
  Stage 2  — Threat Cache lookup     (skip re-scan if known)
  Stage 3  — Anomaly Detector check  (behavioural pre-filter)
  Stage 4  — Security Service        (core regex pipeline)
  Stage 5  — Behavioral Profiler     (update session profile)
  Stage 6  — Threat Cache store      (cache result)
  Stage 7  — Audit logger            (record security decision)

Each stage can BLOCK (short-circuit), WARN, or PASS.
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ── Decision model ────────────────────────────────────────────────────────────

@dataclass
class StageResult:
    stage: int
    name: str
    decision: str          # "block" | "warn" | "pass"
    reason: str
    duration_ms: float
    metadata: dict = field(default_factory=dict)


@dataclass
class OrchestratorDecision:
    """Full pipeline decision for one request."""
    request_id: str
    final_decision: str        # "block" | "warn" | "pass"
    blocked_at_stage: Optional[int]
    blocked_reason: str
    threat_type: str
    severity_score: float
    stages: list[StageResult] = field(default_factory=list)
    total_duration_ms: float = 0.0
    sanitized_prompt: str = ""
    is_anomalous: bool = False
    cache_hit: bool = False

    @property
    def is_blocked(self) -> bool:
        return self.final_decision == "block"

    @property
    def is_warned(self) -> bool:
        return self.final_decision == "warn"

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "final_decision": self.final_decision,
            "blocked_at_stage": self.blocked_at_stage,
            "blocked_reason": self.blocked_reason,
            "threat_type": self.threat_type,
            "severity_score": self.severity_score,
            "total_duration_ms": round(self.total_duration_ms, 2),
            "sanitized_prompt_length": len(self.sanitized_prompt),
            "is_anomalous": self.is_anomalous,
            "cache_hit": self.cache_hit,
            "stages": [
                {
                    "stage": s.stage,
                    "name": s.name,
                    "decision": s.decision,
                    "reason": s.reason,
                    "duration_ms": round(s.duration_ms, 2),
                    "metadata": s.metadata,
                }
                for s in self.stages
            ],
        }


# ── Metrics ───────────────────────────────────────────────────────────────────

@dataclass
class OrchestratorStats:
    total_evaluated: int = 0
    total_blocked: int = 0
    total_warned: int = 0
    total_passed: int = 0
    total_cache_hits: int = 0
    blocks_per_stage: dict[int, int] = field(default_factory=dict)
    avg_duration_ms: float = 0.0
    _duration_sum: float = 0.0


# ── Orchestrator ──────────────────────────────────────────────────────────────

class DefenseOrchestrator:
    """
    Runs every incoming prompt through the full layered defense pipeline.
    Designed to be the single entry point for all security decisions.
    """

    def __init__(
        self,
        anomaly_score_threshold: float = 0.5,
        block_on_anomaly: bool = False,
    ):
        self._anomaly_threshold = anomaly_score_threshold
        self._block_on_anomaly = block_on_anomaly
        self._stats = OrchestratorStats()
        logger.info("🎯 DefenseOrchestrator initialised")

    def _tick(self) -> float:
        return time.perf_counter()

    def _elapsed_ms(self, start: float) -> float:
        return (time.perf_counter() - start) * 1000

    # ── Individual stage runners ──────────────────────────────────────────────

    def _run_context_guard(self, prompt: str) -> StageResult:
        t = self._tick()
        try:
            from app.services.context_guard import context_guard
            result = context_guard.check(prompt)
            decision = "block" if result.is_violation else "pass"
            reason = ", ".join(result.violations) if result.violations else "ok"
            meta = {"violations": result.violations, "estimated_tokens": result.estimated_tokens}
        except Exception as exc:
            decision, reason, meta = "pass", f"stage_error: {exc}", {}
        return StageResult(0, "context_guard", decision, reason, self._elapsed_ms(t), meta)

    def _run_sanitizer(self, prompt: str) -> tuple[StageResult, str]:
        t = self._tick()
        sanitized = prompt
        try:
            from app.services.input_sanitizer import input_sanitizer
            result = input_sanitizer.sanitize(prompt)
            sanitized = result.sanitized_text
            decision = "warn" if result.flagged else "pass"
            reason = ", ".join(result.flag_reasons) if result.flag_reasons else "ok"
            meta = {"transforms": result.transforms_applied, "flags": result.flag_reasons}
        except Exception as exc:
            decision, reason, meta = "pass", f"stage_error: {exc}", {}
        return StageResult(1, "input_sanitizer", decision, reason, self._elapsed_ms(t), meta), sanitized

    def _run_cache_lookup(self, prompt: str) -> tuple[StageResult, bool, Optional[object]]:
        t = self._tick()
        try:
            from app.services.threat_cache import threat_cache
            entry = threat_cache.get(prompt)
            if entry:
                decision = "block" if entry.is_threat else "pass"
                reason = f"cache_hit: {entry.threat_type}"
                meta = {"hits": entry.hits, "threat_type": entry.threat_type, "severity": entry.severity_score}
                return StageResult(2, "threat_cache", decision, reason, self._elapsed_ms(t), meta), True, entry
            return StageResult(2, "threat_cache", "pass", "cache_miss", self._elapsed_ms(t), {}), False, None
        except Exception as exc:
            return StageResult(2, "threat_cache", "pass", f"stage_error: {exc}", self._elapsed_ms(t), {}), False, None

    def _run_anomaly_check(self, ip: str, prompt: str) -> StageResult:
        t = self._tick()
        try:
            from app.services.anomaly_detector import anomaly_detector
            result = anomaly_detector.check(ip, prompt)
            decision = ("block" if self._block_on_anomaly else "warn") if result.is_anomalous else "pass"
            reason = result.top_signal if result.is_anomalous else "ok"
            meta = {"risk_score": result.risk_score, "signals": [s.signal for s in result.signals]}
        except Exception as exc:
            decision, reason, meta = "pass", f"stage_error: {exc}", {}
        return StageResult(3, "anomaly_detector", decision, reason, self._elapsed_ms(t), meta)

    def _run_security_scan(self, prompt: str) -> StageResult:
        t = self._tick()
        try:
            from app.services.security_service import check_for_threats
            result = check_for_threats(prompt)
            decision = "block" if result.is_threat else "pass"
            reason = result.threat_type if result.is_threat else "ok"
            meta = {"severity": result.severity_score, "matched": result.matched_pattern}
        except Exception as exc:
            decision, reason, meta = "pass", f"stage_error: {exc}", {}
            result = None
        return StageResult(4, "security_service", decision, reason, self._elapsed_ms(t), meta)

    def _store_to_cache(self, prompt: str, is_threat: bool, threat_type: str, severity: float) -> None:
        try:
            from app.services.threat_cache import threat_cache
            threat_cache.put(prompt, is_threat, threat_type, severity)
        except Exception:
            pass

    def _record_anomaly(self, ip: str, prompt: str, is_threat: bool) -> None:
        try:
            from app.services.anomaly_detector import anomaly_detector
            anomaly_detector.record(ip, prompt, is_threat)
        except Exception:
            pass

    def _record_audit(self, request_id: str, decision: OrchestratorDecision, ip: str) -> None:
        try:
            from app.routes.audit import record_audit_event
            severity = "critical" if decision.is_blocked else "warning" if decision.is_warned else "info"
            record_audit_event(
                event_type=f"pipeline_{decision.final_decision}",
                ip=ip,
                detail=f"stage={decision.blocked_at_stage} reason={decision.blocked_reason} threat={decision.threat_type}",
                severity=severity,
                request_id=request_id,
            )
        except Exception:
            pass

    # ── Main evaluate method ──────────────────────────────────────────────────

    def evaluate(
        self,
        prompt: str,
        request_id: str,
        ip: str = "0.0.0.0",
        security_enabled: bool = True,
    ) -> OrchestratorDecision:
        """
        Run prompt through the full 7-stage defense pipeline.

        Args:
            prompt:           Raw user input.
            request_id:       UUID for log correlation.
            ip:               Source IP address.
            security_enabled: If False, run all stages but don't block.

        Returns:
            OrchestratorDecision with per-stage breakdown and final verdict.
        """
        pipeline_start = self._tick()
        stages: list[StageResult] = []
        final = "pass"
        blocked_stage: Optional[int] = None
        blocked_reason = "none"
        threat_type = "none"
        severity: float = 0.0
        is_anomalous = False
        cache_hit = False
        sanitized = prompt

        self._stats.total_evaluated += 1

        # ── Stage 0: Context Guard ─────────────────────────────────────────────
        s0 = self._run_context_guard(prompt)
        stages.append(s0)
        if security_enabled and s0.decision == "block":
            final, blocked_stage, blocked_reason, threat_type = "block", 0, s0.reason, "context_violation"
            self._stats.total_blocked += 1
            self._stats.blocks_per_stage[0] = self._stats.blocks_per_stage.get(0, 0) + 1
            return self._build_result(request_id, final, blocked_stage, blocked_reason, threat_type, severity, stages, pipeline_start, sanitized, is_anomalous, cache_hit, ip)

        # ── Stage 1: Sanitizer ────────────────────────────────────────────────
        s1, sanitized = self._run_sanitizer(prompt)
        stages.append(s1)

        # ── Stage 2: Cache Lookup ─────────────────────────────────────────────
        s2, cache_hit, cache_entry = self._run_cache_lookup(sanitized)
        stages.append(s2)
        if security_enabled and s2.decision == "block" and cache_entry:
            final, blocked_stage = "block", 2
            blocked_reason = f"cached_threat:{cache_entry.threat_type}"
            threat_type = cache_entry.threat_type
            severity = cache_entry.severity_score
            self._stats.total_blocked += 1
            self._stats.total_cache_hits += 1
            self._stats.blocks_per_stage[2] = self._stats.blocks_per_stage.get(2, 0) + 1
            return self._build_result(request_id, final, blocked_stage, blocked_reason, threat_type, severity, stages, pipeline_start, sanitized, is_anomalous, cache_hit, ip)
        if cache_hit:
            self._stats.total_cache_hits += 1

        # ── Stage 3: Anomaly Check ────────────────────────────────────────────
        s3 = self._run_anomaly_check(ip, sanitized)
        stages.append(s3)
        is_anomalous = s3.decision in ("block", "warn")
        if security_enabled and s3.decision == "block":
            final, blocked_stage, blocked_reason, threat_type = "block", 3, s3.reason, "anomaly"
            self._stats.total_blocked += 1
            self._stats.blocks_per_stage[3] = self._stats.blocks_per_stage.get(3, 0) + 1
            return self._build_result(request_id, final, blocked_stage, blocked_reason, threat_type, severity, stages, pipeline_start, sanitized, is_anomalous, cache_hit, ip)
        elif s3.decision == "warn":
            final = "warn"

        # ── Stage 4: Core Security Scan ───────────────────────────────────────
        if not cache_hit:
            s4 = self._run_security_scan(sanitized)
            stages.append(s4)
            if s4.decision == "block":
                threat_type = s4.reason
                severity = float(s4.metadata.get("severity", 0.0))
                self._store_to_cache(sanitized, True, threat_type, severity)
                if security_enabled:
                    final, blocked_stage, blocked_reason = "block", 4, s4.reason
                    self._stats.total_blocked += 1
                    self._stats.blocks_per_stage[4] = self._stats.blocks_per_stage.get(4, 0) + 1
                    self._record_anomaly(ip, sanitized, True)
                    return self._build_result(request_id, final, blocked_stage, blocked_reason, threat_type, severity, stages, pipeline_start, sanitized, is_anomalous, cache_hit, ip)
            else:
                self._store_to_cache(sanitized, False, "none", 0.0)

        # ── Record anomaly history ────────────────────────────────────────────
        self._record_anomaly(ip, sanitized, final == "block")

        # ── Track stats ───────────────────────────────────────────────────────
        if final == "block":
            self._stats.total_blocked += 1
        elif final == "warn":
            self._stats.total_warned += 1
        else:
            self._stats.total_passed += 1

        return self._build_result(request_id, final, blocked_stage, blocked_reason, threat_type, severity, stages, pipeline_start, sanitized, is_anomalous, cache_hit, ip)

    def _build_result(
        self, request_id, final, blocked_stage, blocked_reason, threat_type,
        severity, stages, pipeline_start, sanitized, is_anomalous, cache_hit, ip
    ) -> OrchestratorDecision:
        duration = self._elapsed_ms(pipeline_start)
        self._stats._duration_sum += duration
        self._stats.avg_duration_ms = self._stats._duration_sum / self._stats.total_evaluated

        decision = OrchestratorDecision(
            request_id=request_id,
            final_decision=final,
            blocked_at_stage=blocked_stage,
            blocked_reason=blocked_reason,
            threat_type=threat_type,
            severity_score=severity,
            stages=stages,
            total_duration_ms=duration,
            sanitized_prompt=sanitized,
            is_anomalous=is_anomalous,
            cache_hit=cache_hit,
        )

        self._record_audit(request_id, decision, ip)

        logger.info(
            "🎯 Pipeline [%s] → %s  stage=%s  threat=%s  dur=%.1fms  cache=%s",
            request_id[:8], final, blocked_stage, threat_type, duration, cache_hit
        )
        return decision

    def get_stats(self) -> dict:
        s = self._stats
        return {
            "total_evaluated": s.total_evaluated,
            "total_blocked": s.total_blocked,
            "total_warned": s.total_warned,
            "total_passed": s.total_passed,
            "total_cache_hits": s.total_cache_hits,
            "cache_hit_rate_pct": round(s.total_cache_hits / max(s.total_evaluated, 1) * 100, 1),
            "block_rate_pct": round(s.total_blocked / max(s.total_evaluated, 1) * 100, 1),
            "avg_duration_ms": round(s.avg_duration_ms, 2),
            "blocks_per_stage": s.blocks_per_stage,
        }


# ── Module-level singleton ─────────────────────────────────────────────────────
orchestrator = DefenseOrchestrator()
