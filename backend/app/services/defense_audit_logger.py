"""
Commit 80: Defense Audit Logger
==================================
Structured audit logger for all security-relevant events across the platform.
Provides:
  - Severity-tiered event types (INFO, WARN, BLOCK, ALERT, CRITICAL)
  - Structured JSON-compatible records with rich context
  - In-memory ring buffer (configurable size) for recent events
  - Filtering / querying by severity, module, IP, session, time range
  - Aggregated statistics per event type and module
  - Export helper that returns events as list[dict] for API endpoints

Design principles:
  - Never blocks the calling thread (writes are synchronous but very fast)
  - Thread-safe with a single RLock
  - No external I/O dependencies (log targets plug in via standard logging)
  - Lightweight records (dataclasses, no heavy serialisation)
"""

import json
import logging
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from threading import RLock
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_RING_BUFFER_SIZE = 10_000


class AuditSeverity(str, Enum):
    INFO     = "info"
    WARN     = "warn"
    BLOCK    = "block"
    ALERT    = "alert"
    CRITICAL = "critical"


_SEV_ORDER: dict[str, int] = {
    AuditSeverity.INFO.value:     0,
    AuditSeverity.WARN.value:     1,
    AuditSeverity.BLOCK.value:    2,
    AuditSeverity.ALERT.value:    3,
    AuditSeverity.CRITICAL.value: 4,
}

class AuditEventType(str, Enum):
    REQUEST_RECEIVED       = "request_received"
    REQUEST_BLOCKED        = "request_blocked"
    REQUEST_WARNED         = "request_warned"
    RESPONSE_BLOCKED       = "response_blocked"
    RESPONSE_REDACTED      = "response_redacted"
    RATE_LIMITED           = "rate_limited"
    JAILBREAK_DETECTED     = "jailbreak_detected"
    OBFUSCATION_DETECTED   = "obfuscation_detected"
    SOCIAL_ENGINEERING     = "social_engineering_detected"
    CONTEXT_ESCALATION     = "context_escalation"
    SESSION_ESCALATED      = "session_escalated"
    IP_FLAGGED             = "ip_flagged"
    IP_BLOCKED             = "ip_blocked"
    ANOMALY_DETECTED       = "anomaly_detected"
    POLICY_HARD_BLOCK      = "policy_hard_block"
    POLICY_SOFT_BLOCK      = "policy_soft_block"
    ADMIN_ACTION           = "admin_action"
    AUTH_FAILURE           = "auth_failure"
    SYSTEM_HEALTH          = "system_health"
    KEYWORD_HIT            = "keyword_hit"
    OUTPUT_FILTER_HIT      = "output_filter_hit"
    LANGUAGE_THREAT        = "language_threat_detected"
    CONTENT_CLASSIFIED     = "content_classified"


@dataclass
class AuditRecord:
    record_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    timestamp: float = field(default_factory=time.time)
    severity: AuditSeverity = AuditSeverity.INFO
    event_type: AuditEventType = AuditEventType.REQUEST_RECEIVED
    module: str = ""
    ip: Optional[str] = None
    session_id: Optional[str] = None
    user_id: Optional[str] = None
    prompt_hash: Optional[str] = None     # first 16 chars of sha256(prompt)
    risk_score: float = 0.0
    decision: str = "allow"
    details: dict = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "record_id":   self.record_id,
            "timestamp":   self.timestamp,
            "severity":    self.severity.value,
            "event_type":  self.event_type.value,
            "module":      self.module,
            "ip":          self.ip,
            "session_id":  self.session_id,
            "user_id":     self.user_id,
            "prompt_hash": self.prompt_hash,
            "risk_score":  round(float(self.risk_score), 3),  # type: ignore[call-overload]
            "decision":    self.decision,
            "details":     self.details,
            "tags":        self.tags,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


class DefenseAuditLogger:
    """
    Structured, queryable audit log for all defense-related events.
    Stores events in an in-memory ring buffer. Emits to Python logging.
    """

    def __init__(self, ring_buffer_size: int = DEFAULT_RING_BUFFER_SIZE) -> None:
        self._buffer: deque = deque(maxlen=ring_buffer_size)
        self._lock = RLock()
        self._total_records = 0
        self._severity_counts: dict[str, int] = {s.value: 0 for s in AuditSeverity}
        self._module_counts: dict[str, int] = {}
        self._event_type_counts: dict[str, int] = {}
        logger.info("📋 DefenseAuditLogger initialised — buffer_size=%d", ring_buffer_size)

    def log(
        self,
        severity: AuditSeverity,
        event_type: AuditEventType,
        module: str,
        risk_score: float = 0.0,
        decision: str = "allow",
        ip: Optional[str] = None,
        session_id: Optional[str] = None,
        user_id: Optional[str] = None,
        prompt_hash: Optional[str] = None,
        details: Optional[dict] = None,
        tags: Optional[list[str]] = None,
    ) -> AuditRecord:
        """Create and store an audit record. Returns the created record."""
        record = AuditRecord(
            severity=severity,
            event_type=event_type,
            module=module,
            ip=ip,
            session_id=session_id,
            user_id=user_id,
            prompt_hash=prompt_hash,
            risk_score=max(0.0, min(1.0, risk_score)),
            decision=decision,
            details=details or {},
            tags=tags or [],
        )
        with self._lock:
            self._buffer.append(record)
            self._total_records += 1
            self._severity_counts[severity.value] = self._severity_counts.get(severity.value, 0) + 1
            self._module_counts[module] = self._module_counts.get(module, 0) + 1
            self._event_type_counts[event_type.value] = self._event_type_counts.get(event_type.value, 0) + 1

        # Emit to Python logger at matching level
        _log_fn = {
            AuditSeverity.INFO:     logger.info,
            AuditSeverity.WARN:     logger.warning,
            AuditSeverity.BLOCK:    logger.warning,
            AuditSeverity.ALERT:    logger.error,
            AuditSeverity.CRITICAL: logger.critical,
        }.get(severity, logger.info)
        _log_fn("📋 [%s] %s module=%s ip=%s risk=%.2f",
                severity.value.upper(), event_type.value, module, ip or "-", risk_score)

        return record

    # ── Convenience wrappers ──────────────────────────────────────────────────

    def info(self, event_type: AuditEventType, module: str, **kwargs) -> AuditRecord:
        return self.log(AuditSeverity.INFO, event_type, module, **kwargs)

    def warn(self, event_type: AuditEventType, module: str, **kwargs) -> AuditRecord:
        return self.log(AuditSeverity.WARN, event_type, module, **kwargs)

    def block(self, event_type: AuditEventType, module: str, **kwargs) -> AuditRecord:
        return self.log(AuditSeverity.BLOCK, event_type, module, **kwargs)

    def alert(self, event_type: AuditEventType, module: str, **kwargs) -> AuditRecord:
        return self.log(AuditSeverity.ALERT, event_type, module, **kwargs)

    def critical(self, event_type: AuditEventType, module: str, **kwargs) -> AuditRecord:
        return self.log(AuditSeverity.CRITICAL, event_type, module, **kwargs)

    # ── Query ─────────────────────────────────────────────────────────────────

    def query(
        self,
        min_severity: Optional[AuditSeverity] = None,
        module: Optional[str] = None,
        ip: Optional[str] = None,
        session_id: Optional[str] = None,
        event_type: Optional[AuditEventType] = None,
        since_ts: Optional[float] = None,
        until_ts: Optional[float] = None,
        limit: int = 100,
    ) -> list[dict]:
        """Query the audit buffer with optional filters. Returns list of dicts."""
        min_ord = _SEV_ORDER.get(min_severity.value, 0) if min_severity else 0
        with self._lock:
            records = list(self._buffer)

        filtered: list[AuditRecord] = []
        for r in reversed(records):
            if _SEV_ORDER.get(r.severity.value, 0) < min_ord:
                continue
            if module and r.module != module:
                continue
            if ip and r.ip != ip:
                continue
            if session_id and r.session_id != session_id:
                continue
            if event_type and r.event_type != event_type:
                continue
            if since_ts and r.timestamp < since_ts:
                continue
            if until_ts and r.timestamp > until_ts:
                continue
            filtered.append(r)
            if len(filtered) >= limit:
                break

        return [r.to_dict() for r in filtered]

    def recent(self, n: int = 20) -> list[dict]:
        """Return the N most recent audit records."""
        with self._lock:
            records = list(self._buffer)
        return [r.to_dict() for r in reversed(records[-n:])]  # type: ignore[index]

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "total_records": self._total_records,
                "buffer_size": self._buffer.maxlen,
                "severity_counts": dict(self._severity_counts),
                "module_counts": dict(self._module_counts),
                "event_type_counts": dict(self._event_type_counts),
            }


defense_audit_logger = DefenseAuditLogger()
