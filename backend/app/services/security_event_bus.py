"""
Commit 39: Security Event Bus
================================
Lightweight publish-subscribe event bus for cross-module security communication.
Allows defense modules to emit events (e.g. "threat_detected", "anomaly_flagged")
and other modules to react without tight coupling.

Features:
  - Synchronous subscribers called in registration order
  - Wildcard subscription ("*" matches all event types)
  - Event history buffer (last N events per type)
  - Subscriber error isolation (one bad subscriber won't break others)
  - Thread-safe publish and subscribe
  - Event replay for late subscribers
  - Dead letter queue for failed deliveries
"""

import logging
import time
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Callable, Optional
from uuid import uuid4

logger = logging.getLogger(__name__)

# ── Event ──────────────────────────────────────────────────────────────────────

@dataclass
class SecurityEvent:
    """A security event published to the bus."""
    event_id: str = field(default_factory=lambda: str(uuid4())[:8])
    event_type: str = ""
    source: str = ""           # which module emitted this
    severity: str = "info"    # "info" | "warning" | "critical"
    data: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "source": self.source,
            "severity": self.severity,
            "data": self.data,
            "timestamp": self.timestamp,
        }


# ── Dead Letter entry ──────────────────────────────────────────────────────────

@dataclass
class DeadLetter:
    event: SecurityEvent
    subscriber_id: str
    error: str
    failed_at: float = field(default_factory=time.time)


# ── Subscriber registration ────────────────────────────────────────────────────

@dataclass
class Subscriber:
    subscriber_id: str
    event_types: list[str]     # list of types OR ["*"] for all
    callback: Callable[[SecurityEvent], None]
    description: str = ""
    calls: int = 0
    errors: int = 0


# ── Event Bus ──────────────────────────────────────────────────────────────────

class SecurityEventBus:
    """
    Thread-safe pub/sub event bus for security module communication.

    Usage:
        # Subscribe
        bus.subscribe("threat_detected", my_handler, sub_id="logger")

        # Publish
        bus.publish(SecurityEvent(
            event_type="threat_detected",
            source="security_service",
            severity="warning",
            data={"threat_type": "injection", "ip": "1.2.3.4"}
        ))
    """

    def __init__(self, history_size: int = 500, dead_letter_size: int = 100):
        self._subscribers: dict[str, list[Subscriber]] = defaultdict(list)
        self._wildcard: list[Subscriber] = []
        self._history: deque[SecurityEvent] = deque(maxlen=history_size)
        self._dead_letters: deque[DeadLetter] = deque(maxlen=dead_letter_size)
        self._lock = threading.RLock()
        self._total_published = 0
        self._total_delivered = 0
        self._total_failed = 0
        logger.info("📡 SecurityEventBus initialised (history=%d)", history_size)

    def subscribe(
        self,
        event_types: list[str],
        callback: Callable[[SecurityEvent], None],
        subscriber_id: Optional[str] = None,
        description: str = "",
        replay_last: int = 0,
    ) -> str:
        """
        Register a callback for one or more event types.

        Args:
            event_types:   List of event type strings, or ["*"] for all events.
            callback:      Function called with the SecurityEvent.
            subscriber_id: Optional unique ID (generated if not provided).
            description:   Human-readable description for debugging.
            replay_last:   If > 0, immediately replay the last N events.

        Returns:
            The subscriber_id string.
        """
        sid = subscriber_id or str(uuid4())[:8]
        sub = Subscriber(
            subscriber_id=sid,
            event_types=event_types,
            callback=callback,
            description=description,
        )
        with self._lock:
            if "*" in event_types:
                self._wildcard.append(sub)
            else:
                for et in event_types:
                    self._subscribers[et].append(sub)
            logger.debug("📌 Subscribed [%s] for %s", sid, event_types)

            if replay_last > 0:
                to_replay = list(self._history)[-replay_last:]
                for event in to_replay:
                    if "*" in event_types or event.event_type in event_types:
                        self._deliver(sub, event)

        return sid

    def unsubscribe(self, subscriber_id: str) -> bool:
        """Remove a subscriber by ID. Returns True if found and removed."""
        with self._lock:
            removed = False
            for et, subs in self._subscribers.items():
                original = len(subs)
                self._subscribers[et] = [s for s in subs if s.subscriber_id != subscriber_id]
                if len(self._subscribers[et]) < original:
                    removed = True
            self._wildcard = [s for s in self._wildcard if s.subscriber_id != subscriber_id]
            return removed

    def publish(self, event: SecurityEvent) -> int:
        """
        Publish an event to all matching subscribers.

        Returns:
            Number of subscribers successfully notified.
        """
        with self._lock:
            self._history.append(event)
            self._total_published += 1

            targets: list[Subscriber] = (
                list(self._subscribers.get(event.event_type, []))
                + list(self._wildcard)
            )

        delivered = 0
        for sub in targets:
            if self._deliver(sub, event):
                delivered += 1

        with self._lock:
            self._total_delivered += delivered

        if event.severity == "critical":
            logger.warning(
                "📡 CRITICAL event [%s] from %s → %d subscribers",
                event.event_type, event.source, delivered
            )
        else:
            logger.debug(
                "📡 Event [%s] from %s → %d subscribers",
                event.event_type, event.source, delivered
            )
        return delivered

    def _deliver(self, sub: Subscriber, event: SecurityEvent) -> bool:
        """Deliver one event to one subscriber. Returns True on success."""
        try:
            sub.callback(event)
            sub.calls += 1
            return True
        except Exception as exc:
            sub.errors += 1
            self._total_failed += 1
            dl = DeadLetter(
                event=event,
                subscriber_id=sub.subscriber_id,
                error=str(exc),
            )
            self._dead_letters.append(dl)
            logger.error(
                "💀 Delivery failed — sub=%s  event=%s  error=%s",
                sub.subscriber_id, event.event_type, exc
            )
            return False

    def emit(
        self,
        event_type: str,
        source: str,
        severity: str = "info",
        **data,
    ) -> int:
        """Convenience helper to create and publish an event in one call."""
        return self.publish(SecurityEvent(
            event_type=event_type,
            source=source,
            severity=severity,
            data=dict(data),
        ))

    def get_history(self, event_type: str = "", limit: int = 50) -> list[dict]:
        """Return recent events, optionally filtered by type."""
        with self._lock:
            events = list(self._history)
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        return [e.to_dict() for e in reversed(events[-limit:])]

    def get_dead_letters(self) -> list[dict]:
        """Return failed delivery records."""
        with self._lock:
            return [
                {
                    "event": dl.event.to_dict(),
                    "subscriber_id": dl.subscriber_id,
                    "error": dl.error,
                    "failed_at": dl.failed_at,
                }
                for dl in self._dead_letters
            ]

    def get_stats(self) -> dict:
        with self._lock:
            all_subs = sum(len(v) for v in self._subscribers.values()) + len(self._wildcard)
            return {
                "total_published": self._total_published,
                "total_delivered": self._total_delivered,
                "total_failed": self._total_failed,
                "active_subscribers": all_subs,
                "history_size": len(self._history),
                "dead_letters": len(self._dead_letters),
                "delivery_rate_pct": round(
                    self._total_delivered / max(self._total_published * max(all_subs, 1), 1) * 100, 1
                ),
            }


# ── Singleton ──────────────────────────────────────────────────────────────────
event_bus = SecurityEventBus(history_size=500)

# ── Built-in event type constants ──────────────────────────────────────────────
class Events:
    THREAT_DETECTED       = "threat_detected"
    THREAT_BLOCKED        = "threat_blocked"
    ANOMALY_DETECTED      = "anomaly_detected"
    DLP_LEAK              = "dlp_leak"
    CIRCUIT_OPENED        = "circuit_opened"
    CIRCUIT_RECOVERED     = "circuit_recovered"
    CONTEXT_VIOLATION     = "context_violation"
    JAILBREAK_ATTEMPTED   = "jailbreak_attempted"
    JAILBREAK_SUCCESS     = "jailbreak_success"
    RATE_LIMIT_TRIGGERED  = "rate_limit_triggered"
    STATS_RESET           = "stats_reset"
    SERVICE_START         = "service_start"
    SERVICE_STOP          = "service_stop"
