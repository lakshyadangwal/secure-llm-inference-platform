"""
Commit 57: Threat Reporter
============================
Generates periodic threat intelligence reports summarising
the platform's security posture.

Report types:
  - Hourly rolling snapshot (last 60 minutes)
  - Daily summary (last 24 hours)
  - Ad-hoc report for any custom time window

Aggregates data from all in-process defense modules:
  - Top attack categories  (content policy, watchlist, classifier)
  - Top attacker IPs (reputation + violation history)
  - Attack volume trends   (requests per 15-minute bucket)
  - Jailbreak attempt rate
  - Near-duplicate payload clusters
  - Session threat escalations
  - Budget exhaustion events

Designed to run without file I/O or DB; all data is in-memory
from the live singleton instances used by the defense pipeline.
"""

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from threading import RLock
from typing import Optional

logger = logging.getLogger(__name__)

# ── Config ──────────────────────────────────────────────────────────────────────
BUCKET_SIZE_SECONDS  = 900.0     # 15-minute buckets
MAX_BUCKETS          = 192       # = 48 hours of buckets
MAX_REPORT_HISTORY   = 24        # keep last 24 generated reports


# ── Event types that the reporter tracks ────────────────────────────────────────

class ThreatEventType:
    THREAT_DETECTED      = "threat_detected"
    JAILBREAK_ATTEMPT    = "jailbreak_attempt"
    INJECTION_ATTEMPT    = "injection_attempt"
    CONTENT_POLICY_BLOCK = "content_policy_block"
    WATCHLIST_BLOCK      = "watchlist_block"
    IP_BLOCKED           = "ip_blocked"
    SESSION_FLAGGED      = "session_flagged"
    BUDGET_EXHAUSTED     = "budget_exhausted"
    ANOMALY_DETECTED     = "anomaly_detected"
    DUP_PAYLOAD          = "duplicate_payload"
    HIGH_ENTROPY         = "high_entropy_payload"
    RATE_LIMIT_HIT       = "rate_limit_hit"


# ── Recorded event (lightweight) ─────────────────────────────────────────────────

@dataclass
class ReporterEvent:
    event_type: str
    ip: str
    timestamp: float
    severity: float = 0.5    # 0.0 – 1.0
    detail: str = ""

    @property
    def bucket(self) -> int:
        """Which 15-minute bucket does this event fall into?"""
        return int(self.timestamp // BUCKET_SIZE_SECONDS)


# ── Report data structure ──────────────────────────────────────────────────────

@dataclass
class ThreatReport:
    generated_at: float
    window_start: float
    window_end: float
    total_events: int
    events_by_type: dict[str, int]
    top_attacker_ips: list[dict]
    top_attack_categories: list[dict]
    events_per_bucket: list[dict]    # timeline: [{ts, count, types}]
    jailbreak_rate_pct: float
    injection_rate_pct: float
    avg_severity: float
    peak_rate_rpm: float             # requests per minute at peak
    summary_text: str

    def to_dict(self) -> dict:
        return {
            "generated_at": self.generated_at,
            "window_start": self.window_start,
            "window_end": self.window_end,
            "total_events": self.total_events,
            "events_by_type": self.events_by_type,
            "top_attacker_ips": self.top_attacker_ips,
            "top_attack_categories": self.top_attack_categories,
            "events_per_bucket": self.events_per_bucket,
            "jailbreak_rate_pct": round(float(self.jailbreak_rate_pct), 1),  # type: ignore[call-overload]
            "injection_rate_pct": round(float(self.injection_rate_pct), 1),  # type: ignore[call-overload]
            "avg_severity": round(float(self.avg_severity), 3),  # type: ignore[call-overload]
            "peak_rate_rpm": round(float(self.peak_rate_rpm), 1),  # type: ignore[call-overload]
            "summary_text": self.summary_text,
        }


# ── Reporter class ─────────────────────────────────────────────────────────────

class ThreatReporter:
    """
    Collects security events from the defense pipeline and generates
    periodic threat intelligence reports.
    """

    def __init__(self) -> None:
        self._events: list[ReporterEvent] = []
        self._report_history: list[ThreatReport] = []
        self._lock = RLock()
        self._last_hourly: Optional[float] = None
        self._last_daily: Optional[float] = None
        logger.info("📰 ThreatReporter initialised")

    # ── Event ingestion ────────────────────────────────────────────────────

    def record(
        self,
        event_type: str,
        ip: str = "unknown",
        severity: float = 0.5,
        detail: str = "",
    ) -> None:
        """Record a security event. Thread-safe."""
        event = ReporterEvent(
            event_type=event_type,
            ip=ip,
            timestamp=time.time(),
            severity=severity,
            detail=detail,
        )
        with self._lock:
            self._events.append(event)
            # Keep last 48h of events (estimate: max_buckets * ~60 events/bucket)
            if len(self._events) > MAX_BUCKETS * 200:
                self._events = list(self._events)[-MAX_BUCKETS * 150:]  # type: ignore[index]

    # ── Report generation ──────────────────────────────────────────────────

    def generate_report(
        self,
        window_seconds: float = 3600.0,
        label: str = "custom",
    ) -> ThreatReport:
        """
        Generate a threat report for the last `window_seconds`.

        Args:
            window_seconds: Lookback window in seconds.
            label:          Human-readable label for logging.

        Returns:
            ThreatReport with aggregated threat statistics.
        """
        now = time.time()
        window_start = now - window_seconds

        with self._lock:
            events_in_window = [e for e in self._events if e.timestamp >= window_start]

        total = len(events_in_window)

        if total == 0:
            report = ThreatReport(
                generated_at=now,
                window_start=window_start,
                window_end=now,
                total_events=0,
                events_by_type={},
                top_attacker_ips=[],
                top_attack_categories=[],
                events_per_bucket=[],
                jailbreak_rate_pct=0.0,
                injection_rate_pct=0.0,
                avg_severity=0.0,
                peak_rate_rpm=0.0,
                summary_text=f"No threat events recorded in the last {window_seconds:.0f}s.",
            )
            self._store_report(report)
            return report

        # ── Events by type ────────────────────────────────────────────────
        type_counts: dict[str, int] = defaultdict(int)
        for e in events_in_window:
            type_counts[e.event_type] += 1

        # ── Top attackers ─────────────────────────────────────────────────
        ip_counts: dict[str, int] = defaultdict(int)
        ip_severity: dict[str, float] = defaultdict(float)
        for e in events_in_window:
            if e.ip and e.ip != "unknown":
                ip_counts[e.ip] += 1
                ip_severity[e.ip] = max(ip_severity[e.ip], e.severity)

        sorted_ips = sorted(ip_counts.keys(), key=lambda ip: ip_counts[ip], reverse=True)
        top_ips = [
            {
                "ip": ip,
                "event_count": ip_counts[ip],
                "max_severity": round(float(ip_severity[ip]), 2),  # type: ignore[call-overload]
            }
            for ip in list(sorted_ips)[:10]  # type: ignore[index]
        ]

        # ── Category distribution ─────────────────────────────────────────
        category_counts: dict[str, int] = {}
        category_groups: dict[str, list[str]] = {
            "jailbreak":      [ThreatEventType.JAILBREAK_ATTEMPT],
            "injection":      [ThreatEventType.INJECTION_ATTEMPT],
            "content_policy": [ThreatEventType.CONTENT_POLICY_BLOCK],
            "watchlist":      [ThreatEventType.WATCHLIST_BLOCK],
            "ip_reputation":  [ThreatEventType.IP_BLOCKED],
            "session":        [ThreatEventType.SESSION_FLAGGED],
            "budget":         [ThreatEventType.BUDGET_EXHAUSTED],
            "anomaly":        [ThreatEventType.ANOMALY_DETECTED],
            "duplicate":      [ThreatEventType.DUP_PAYLOAD],
            "entropy":        [ThreatEventType.HIGH_ENTROPY],
            "rate_limit":     [ThreatEventType.RATE_LIMIT_HIT],
        }
        for cat, types in category_groups.items():
            count = sum(type_counts.get(t, 0) for t in types)
            if count > 0:
                category_counts[cat] = count

        top_cats = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)
        top_cats_list = [{"category": cat, "count": cnt} for cat, cnt in top_cats]

        # ── Timeline buckets ──────────────────────────────────────────────
        bucket_counts: dict[int, int] = defaultdict(int)
        for e in events_in_window:
            bucket_counts[e.bucket] += 1

        min_bucket = int(window_start // BUCKET_SIZE_SECONDS)
        max_bucket = int(now // BUCKET_SIZE_SECONDS)
        timeline = []
        for b in range(min_bucket, max_bucket + 1):
            timeline.append({
                "bucket_ts": b * BUCKET_SIZE_SECONDS,
                "event_count": bucket_counts.get(b, 0),
            })

        # ── Rate metrics ──────────────────────────────────────────────────
        peak = max(bucket_counts.values()) if bucket_counts else 0
        peak_rpm = (peak / BUCKET_SIZE_SECONDS) * 60.0

        avg_sev = sum(e.severity for e in events_in_window) / max(total, 1)
        jb_pct = type_counts.get(ThreatEventType.JAILBREAK_ATTEMPT, 0) / max(total, 1) * 100
        inj_pct = type_counts.get(ThreatEventType.INJECTION_ATTEMPT, 0) / max(total, 1) * 100

        # ── Summary text ──────────────────────────────────────────────────
        top_cat = top_cats_list[0]["category"] if top_cats_list else "none"
        top_ip  = top_ips[0]["ip"] if top_ips else "none"
        summary = (
            f"Window: {window_seconds/3600:.1f}h | "
            f"Events: {total} | "
            f"Top category: {top_cat} | "
            f"Most active IP: {top_ip} | "
            f"Avg severity: {avg_sev:.2f} | "
            f"Jailbreak rate: {jb_pct:.1f}%"
        )

        report = ThreatReport(
            generated_at=now,
            window_start=window_start,
            window_end=now,
            total_events=total,
            events_by_type=dict(type_counts),
            top_attacker_ips=top_ips,
            top_attack_categories=top_cats_list,
            events_per_bucket=timeline,
            jailbreak_rate_pct=jb_pct,
            injection_rate_pct=inj_pct,
            avg_severity=avg_sev,
            peak_rate_rpm=peak_rpm,
            summary_text=summary,
        )

        self._store_report(report)
        logger.info("📰 ThreatReport generated — %s  events=%d", label, total)
        return report

    def hourly_report(self) -> ThreatReport:
        """Generate an hourly report (cached if already generated this hour)."""
        return self.generate_report(window_seconds=3600.0, label="hourly")

    def daily_report(self) -> ThreatReport:
        """Generate a daily report for the last 24 hours."""
        return self.generate_report(window_seconds=86400.0, label="daily")

    def _store_report(self, report: ThreatReport) -> None:
        with self._lock:
            self._report_history.append(report)
            if len(self._report_history) > MAX_REPORT_HISTORY:
                self._report_history = list(self._report_history)[-MAX_REPORT_HISTORY:]  # type: ignore[index]

    def get_last_report(self) -> Optional[ThreatReport]:
        with self._lock:
            return self._report_history[-1] if self._report_history else None

    def get_report_history(self) -> list[dict]:
        with self._lock:
            return [
                {
                    "generated_at": r.generated_at,
                    "total_events": r.total_events,
                    "summary": r.summary_text,
                }
                for r in self._report_history
            ]

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "total_events_stored": len(self._events),
                "reports_generated": len(self._report_history),
                "oldest_event_age_seconds": (
                    time.time() - self._events[0].timestamp
                    if self._events else 0
                ),
            }


# ── Singleton ──────────────────────────────────────────────────────────────────
threat_reporter = ThreatReporter()
