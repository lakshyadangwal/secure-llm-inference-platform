"""
Commit 71: Security Policy Enforcer
======================================
Central policy enforcement engine that aggregates risk signals from
multiple defense modules and makes final allow/warn/block decisions.

Aggregation strategy:
  - Each contributing module provides a risk_score (0.0–1.0) and metadata
  - Scores are combined using a weighted max + sum hybrid formula
  - The highest individual score has heavy influence (hard block signals)
  - Final decision maps to: ALLOW / WARN / SOFT_BLOCK / HARD_BLOCK

Policy rules evaluated in order:
  1. Absolute block list  (known malicious IPs, always block)
  2. Hard-block threshold (any single module score >= hard_threshold)
  3. Soft-block threshold (weighted aggregate >= soft_threshold)
  4. Warn threshold       (aggregate >= warn_threshold)
  5. Allow               (aggregate < warn_threshold)

Configurable per-deployment via PolicyConfig.
"""

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from threading import RLock
from typing import Optional

logger = logging.getLogger(__name__)


class PolicyDecision(str, Enum):
    ALLOW      = "allow"
    WARN       = "warn"
    SOFT_BLOCK = "soft_block"
    HARD_BLOCK = "hard_block"


@dataclass
class ModuleSignal:
    """Risk signal from a single defense module."""
    module_name: str
    risk_score: float      # 0.0 – 1.0
    weight: float = 1.0    # importance of this module's signal
    detail: str = ""


@dataclass
class PolicyConfig:
    hard_threshold: float  = 0.75   # any single module >= this → HARD_BLOCK
    soft_threshold: float  = 0.55   # aggregate >= this → SOFT_BLOCK
    warn_threshold: float  = 0.30   # aggregate >= this → WARN
    # Module weights (higher = more influential in aggregate)
    module_weights: dict[str, float] = field(default_factory=lambda: {
        "jailbreak_scanner":       1.5,
        "output_filter":           1.4,
        "threat_pattern_library":  1.3,
        "keyword_watchlist":       1.3,
        "obfuscation_detector":    1.2,
        "social_engineering":      1.1,
        "prompt_classifier":       1.2,
        "content_policy":          1.2,
        "ip_reputation":           1.0,
        "entropy_analyzer":        0.9,
        "payload_fingerprinter":   0.9,
        "rate_analyzer":           0.8,
        "request_validator":       0.8,
        "token_budget":            0.7,
        "session_manager":         0.7,
    })


@dataclass
class PolicyResult:
    decision: PolicyDecision
    aggregate_score: float
    max_signal_score: float
    max_signal_module: Optional[str]
    contributing_modules: list[str]
    blocked_by: Optional[str]
    details: list[str] = field(default_factory=list)
    latency_ms: float = 0.0

    @property
    def is_blocked(self) -> bool:
        return self.decision in (PolicyDecision.SOFT_BLOCK, PolicyDecision.HARD_BLOCK)

    def to_dict(self) -> dict:
        return {
            "decision": self.decision.value,
            "is_blocked": self.is_blocked,
            "aggregate_score": round(float(self.aggregate_score), 3),  # type: ignore[call-overload]
            "max_signal_score": round(float(self.max_signal_score), 3),  # type: ignore[call-overload]
            "max_signal_module": self.max_signal_module,
            "contributing_modules": self.contributing_modules,
            "blocked_by": self.blocked_by,
            "details": self.details,
            "latency_ms": round(float(self.latency_ms), 2),  # type: ignore[call-overload]
        }


class SecurityPolicyEnforcer:
    """
    Aggregates risk signals from all defense modules and enforces
    the platform's security policy.
    """

    def __init__(self, config: Optional[PolicyConfig] = None) -> None:
        self._config = config or PolicyConfig()
        self._blocklist: set[str] = set()
        self._lock = RLock()
        self._total_evaluated = 0
        self._decision_counts: dict[str, int] = {d.value: 0 for d in PolicyDecision}
        self._module_trigger_counts: dict[str, int] = {}
        logger.info(
            "⚖️  SecurityPolicyEnforcer ready — "
            "hard=%.2f soft=%.2f warn=%.2f",
            self._config.hard_threshold,
            self._config.soft_threshold,
            self._config.warn_threshold,
        )

    def add_to_blocklist(self, ip: str) -> None:
        with self._lock:
            self._blocklist.add(ip)
        logger.info("⚖️  IP %s added to policy blocklist", ip)

    def remove_from_blocklist(self, ip: str) -> None:
        with self._lock:
            self._blocklist.discard(ip)

    def evaluate(
        self,
        signals: list[ModuleSignal],
        ip: Optional[str] = None,
    ) -> PolicyResult:
        """
        Evaluate a list of module risk signals and return a policy decision.

        Args:
            signals:  Risk signals from individual defense modules.
            ip:       Client IP (for absolute blocklist check).

        Returns:
            PolicyResult with the final allow/warn/block decision.
        """
        start_ts = time.time()
        with self._lock:
            self._total_evaluated += 1
            is_blocklisted = ip in self._blocklist if ip else False

        if is_blocklisted:
            result = PolicyResult(
                decision=PolicyDecision.HARD_BLOCK,
                aggregate_score=1.0,
                max_signal_score=1.0,
                max_signal_module="blocklist",
                contributing_modules=["blocklist"],
                blocked_by="ip_blocklist",
                details=["ip_in_absolute_blocklist"],
                latency_ms=0.0,
            )
            with self._lock:
                self._decision_counts[PolicyDecision.HARD_BLOCK.value] += 1
            return result

        if not signals:
            return PolicyResult(
                decision=PolicyDecision.ALLOW,
                aggregate_score=0.0,
                max_signal_score=0.0,
                max_signal_module=None,
                contributing_modules=[],
                blocked_by=None,
                latency_ms=0.0,
            )

        cfg = self._config

        # Compute weighted aggregate
        total_weight: float = 0.0
        weighted_sum: float = 0.0
        max_score: float = 0.0
        max_module: Optional[str] = None
        contributing: list[str] = []
        details: list[str] = []

        for sig in signals:
            mod_weight = cfg.module_weights.get(sig.module_name, sig.weight)
            effective = float(sig.risk_score * mod_weight)
            weighted_sum = float(weighted_sum + effective)  # type: ignore[operator]
            total_weight = float(total_weight + mod_weight)  # type: ignore[operator]
            if sig.risk_score > 0:
                contributing.append(sig.module_name)
            if sig.risk_score > max_score:
                max_score = sig.risk_score
                max_module = sig.module_name
            if sig.detail:
                details.append(f"{sig.module_name}:{sig.detail}")

        # Normalise: weighted average + 0.3 * max (to give hard signals more influence)
        avg = float(weighted_sum / total_weight) if total_weight > 0 else 0.0
        aggregate = float(avg * 0.7 + max_score * 0.3)  # type: ignore[operator]
        aggregate = min(1.0, aggregate)

        # Decision
        decision = PolicyDecision.ALLOW
        blocked_by: Optional[str] = None

        if max_score >= cfg.hard_threshold:
            decision = PolicyDecision.HARD_BLOCK
            blocked_by = f"hard_threshold({max_module})"
        elif aggregate >= cfg.soft_threshold:
            decision = PolicyDecision.SOFT_BLOCK
            blocked_by = f"soft_threshold(aggregate={aggregate:.2f})"
        elif aggregate >= cfg.warn_threshold:
            decision = PolicyDecision.WARN

        elapsed_ms = float((time.time() - start_ts) * 1000)

        with self._lock:
            self._decision_counts[decision.value] += 1
            for mod in contributing:
                self._module_trigger_counts[mod] = self._module_trigger_counts.get(mod, 0) + 1

        if decision != PolicyDecision.ALLOW:
            logger.warning(
                "⚖️  Policy %s — aggregate=%.2f max=%.2f(%s) modules=%s",
                decision.value, aggregate, max_score, max_module, contributing,
            )

        return PolicyResult(
            decision=decision,
            aggregate_score=aggregate,
            max_signal_score=max_score,
            max_signal_module=max_module,
            contributing_modules=contributing,
            blocked_by=blocked_by,
            details=details,
            latency_ms=elapsed_ms,
        )

    def update_config(
        self,
        hard_threshold: Optional[float] = None,
        soft_threshold: Optional[float] = None,
        warn_threshold: Optional[float] = None,
    ) -> None:
        with self._lock:
            if hard_threshold is not None:
                self._config.hard_threshold = hard_threshold
            if soft_threshold is not None:
                self._config.soft_threshold = soft_threshold
            if warn_threshold is not None:
                self._config.warn_threshold = warn_threshold
        logger.info(
            "⚖️  Policy thresholds updated — hard=%.2f soft=%.2f warn=%.2f",
            self._config.hard_threshold,
            self._config.soft_threshold,
            self._config.warn_threshold,
        )

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "total_evaluated": self._total_evaluated,
                "decision_counts": dict(self._decision_counts),
                "module_trigger_counts": dict(self._module_trigger_counts),
                "blocklist_size": len(self._blocklist),
                "config": {
                    "hard_threshold": self._config.hard_threshold,
                    "soft_threshold": self._config.soft_threshold,
                    "warn_threshold": self._config.warn_threshold,
                },
            }


security_policy_enforcer = SecurityPolicyEnforcer()
