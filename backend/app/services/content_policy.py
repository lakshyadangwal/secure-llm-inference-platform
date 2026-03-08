"""
Commit 45: Content Policy Engine
===================================
A configurable rule-based engine that evaluates prompts and responses
against a set of named content policies.

Each policy is a named rule with:
  - A set of regex patterns
  - A severity level (low / medium / high / critical)
  - An action (warn / block / redact / log_only)
  - An optional per-category scope (input / output / both)

Policies are defined in code with sensible defaults and can be
extended at runtime without restarting the server.

Built-in default policies:
  - adult_content      (high, block)
  - self_harm          (critical, block)
  - violence           (medium, warn)
  - hate_speech        (high, block)
  - misinformation     (medium, warn)
  - spam               (low, log_only)
  - competitor_mention (low, log_only)
"""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


# ── Enums ──────────────────────────────────────────────────────────────────────

class PolicySeverity(str, Enum):
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"

    @property
    def numeric(self) -> int:
        return {"low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class PolicyAction(str, Enum):
    LOG_ONLY = "log_only"
    WARN     = "warn"
    BLOCK    = "block"
    REDACT   = "redact"


class PolicyScope(str, Enum):
    INPUT  = "input"
    OUTPUT = "output"
    BOTH   = "both"


# ── Policy definition ──────────────────────────────────────────────────────────

@dataclass
class ContentPolicy:
    name: str
    description: str
    patterns: list[str]
    severity: PolicySeverity
    action: PolicyAction
    scope: PolicyScope = PolicyScope.BOTH
    enabled: bool = True
    _compiled: list = field(default_factory=list, init=False, repr=False)

    def __post_init__(self):
        self._compiled = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in self.patterns]

    def matches(self, text: str) -> list[str]:
        """Return list of matched pattern strings."""
        return [p.pattern for p in self._compiled if p.search(text)]


# ── Policy match result ────────────────────────────────────────────────────────

@dataclass
class PolicyMatch:
    policy_name: str
    severity: PolicySeverity
    action: PolicyAction
    matched_patterns: list[str]
    scope: PolicyScope


@dataclass
class PolicyEvalResult:
    text_scope: PolicyScope
    matches: list[PolicyMatch] = field(default_factory=list)
    highest_severity: Optional[PolicySeverity] = None
    recommended_action: PolicyAction = PolicyAction.LOG_ONLY
    should_block: bool = False
    should_warn: bool = False
    policy_names_triggered: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "matches": len(self.matches),
            "highest_severity": self.highest_severity.value if self.highest_severity else None,
            "recommended_action": self.recommended_action.value,
            "should_block": self.should_block,
            "should_warn": self.should_warn,
            "policies_triggered": self.policy_names_triggered,
        }


# ── Default built-in policies ──────────────────────────────────────────────────

_DEFAULT_POLICIES: list[ContentPolicy] = [
    ContentPolicy(
        name="self_harm",
        description="Detects self-harm or suicide-related content",
        patterns=[
            r"\b(?:kill\s+myself|end\s+my\s+life|commit\s+suicide|self[\s\-]harm)\b",
            r"\b(?:methods?\s+to\s+die|want\s+to\s+die|ways?\s+to\s+kill)\b",
        ],
        severity=PolicySeverity.CRITICAL,
        action=PolicyAction.BLOCK,
    ),
    ContentPolicy(
        name="adult_content",
        description="Detects explicit adult content requests",
        patterns=[
            r"\b(?:explicit|nsfw|pornograph|erotic|sexual\s+content)\b",
            r"\b(?:nude|nudity|18\+\s+content)\b",
        ],
        severity=PolicySeverity.HIGH,
        action=PolicyAction.BLOCK,
    ),
    ContentPolicy(
        name="violence",
        description="Detects graphic violence content",
        patterns=[
            r"\b(?:graphic\s+violence|gore|torture\s+methods?|how\s+to\s+hurt)\b",
            r"\b(?:maim|mutilate|decapitat)\w*\b",
        ],
        severity=PolicySeverity.MEDIUM,
        action=PolicyAction.WARN,
    ),
    ContentPolicy(
        name="hate_speech",
        description="Detects hate speech targeting protected groups",
        patterns=[
            r"\b(?:all\s+\w+\s+(?:should|must|deserve to)\s+(?:die|be\s+killed))\b",
            r"\b(?:racial\s+slur|ethnic\s+cleansing|genocide\s+of)\b",
        ],
        severity=PolicySeverity.HIGH,
        action=PolicyAction.BLOCK,
    ),
    ContentPolicy(
        name="misinformation",
        description="Flags potential misinformation generation requests",
        patterns=[
            r"\bwrite\s+(?:fake|false|fabricated)\s+(?:news|article|report|story)\b",
            r"\bcreate\s+(?:disinformation|propaganda)\b",
        ],
        severity=PolicySeverity.MEDIUM,
        action=PolicyAction.WARN,
        scope=PolicyScope.INPUT,
    ),
    ContentPolicy(
        name="spam",
        description="Detects bulk spam generation requests",
        patterns=[
            r"\b(?:generate|write|create)\s+\d{2,}\s+(?:emails?|messages?|posts?)\b",
            r"\bbulk\s+(?:email|sms|message)\s+(?:campaign|blast)\b",
        ],
        severity=PolicySeverity.LOW,
        action=PolicyAction.LOG_ONLY,
        scope=PolicyScope.INPUT,
    ),
    ContentPolicy(
        name="competitor_mention",
        description="Logs mentions of major AI competitors in outputs",
        patterns=[
            r"\b(?:ChatGPT|GPT-4|OpenAI|Anthropic|Claude|Gemini|Bard|Copilot)\b",
        ],
        severity=PolicySeverity.LOW,
        action=PolicyAction.LOG_ONLY,
        scope=PolicyScope.OUTPUT,
    ),
]


# ── Engine ─────────────────────────────────────────────────────────────────────

class ContentPolicyEngine:
    """
    Evaluates text against a set of named content policies.
    Policies can be added, removed, enabled, and disabled at runtime.
    """

    def __init__(self):
        self._policies: dict[str, ContentPolicy] = {}
        self._eval_count = 0
        self._block_count = 0
        self._warn_count = 0

        for policy in _DEFAULT_POLICIES:
            self.register(policy)

        logger.info(
            "📋 ContentPolicyEngine initialised with %d default policies",
            len(self._policies)
        )

    def register(self, policy: ContentPolicy) -> None:
        """Register or replace a content policy."""
        self._policies[policy.name] = policy
        logger.debug("📋 Policy registered: %s (%s)", policy.name, policy.action.value)

    def unregister(self, name: str) -> bool:
        """Remove a policy by name. Returns True if it existed."""
        if name in self._policies:
            del self._policies[name]
            return True
        return False

    def enable(self, name: str) -> bool:
        if name in self._policies:
            self._policies[name].enabled = True
            return True
        return False

    def disable(self, name: str) -> bool:
        if name in self._policies:
            self._policies[name].enabled = False
            return True
        return False

    def evaluate(self, text: str, scope: PolicyScope = PolicyScope.INPUT) -> PolicyEvalResult:
        """
        Evaluate `text` against all policies applicable to `scope`.

        Args:
            text:  The text to evaluate (user prompt or LLM response).
            scope: Whether this is INPUT or OUTPUT text.

        Returns:
            PolicyEvalResult with all matched policies and recommended action.
        """
        self._eval_count += 1
        matches: list[PolicyMatch] = []

        for policy in self._policies.values():
            if not policy.enabled:
                continue
            if policy.scope != PolicyScope.BOTH and policy.scope != scope:
                continue
            matched = policy.matches(text)
            if matched:
                matches.append(PolicyMatch(
                    policy_name=policy.name,
                    severity=policy.severity,
                    action=policy.action,
                    matched_patterns=matched,
                    scope=scope,
                ))

        result = PolicyEvalResult(text_scope=scope, matches=matches)

        if not matches:
            return result

        # Compute highest severity and recommended action
        highest = max(matches, key=lambda m: m.severity.numeric)
        result.highest_severity = highest.severity
        result.policy_names_triggered = [m.policy_name for m in matches]

        action_priority = {
            PolicyAction.LOG_ONLY: 0,
            PolicyAction.WARN: 1,
            PolicyAction.REDACT: 2,
            PolicyAction.BLOCK: 3,
        }
        worst_action = max(matches, key=lambda m: action_priority[m.action])
        result.recommended_action = worst_action.action
        result.should_block = worst_action.action == PolicyAction.BLOCK
        result.should_warn = worst_action.action in (PolicyAction.WARN, PolicyAction.REDACT)

        if result.should_block:
            self._block_count += 1
            logger.warning(
                "📋 Policy BLOCK — scope=%s  policies=%s",
                scope.value, result.policy_names_triggered
            )
        elif result.should_warn:
            self._warn_count += 1
            logger.info(
                "📋 Policy WARN — scope=%s  policies=%s",
                scope.value, result.policy_names_triggered
            )

        return result

    def list_policies(self) -> list[dict]:
        return [
            {
                "name": p.name,
                "description": p.description,
                "severity": p.severity.value,
                "action": p.action.value,
                "scope": p.scope.value,
                "enabled": p.enabled,
                "pattern_count": len(p.patterns),
            }
            for p in self._policies.values()
        ]

    def get_stats(self) -> dict:
        return {
            "total_policies": len(self._policies),
            "enabled_policies": sum(1 for p in self._policies.values() if p.enabled),
            "total_evaluations": self._eval_count,
            "total_blocks": self._block_count,
            "total_warns": self._warn_count,
            "block_rate_pct": round(self._block_count / max(self._eval_count, 1) * 100, 1),
        }


# ── Singleton ──────────────────────────────────────────────────────────────────
content_policy_engine = ContentPolicyEngine()
