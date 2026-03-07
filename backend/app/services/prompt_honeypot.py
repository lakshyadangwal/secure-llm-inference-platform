"""
Commit 40: Prompt Honeypot System
====================================
Embeds invisible detection traps in the system context.
When an attacker successfully extracts the system prompt,
the honeypot tokens trigger an alert.

Additionally, scans incoming prompts for tokens that would
ONLY appear if the attacker had already extracted system context,
indicating a successful prior extraction attempt.

Honeypot strategies:
  1. Canary token injection — invisible UUIDs in system context
  2. Canary echo detection  — prompt contains our canary token
  3. System prompt reflection detection — response mirrors sys. prompt patterns
  4. Instruction boundary probing — attacker tests where prompts start/end
  5. Context extraction attempt logging — tracks IPs that probe for context
"""

import logging
import re
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from threading import RLock
from typing import Optional

logger = logging.getLogger(__name__)

# ── Honeypot patterns (what attackers probe for) ───────────────────────────────
_INSTRUCTION_BOUNDARY_PROBES = re.compile(
    r"\b(?:what(?:'s| is)(?: your)? (?:system |initial |first )?(?:prompt|instruction|directive))\b"
    r"|\b(?:show|print|display|output|repeat|echo|tell me|reveal|expose)"
    r"\b.{0,25}\b(?:system prompt|initial prompt|your prompt|your instruction)\b"
    r"|\bwhat (?:were|are) (?:you|your) (?:told|instructed|asked|directed) to\b"
    r"|\bbegin(?:ning)? of (?:the |your )?(?:conversation|context|session)\b",
    re.IGNORECASE,
)

_ROLEPLAY_CONTEXT_PROBE = re.compile(
    r"\bpretend (?:you (?:don'?t|have no) (?:system|any) (?:prompt|instruction))\b"
    r"|\bignore (?:your|the|all) (?:system|previous|initial) (?:prompt|instruction|context)\b"
    r"|\bact as if (?:you|your) (?:have no|weren'?t given any) (?:rules|instruction|constraint)\b",
    re.IGNORECASE,
)

@dataclass
class CanaryConfig:
    """Configuration for one active canary token."""
    token: str
    description: str
    created_at: float = field(default_factory=time.time)
    trigger_count: int = 0


@dataclass
class HoneypotResult:
    """Result of a honeypot check on one request."""
    triggered: bool
    trigger_type: str              # "canary_echo" | "boundary_probe" | "context_probe"
    details: str
    ip: str
    severity: float


class PromptHoneypot:
    """
    Honeypot system for detecting system prompt extraction attacks.
    """

    def __init__(self):
        self._canaries: dict[str, CanaryConfig] = {}
        self._extraction_log: dict[str, deque] = defaultdict(lambda: deque(maxlen=50))
        self._lock = RLock()
        self._total_triggers = 0
        self._total_checked = 0

        # Pre-generate a set of default canary tokens
        self._default_canaries: list[str] = []
        for _ in range(5):
            self._default_canaries.append(self._generate_canary())

        logger.info(
            "🍯 PromptHoneypot initialised with %d default canaries",
            len(self._default_canaries)
        )

    def _generate_canary(self) -> str:
        """Generate a unique canary token that looks like an innocuous UUID."""
        return f"NSRY-{str(uuid.uuid4())[:8].upper()}"

    def register_canary(self, token: str, description: str = "") -> str:
        """
        Register a canary token to watch for.
        If this token appears in user input, an extraction attack is flagged.
        """
        with self._lock:
            self._canaries[token] = CanaryConfig(token=token, description=description)
            logger.info("🪤 Canary registered: %s (%s)", token[:8] + "...", description)
        return token

    def generate_and_register(self, description: str = "auto") -> str:
        """Generate a new canary token, register it, and return it."""
        token = self._generate_canary()
        self.register_canary(token, description)
        return token

    def get_system_prompt_injection(self) -> str:
        """
        Return a string to embed in the system prompt containing canary tokens.
        The tokens are formatted as seemingly-innocent config values.
        """
        tokens = self._default_canaries[:3]
        lines = [
            f"# Internal ref: {tokens[0]}",
            f"# Build id: {tokens[1]}",
            f"# Session: {tokens[2]}",
        ]
        return "\n".join(lines)

    def check(self, prompt: str, ip: str = "unknown") -> Optional[HoneypotResult]:
        """
        Check a prompt for honeypot triggers.

        Returns:
            HoneypotResult if a trigger was detected, None if clean.
        """
        self._total_checked += 1

        # ── Check 1: Canary echo detection ────────────────────────────────────
        with self._lock:
            all_canaries = list(self._canaries.keys()) + self._default_canaries

        for token in all_canaries:
            if token.lower() in prompt.lower():
                with self._lock:
                    if token in self._canaries:
                        self._canaries[token].trigger_count += 1
                    self._total_triggers += 1
                    self._extraction_log[ip].append({
                        "ts": time.time(),
                        "trigger": "canary_echo",
                        "token_preview": token[:8],
                    })

                logger.critical(
                    "🚨 HONEYPOT TRIGGERED — ip=%s  canary=%s...  TYPE=CANARY_ECHO",
                    ip, token[:8]
                )
                return HoneypotResult(
                    triggered=True,
                    trigger_type="canary_echo",
                    details=f"Canary token {token[:8]}... found in user prompt",
                    ip=ip,
                    severity=1.0,
                )

        # ── Check 2: Instruction boundary probing ─────────────────────────────
        if _INSTRUCTION_BOUNDARY_PROBES.search(prompt):
            with self._lock:
                self._total_triggers += 1
                self._extraction_log[ip].append({
                    "ts": time.time(),
                    "trigger": "boundary_probe",
                })

            logger.warning(
                "🍯 Honeypot: instruction boundary probe — ip=%s", ip
            )
            return HoneypotResult(
                triggered=True,
                trigger_type="boundary_probe",
                details="Prompt probes for system instruction boundaries",
                ip=ip,
                severity=0.75,
            )

        # ── Check 3: Roleplay context extraction ───────────────────────────────
        if _ROLEPLAY_CONTEXT_PROBE.search(prompt):
            with self._lock:
                self._total_triggers += 1
                self._extraction_log[ip].append({
                    "ts": time.time(),
                    "trigger": "context_probe",
                })

            logger.warning(
                "🍯 Honeypot: roleplay context probe — ip=%s", ip
            )
            return HoneypotResult(
                triggered=True,
                trigger_type="context_probe",
                details="Prompt attempts roleplay-based context extraction",
                ip=ip,
                severity=0.6,
            )

        return None

    def get_extraction_history(self, ip: str) -> list[dict]:
        """Return all recorded honeypot triggers for an IP."""
        with self._lock:
            return list(self._extraction_log.get(ip, []))

    def get_top_attackers(self, limit: int = 10) -> list[dict]:
        """Return IPs with the most honeypot triggers."""
        with self._lock:
            scored = [
                {"ip": ip, "trigger_count": len(events), "last_seen": events[-1]["ts"] if events else 0}
                for ip, events in self._extraction_log.items()
            ]
        return sorted(scored, key=lambda x: x["trigger_count"], reverse=True)[:limit]

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "registered_canaries": len(self._canaries),
                "default_canaries": len(self._default_canaries),
                "total_checked": self._total_checked,
                "total_triggers": self._total_triggers,
                "unique_attacker_ips": len(self._extraction_log),
                "trigger_rate_pct": round(
                    self._total_triggers / max(self._total_checked, 1) * 100, 1
                ),
            }


# ── Singleton ──────────────────────────────────────────────────────────────────
prompt_honeypot = PromptHoneypot()
