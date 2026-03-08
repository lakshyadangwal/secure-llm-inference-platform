"""
Commit 47: Prompt Intent Classifier
======================================
Classifies user prompts into intent categories using keyword/pattern matching.
Helps downstream modules calibrate their response and threat assessment.

Categories:
  - BENIGN_QUESTION      — normal factual question
  - CODE_GENERATION      — ask to write code
  - TEXT_GENERATION      — ask to write text/creative content
  - DATA_ANALYSIS        — ask to analyse data
  - SYSTEM_PROBE         — probing the system/model itself
  - JAILBREAK_ATTEMPT    — trying to bypass safety
  - INJECTION_ATTEMPT    — prompt injection signals
  - SOCIAL_ENGINEERING   — manipulation attempts
  - RECON                — reconnaissance / information gathering
  - UNKNOWN              — could not classify

Each prompt gets a primary intent and a confidence score.
Multiple secondary intents are also returned.
"""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


# ── Intent categories ──────────────────────────────────────────────────────────

class Intent(str, Enum):
    BENIGN_QUESTION    = "benign_question"
    CODE_GENERATION    = "code_generation"
    TEXT_GENERATION    = "text_generation"
    DATA_ANALYSIS      = "data_analysis"
    SYSTEM_PROBE       = "system_probe"
    JAILBREAK_ATTEMPT  = "jailbreak_attempt"
    INJECTION_ATTEMPT  = "injection_attempt"
    SOCIAL_ENGINEERING = "social_engineering"
    RECON              = "reconnaissance"
    UNKNOWN            = "unknown"

    @property
    def is_malicious(self) -> bool:
        return self in (
            Intent.JAILBREAK_ATTEMPT,
            Intent.INJECTION_ATTEMPT,
            Intent.SOCIAL_ENGINEERING,
        )

    @property
    def is_suspicious(self) -> bool:
        return self in (
            Intent.SYSTEM_PROBE,
            Intent.RECON,
        )


# ── Pattern definitions ────────────────────────────────────────────────────────

_INTENT_PATTERNS: dict[Intent, list[str]] = {
    Intent.BENIGN_QUESTION: [
        r"\b(?:what|who|where|when|why|how|which|can you explain|tell me about)\b",
        r"\b(?:define|meaning of|difference between|example of)\b",
        r"\b(?:what is|what are|what does|what was)\b",
    ],
    Intent.CODE_GENERATION: [
        r"\b(?:write|create|generate|build|implement|code)\b.{0,30}\b(?:function|class|script|program|api|endpoint|module)\b",
        r"\b(?:python|javascript|java|typescript|rust|go|sql|bash)\b.{0,20}\b(?:code|script|function|snippet)\b",
        r"\b(?:fix|debug|refactor|optimise|improve).{0,20}\b(?:code|function|script)\b",
    ],
    Intent.TEXT_GENERATION: [
        r"\b(?:write|draft|compose|create|generate)\b.{0,30}\b(?:email|letter|essay|story|article|blog|tweet|post|message)\b",
        r"\b(?:summarise|summarize|paraphrase|rewrite|translate)\b",
        r"\b(?:make this|rewrite this|improve this).{0,30}(?:text|writing|paragraph)\b",
    ],
    Intent.DATA_ANALYSIS: [
        r"\b(?:analyse|analyze|chart|graph|plot|visualise|visualize)\b.{0,30}\b(?:data|dataset|table|csv|json)\b",
        r"\b(?:find|extract|identify).{0,30}\b(?:pattern|trend|insight|correlation)\b",
        r"\b(?:calculate|compute|count|sum|average).{0,30}\b(?:of|from|in)\b",
    ],
    Intent.SYSTEM_PROBE: [
        r"\b(?:what|who|how).{0,30}\b(?:model|llm|ai|system|you) are\b",
        r"\byour\s+(?:name|version|training|knowledge|capabilities|limitations)\b",
        r"\bwhat\s+(?:can|can'?t|cannot|could|couldn'?t)\s+you\s+(?:do|tell|say|know)\b",
        r"\b(?:what\s+(?:are\s+)?your|tell\s+me\s+your)\s+(?:rules|guidelines|instructions|constraints)\b",
    ],
    Intent.JAILBREAK_ATTEMPT: [
        r"\b(?:DAN|jailbreak|unrestricted|no\s+limits?|bypass\s+(?:safety|filter))\b",
        r"\b(?:pretend\s+you\s+(?:have\s+no|don'?t\s+have|aren'?t\s+bound\s+by))\b",
        r"\b(?:act\s+as\s+(?:if|though)\s+you\s+(?:are|were)\s+(?:DAN|an\s+AI\s+without))\b",
        r"\b(?:enable\s+developer\s+mode|turn\s+off\s+(?:safety|filter|censorship))\b",
        r"\bstay\s+in\s+character\s+no\s+matter\s+what\b",
    ],
    Intent.INJECTION_ATTEMPT: [
        r"\b(?:ignore|disregard|forget|override)\b.{0,30}\b(?:previous|above|prior|all)\b.{0,30}\b(?:instruction|prompt|rule|context)\b",
        r"\b(?:new\s+instruction|system\s+override|admin\s+command)\b",
        r"\[INST\]|\[SYS\]|<\|system\|>|<<SYS>>",
        r"\b(?:your\s+new\s+(?:task|job|role|purpose|directive)\s+is)\b",
    ],
    Intent.SOCIAL_ENGINEERING: [
        r"\b(?:trust\s+me|i\s+promise|between\s+us|just\s+this\s+once)\b",
        r"\bmy\s+(?:boss|teacher|doctor|lawyer|therapist)\s+said\b",
        r"\b(?:hypothetically|for\s+a\s+(?:story|book|movie|game|research|class))\b.{0,30}\b(?:how\s+to|explain|describe)\b",
        r"\blegitimate\s+(?:reason|purpose|use\s+case)\b",
    ],
    Intent.RECON: [
        r"\b(?:list|enumerate|show\s+me|what\s+are)\b.{0,30}\b(?:all\s+(?:your|the)|available)\b.{0,30}\b(?:endpoint|api|command|feature|capability)\b",
        r"\b(?:test|check|probe|scan)\b.{0,30}\b(?:security|vulnerability|weakness)\b",
        r"\b(?:can\s+you|could\s+you|are\s+you\s+able\s+to)\b.{0,30}\b(?:access|read|write|delete|modify|execute)\b",
    ],
}

_COMPILED: dict[Intent, list[re.Pattern]] = {
    intent: [re.compile(p, re.IGNORECASE) for p in patterns]
    for intent, patterns in _INTENT_PATTERNS.items()
}


# ── Classification result ──────────────────────────────────────────────────────

@dataclass
class ClassificationResult:
    primary_intent: Intent
    confidence: float              # 0.0 – 1.0
    secondary_intents: list[Intent] = field(default_factory=list)
    intent_scores: dict[str, float] = field(default_factory=dict)
    is_malicious: bool = False
    is_suspicious: bool = False

    def to_dict(self) -> dict:
        return {
            "primary_intent": self.primary_intent.value,
            "confidence": self.confidence,
            "secondary_intents": [i.value for i in self.secondary_intents],
            "is_malicious": self.is_malicious,
            "is_suspicious": self.is_suspicious,
        }


# ── Classifier ─────────────────────────────────────────────────────────────────

class PromptClassifier:
    """
    Rule-based prompt intent classifier.
    Assigns a primary intent and confidence score to any user prompt.
    """

    def __init__(self):
        self._total_classified = 0
        self._intent_counts: dict[str, int] = {}
        logger.info("🏷️  PromptClassifier initialised with 10 intent categories")

    def classify(self, prompt: str) -> ClassificationResult:
        """
        Classify a prompt into intent categories.

        Args:
            prompt: The user's input text.

        Returns:
            ClassificationResult with primary intent, confidence, and secondary intents.
        """
        self._total_classified += 1
        scores: dict[Intent, float] = {}

        for intent, patterns in _COMPILED.items():
            hits = sum(1 for p in patterns if p.search(prompt))
            if hits > 0:
                scores[intent] = min(1.0, hits / len(patterns) * 2)

        if not scores:
            result = ClassificationResult(
                primary_intent=Intent.UNKNOWN,
                confidence=0.0,
            )
            self._record(Intent.UNKNOWN)
            return result

        sorted_intents = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        primary, primary_score = sorted_intents[0]
        secondary = [i for i, _ in list(sorted_intents)[1:4] if _ >= 0.1]  # type: ignore[index]

        # Malicious intents get a confidence boost
        if primary.is_malicious:
            primary_score = min(1.0, primary_score * 1.3)

        result = ClassificationResult(
            primary_intent=primary,
            confidence=round(float(primary_score), 3),  # type: ignore[call-overload]
            secondary_intents=secondary,
            intent_scores={str(i.value): round(float(s), 3) for i, s in sorted_intents},  # type: ignore[call-overload]
            is_malicious=primary.is_malicious,
            is_suspicious=primary.is_suspicious or any(i.is_malicious for i in secondary),
        )

        self._record(primary)
        if result.is_malicious:
            logger.warning(
                "🏷️  Malicious intent detected — intent=%s  confidence=%.2f",
                primary.value, primary_score
            )

        return result

    def _record(self, intent: Intent) -> None:
        key = str(intent.value)
        self._intent_counts[key] = self._intent_counts.get(key, 0) + 1

    def get_stats(self) -> dict:
        return {
            "total_classified": self._total_classified,
            "intent_distribution": self._intent_counts,
            "malicious_count": sum(
                v for k, v in self._intent_counts.items()
                if k in ("jailbreak_attempt", "injection_attempt", "social_engineering")
            ),
        }


# ── Singleton ──────────────────────────────────────────────────────────────────
prompt_classifier = PromptClassifier()
