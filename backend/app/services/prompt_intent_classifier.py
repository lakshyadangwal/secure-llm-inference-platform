"""
Commit 82: Prompt Intent Classifier
======================================
Classifies the intent of a user prompt into one of 16 intent categories.
Uses weighted keyword and structural signals — no ML model required.

Intent taxonomy:
  01. INFORMATION_REQUEST   — asking for facts, explanations
  02. CREATIVE_WRITING      — stories, poems, scripts
  03. CODE_ASSISTANCE       — debugging, writing code
  04. SUMMARIZATION         — summarise text or documents
  05. TRANSLATION           — translate between languages
  06. ANALYSIS              — analyse data, text, or a situation
  07. ROLEPLAY              — fictional character interaction
  08. JAILBREAK_ATTEMPT     — trying to bypass safety measures
  09. HARMFUL_INSTRUCTION   — requesting harmful how-to info
  10. SOCIAL_ENGINEERING    — manipulation or impersonation cues
  11. SPAM                  — low-quality, repetitive, promotional
  12. SELF_HARM             — expressions of suicidal/self-harm intent
  13. EMOTIONAL_SUPPORT     — venting, seeking mental health support
  14. OPINION_SEEKING       — asking for recommendations or opinions
  15. TASK_AUTOMATION       — asking the model to do an agentic task
  16. AMBIGUOUS             — none of the above (fallback)

Multiple intents can be active simultaneously.
The primary intent is the highest-scoring one.
"""

import logging
import re
from dataclasses import dataclass, field
from threading import RLock
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class IntentSignal:
    name: str
    patterns: list[re.Pattern]
    keywords: list[str]
    structural_hints: list[re.Pattern]   # e.g., bulleted lists for task automation
    base_score: float


_RAW_INTENTS: list[tuple[str, list[str], list[str], list[str], float]] = [
    ("information_request", [
        r"\b(what|who|where|when|why|how)\s+is\b",
        r"\b(explain|describe|define|tell\s+me|summarize|overview)\b",
        r"\b(can\s+you\s+tell\s+me|i\s+want\s+to\s+know|i.m\s+curious)\b",
    ], ["explain", "definition", "meaning", "fact", "information", "what is"],
       [], 0.5),

    ("creative_writing", [
        r"\b(write\s+a\s+(story|poem|song|script|haiku|limerick|essay|blog|letter))\b",
        r"\b(create\s+(a|an)\s+(character|narrative|fiction|plot|scene))\b",
        r"\b(imagine|describe\s+(a|an))\b.{0,30}\b(world|scene|setting|character)\b",
    ], ["story", "poem", "creative", "fiction", "write me", "imagine"],
       [], 0.6),

    ("code_assistance", [
        r"\b(write|debug|fix|refactor|review|explain)\s+(the\s+|this\s+|a\s+|some\s+)?(code|function|class|script|program|snippet|error|bug|test)\b",
        r"\b(help\s+me\s+with\s+(python|javascript|rust|go|java|c\+\+|typescript|sql))\b",
        r"\b(implement|optimize|code|programming|algorithm)\b",
    ], ["python", "javascript", "function", "variable", "syntax", "error", "bug", "debug"],
       [re.compile(r"```")], 0.7),

    ("summarization", [
        r"\b(summarize|summarise|give\s+me\s+(a\s+)?(summary|tldr|overview|brief))\b",
        r"\b(condense|shorten|digest|key\s+points|main\s+points)\b",
    ], ["summary", "tldr", "summarize", "condense", "overview"],
       [], 0.6),

    ("translation", [
        r"\b(translate\s+(this|the\s+following|it)\s+(to|into)|translate\s+(from)\b)",
        r"\b(how\s+do\s+you\s+say\s+.+\s+in\s+\w+)\b",
        r"\b(in\s+(french|spanish|german|mandarin|japanese|arabic|russian|portuguese|italian))\b",
    ], ["translate", "translation", "language", "French", "Spanish", "German"],
       [], 0.65),

    ("analysis", [
        r"\b(analyze|analyse|evaluate|assess|compare|contrast|critique|review)\b",
        r"\b(what\s+(are\s+the\s+)?(pros|cons|advantages|disadvantages|strengths|weaknesses))\b",
        r"\b(interpret|break\s+down|examine|investigate)\b",
    ], ["analysis", "compare", "evaluate", "pros", "cons", "examine"],
       [], 0.55),

    ("roleplay", [
        r"\b(roleplay|role-play|act\s+as|pretend\s+(you\s+are|to\s+be)|play\s+the\s+role)\b",
        r"\b(you\s+are\s+(now\s+)?(a|an)\s+\w+\b)",
        r"\b(let.s\s+(play|roleplay|imagine|pretend)|scenario\s*:)\b",
    ], ["roleplay", "act as", "pretend", "character", "persona"],
       [], 0.5),

    ("jailbreak_attempt", [
        r"\b(ignore|bypass|forget|override)\b.{0,20}\b(instructions?|guidelines?|rules?|restrictions?)\b",
        r"\b(DAN|jailbreak|developer\s+mode|god\s+mode|unrestricted\s+mode)\b",
        r"\b(you\s+have\s+no\s+(restrictions?|rules?|limits?|ethics?))\b",
    ], ["DAN", "jailbreak", "bypass", "no restrictions", "uncensored", "unfiltered"],
       [], 0.9),

    ("harmful_instruction", [
        r"\b(how\s+(do|can)\s+i\s+(make|build|create|synthesize|get))\b.{0,30}\b(bomb|weapon|drug|poison|malware|exploit)\b",
        r"\b(step.by.step|instructions?\s+for|recipe\s+for|guide\s+to)\b.{0,30}\b(bomb|drug|weapon|hack|exploit)\b",
        r"\b(teach\s+me\s+(how\s+to)?|show\s+me\s+(how\s+to)?)\b.{0,30}\b(hack|exploit|crack|bypass|break\s+into)\b",
    ], ["bomb", "weapon", "drug synthesis", "malware", "hack", "exploit", "poison"],
       [], 0.85),

    ("social_engineering", [
        r"\b(i\s+(am|work\s+for|represent)\s+(the\s+)?(FBI|CIA|IRS|police|IT\s+department|bank|Microsoft|Apple|Amazon))\b",
        r"\b(urgently|immediately\s+need|must\s+act\s+now)\b.{0,30}\b(comply|provide|give\s+me|tell\s+me)\b",
        r"\b(pretending\s+to\s+be|posing\s+as|impersonat(e|ing))\b",
    ], ["urgent", "immediately", "authority", "comply", "impersonate", "FBI"],
       [], 0.8),

    ("spam", [
        r"(https?://\S+\s+){2,}",
        r"\b(click\s+here|limited\s+offer|act\s+now|buy\s+now|free\s+money|you.ve\s+won)\b",
        r"(\w+\s*[!?]{3,})",
    ], ["click here", "free", "offer", "prize", "win", "limited time"],
       [], 0.4),

    ("self_harm", [
        r"\b(want\s+to\s+die|kill\s+myself|end\s+my\s+life|suicidal|no\s+point\s+(in\s+)?living)\b",
        r"\b(self.harm|cut\s+myself|hurt\s+myself|overdose)\b",
        r"\b(don.t\s+want\s+to\s+(be\s+here|live|exist)\s+anymore)\b",
    ], ["suicide", "self harm", "hurt myself", "no point living"],
       [], 0.9),

    ("emotional_support", [
        r"\b(i\s+(feel|am\s+feeling|am)\s+(sad|depressed|anxious|lonely|overwhelmed|stressed|lost|broken))\b",
        r"\b(i\s+need\s+someone\s+to\s+talk\s+to|no\s+one\s+understands\s+me)\b",
        r"\b(going\s+through\s+(a\s+)?(hard|difficult|tough)\s+time)\b",
    ], ["sad", "depressed", "lonely", "anxious", "emotional", "stressed", "comfort"],
       [], 0.5),

    ("opinion_seeking", [
        r"\b(what\s+(do\s+you\s+)?(think|recommend|suggest|prefer|believe))\b",
        r"\b(in\s+your\s+opinion|what.s\s+your\s+(take|view|opinion|thought))\b",
        r"\b(which\s+(is\s+)?(better|best|worse|worst))\b",
    ], ["recommend", "opinion", "think", "suggest", "prefer", "what is better"],
       [], 0.5),

    ("task_automation", [
        r"\b(automate|schedule|run\s+the|execute\s+the|set\s+up\s+(a\s+)?pipeline)\b",
        r"\b(for\s+(each|every|all)\s+\w+(\s+in\s+\w+)?[,:]?\s+(do|perform|run|execute))\b",
        r"\b(batch\s+(process|convert|rename|delete|move)|cron\s+job|scheduled\s+task)\b",
    ], ["automate", "batch", "pipeline", "schedule", "cron", "execute for each"],
       [re.compile(r"\d+\.\s+\w+", re.MULTILINE)], 0.55),
]


def _build_signals() -> list[IntentSignal]:
    signals = []
    for name, pats, kws, hints, base in _RAW_INTENTS:
        compiled_pats = []
        for p in pats:
            try:
                compiled_pats.append(re.compile(p, re.IGNORECASE | re.DOTALL))
            except re.error:
                pass
        signals.append(IntentSignal(
            name=name,
            patterns=compiled_pats,
            keywords=[k.lower() for k in kws],
            structural_hints=hints,
            base_score=base,
        ))
    return signals


_SIGNALS: list[IntentSignal] = _build_signals()


@dataclass
class IntentScore:
    intent: str
    score: float
    pattern_hits: int
    keyword_hits: int


@dataclass
class IntentClassificationResult:
    primary_intent: str
    all_intents: list[IntentScore]
    active_intents: list[str]
    is_potentially_harmful: bool
    details: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "primary_intent": self.primary_intent,
            "active_intents": self.active_intents,
            "is_potentially_harmful": self.is_potentially_harmful,
            "intent_scores": [
                {"intent": i.intent, "score": round(float(i.score), 3)}  # type: ignore[call-overload]
                for i in self.all_intents if i.score > 0
            ],
        }


HARMFUL_INTENTS = {"jailbreak_attempt", "harmful_instruction", "social_engineering", "self_harm"}
SCORE_THRESHOLD = 0.25


class PromptIntentClassifier:
    """Multi-label prompt intent classifier using rule-based signal matching."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._total_classified = 0
        self._intent_counts: dict[str, int] = {}
        logger.info("🎯 PromptIntentClassifier ready — %d intent categories", len(_SIGNALS))

    def classify(self, text: str) -> IntentClassificationResult:
        with self._lock:
            self._total_classified += 1

        text_lower = text.lower()
        scores: list[IntentScore] = []

        for sig in _SIGNALS:
            pat_hits = sum(1 for p in sig.patterns if p.search(text))
            kw_hits = sum(1 for k in sig.keywords if k in text_lower)
            hint_hits = sum(1 for h in sig.structural_hints if h.search(text))

            score: float = 0.0
            if pat_hits or kw_hits or hint_hits:
                total_signals = len(sig.patterns) + len(sig.keywords) + len(sig.structural_hints)
                match_fraction = float(pat_hits + kw_hits + hint_hits) / max(1, total_signals)
                score = float(sig.base_score * (0.6 + 0.4 * match_fraction))  # type: ignore[operator]

            scores.append(IntentScore(
                intent=sig.name,
                score=score,
                pattern_hits=pat_hits,
                keyword_hits=kw_hits,
            ))

        scores.sort(key=lambda s: s.score, reverse=True)
        active = [s.intent for s in scores if s.score >= SCORE_THRESHOLD]
        primary = scores[0].intent if scores[0].score >= SCORE_THRESHOLD else "ambiguous"
        is_harmful = any(i in HARMFUL_INTENTS for i in active)
        details = [f"{s.intent}:{s.score:.2f}" for s in scores[:5] if s.score > 0]

        with self._lock:
            self._intent_counts[primary] = self._intent_counts.get(primary, 0) + 1

        if is_harmful:
            logger.warning("🎯 Harmful intent detected — primary=%s active=%s", primary, active)

        return IntentClassificationResult(
            primary_intent=primary,
            all_intents=scores,
            active_intents=active,
            is_potentially_harmful=is_harmful,
            details=details,
        )

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "total_classified": self._total_classified,
                "intent_counts": dict(self._intent_counts),
                "intent_categories": len(_SIGNALS),
            }


prompt_intent_classifier = PromptIntentClassifier()
