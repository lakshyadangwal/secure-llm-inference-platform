"""
Commit 109: Language Hint Detector
=====================================
Guesses the dominant language of short text using common word lists.
Covers: English, Spanish, French, German, Portuguese, Italian.
No external library required — pure word-frequency heuristic.
Returns a confidence score (0–1) for each candidate language.
"""

from dataclasses import dataclass

_LANG_SEEDS: dict[str, list[str]] = {
    "en": ["the","and","is","in","of","to","a","that","it","you","i","he","was"],
    "es": ["el","la","de","que","y","en","los","del","se","un","una","por","con"],
    "fr": ["le","la","les","de","du","et","en","un","une","que","je","vous","nous"],
    "de": ["der","die","das","und","in","von","zu","mit","ist","auf","nicht","ein"],
    "pt": ["de","a","o","que","e","do","da","em","um","para","com","uma","os"],
    "it": ["di","e","che","il","la","un","in","del","non","per","una","con","si"],
}


@dataclass
class LanguageHint:
    detected_language: str
    confidence: float
    scores: dict[str, float]

    def to_dict(self) -> dict:
        return {
            "detected_language": self.detected_language,
            "confidence": round(self.confidence, 3),
        }


def detect_language_hint(text: str) -> LanguageHint:
    words = set(text.lower().split())
    scores: dict[str, float] = {}
    for lang, seeds in _LANG_SEEDS.items():
        hits = sum(1 for w in seeds if w in words)
        scores[lang] = hits / len(seeds)

    best_lang = max(scores, key=lambda l: scores[l])
    best_score = scores[best_lang]
    # Normalise: confidence = 1 if score > 0.5, scaled otherwise
    confidence = min(1.0, best_score * 2.0)

    return LanguageHint(
        detected_language=best_lang if best_score > 0.05 else "unknown",
        confidence=float(confidence),
        scores=scores,
    )
