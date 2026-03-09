"""
Commit 92: Input Normalizer
=============================
Centralised input normalization pipeline applied before any scanner.
Each step can be toggled on/off via a config dict.

Steps (in order):
  1. unicode_normalize   — NFKC normalization
  2. lowercase           — convert to lowercase for comparison
  3. strip_accents       — strip combining diacritics (é → e)
  4. expand_contractions — basic English contraction expansion
  5. collapse_whitespace — merge multiple spaces/tabs/newlines
  6. limit_length        — truncate to max_length chars

Returns both the normalized string and a summary of what changed.
"""

import re
import unicodedata
from dataclasses import dataclass, field

_WHITESPACE_RE = re.compile(r"[ \t\r\n]+")

_CONTRACTIONS: dict[str, str] = {
    "don't": "do not", "won't": "will not", "can't": "cannot",
    "i'm": "i am", "it's": "it is", "i've": "i have",
    "i'll": "i will", "i'd": "i would", "they're": "they are",
    "we're": "we are", "you're": "you are", "he's": "he is",
    "she's": "she is", "that's": "that is", "there's": "there is",
    "let's": "let us", "couldn't": "could not", "shouldn't": "should not",
    "wouldn't": "would not", "isn't": "is not", "aren't": "are not",
    "wasn't": "was not", "weren't": "were not", "hasn't": "has not",
    "haven't": "have not", "hadn't": "had not", "doesn't": "does not",
    "didn't": "did not",
}


def _strip_accents(text: str) -> str:
    nfd = unicodedata.normalize("NFD", text)
    return "".join(c for c in nfd if unicodedata.category(c) != "Mn")


def _expand_contractions(text: str) -> str:
    for contraction, expansion in _CONTRACTIONS.items():
        text = text.replace(contraction, expansion)
    return text


@dataclass
class NormalizationResult:
    original: str
    normalized: str
    steps_applied: list[str] = field(default_factory=list)
    changed: bool = False

    def to_dict(self) -> dict:
        return {
            "normalized": self.normalized,
            "steps_applied": self.steps_applied,
            "changed": self.changed,
        }


class InputNormalizer:
    """
    Configurable text normalization pipeline.
    Use `normalize()` to get a NormalizationResult.
    """

    DEFAULT_CONFIG: dict[str, bool] = {
        "unicode_normalize":  True,
        "lowercase":          True,
        "strip_accents":      False,
        "expand_contractions": True,
        "collapse_whitespace": True,
    }

    def __init__(self, config: dict[str, bool] | None = None, max_length: int = 32_768) -> None:
        self._config = dict(self.DEFAULT_CONFIG)
        if config:
            self._config.update(config)
        self._max_length = max_length

    def normalize(self, text: str) -> NormalizationResult:
        original = text
        steps: list[str] = []
        text = text[:self._max_length]

        if self._config.get("unicode_normalize"):
            out = unicodedata.normalize("NFKC", text)
            if out != text:
                steps.append("unicode_normalize")
            text = out

        if self._config.get("lowercase"):
            out = text.lower()
            if out != text:
                steps.append("lowercase")
            text = out

        if self._config.get("strip_accents"):
            out = _strip_accents(text)
            if out != text:
                steps.append("strip_accents")
            text = out

        if self._config.get("expand_contractions"):
            out = _expand_contractions(text)
            if out != text:
                steps.append("expand_contractions")
            text = out

        if self._config.get("collapse_whitespace"):
            out = _WHITESPACE_RE.sub(" ", text).strip()
            if out != text:
                steps.append("collapse_whitespace")
            text = out

        return NormalizationResult(
            original=original,
            normalized=text,
            steps_applied=steps,
            changed=text != original.lower()[:self._max_length],
        )


default_normalizer = InputNormalizer()
