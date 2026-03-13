"""
Commit 111: Character Frequency Analyzer
===========================================
Analyzes character-level frequency distribution.
Identifies character class imbalances that indicate injections
(e.g., all lowercase, no whitespace, only symbols).
"""

from dataclasses import dataclass


@dataclass
class CharProfile:
    alpha_fraction: float
    digit_fraction: float
    space_fraction: float
    symbol_fraction: float
    uppercase_fraction: float   # fraction of alpha chars that are uppercase
    is_balanced: bool           # typical natural language has alpha > 0.6

    def to_dict(self) -> dict:
        return {
            "alpha_fraction": round(self.alpha_fraction, 3),
            "digit_fraction": round(self.digit_fraction, 3),
            "space_fraction": round(self.space_fraction, 3),
            "symbol_fraction": round(self.symbol_fraction, 3),
            "uppercase_fraction": round(self.uppercase_fraction, 3),
            "is_balanced": self.is_balanced,
        }


def analyze_chars(text: str) -> CharProfile:
    if not text:
        return CharProfile(0.0, 0.0, 0.0, 0.0, 0.0, False)
    total = len(text)
    alpha  = sum(1 for c in text if c.isalpha())
    digits = sum(1 for c in text if c.isdigit())
    spaces = sum(1 for c in text if c.isspace())
    upper  = sum(1 for c in text if c.isupper())

    af = alpha / total
    df = digits / total
    sf = spaces / total
    sym = 1.0 - af - df - sf
    uf = upper / max(alpha, 1)

    balanced = af > 0.55 and sf > 0.05

    return CharProfile(
        alpha_fraction=float(af),
        digit_fraction=float(df),
        space_fraction=float(sf),
        symbol_fraction=float(max(sym, 0.0)),
        uppercase_fraction=float(uf),
        is_balanced=balanced,
    )
