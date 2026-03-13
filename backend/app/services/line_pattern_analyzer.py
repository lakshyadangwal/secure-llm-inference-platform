"""
Commit 112: Line Pattern Analyzer
=====================================
Analyzes per-line patterns in a prompt to detect:
  - All-caps lines (shouting / injection headers)
  - Very long single lines (token stuffing)
  - Lines that look like shell commands (start with $ or #)
  - Lines containing only symbols
  - Excessive blank lines used for context overflow
"""

import re
from dataclasses import dataclass

_SHELL_LINE   = re.compile(r"^\s*[$#!>]\s+")
_SYMBOL_ONLY  = re.compile(r"^[^a-zA-Z0-9\s]+$")


@dataclass
class LinePatternResult:
    total_lines: int
    all_caps_lines: int
    long_lines: int           # lines > 200 chars
    shell_like_lines: int
    symbol_only_lines: int
    blank_line_ratio: float
    is_suspicious: bool

    def to_dict(self) -> dict:
        return {
            "total_lines": self.total_lines,
            "all_caps_lines": self.all_caps_lines,
            "long_lines": self.long_lines,
            "shell_like_lines": self.shell_like_lines,
            "is_suspicious": self.is_suspicious,
        }


def analyze_lines(text: str) -> LinePatternResult:
    lines = text.splitlines()
    if not lines:
        return LinePatternResult(0, 0, 0, 0, 0, 0.0, False)

    total      = len(lines)
    all_caps   = sum(1 for l in lines if l.isupper() and len(l) > 5)
    long_lines = sum(1 for l in lines if len(l) > 200)
    shell_like = sum(1 for l in lines if _SHELL_LINE.match(l))
    sym_only   = sum(1 for l in lines if _SYMBOL_ONLY.match(l) and len(l) > 3)
    blank      = sum(1 for l in lines if not l.strip())
    blank_ratio = blank / total

    suspicious = (all_caps > 3 or long_lines > 2 or
                  shell_like > 0 or blank_ratio > 0.4)

    return LinePatternResult(
        total_lines=total,
        all_caps_lines=all_caps,
        long_lines=long_lines,
        shell_like_lines=shell_like,
        symbol_only_lines=sym_only,
        blank_line_ratio=round(float(blank_ratio), 3),
        is_suspicious=suspicious,
    )
