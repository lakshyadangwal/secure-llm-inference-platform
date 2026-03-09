"""
Commit 98: Code Block Detector
=================================
Detects fenced markdown code blocks, indented code blocks, and
inline code spans in a prompt. Identifies the programming language
declared in fenced blocks and flags dangerous languages.
"""

import re
from dataclasses import dataclass

_FENCED_RE    = re.compile(r"```(\w*)\n(.*?)```", re.DOTALL)
_INDENTED_RE  = re.compile(r"(?m)^(    |\t).+")
_INLINE_RE    = re.compile(r"`[^`\n]{1,200}`")

_DANGEROUS_LANGS = {
    "python", "bash", "sh", "shell", "powershell", "ps1",
    "cmd", "batch", "ruby", "perl", "php", "javascript", "js",
    "typescript", "ts", "go", "rust", "c", "cpp", "java",
}


@dataclass
class CodeDetectionResult:
    has_code: bool
    fenced_block_count: int
    languages_found: list[str]
    dangerous_language_found: bool
    flags: list[str]

    def to_dict(self) -> dict:
        return {
            "has_code": self.has_code,
            "fenced_block_count": self.fenced_block_count,
            "languages_found": self.languages_found,
            "dangerous_language_found": self.dangerous_language_found,
            "flags": self.flags,
        }


def detect_code_blocks(text: str) -> CodeDetectionResult:
    fenced = _FENCED_RE.findall(text)
    languages = [lang.lower() for lang, _ in fenced if lang]
    dangerous = [l for l in languages if l in _DANGEROUS_LANGS]
    indented = _INDENTED_RE.findall(text)
    inline = _INLINE_RE.findall(text)
    has_code = bool(fenced or indented or inline)

    flags: list[str] = []
    if dangerous:
        flags.append(f"dangerous_lang:{','.join(dangerous)}")
    if len(fenced) > 3:
        flags.append("many_code_blocks")

    return CodeDetectionResult(
        has_code=has_code,
        fenced_block_count=len(fenced),
        languages_found=list(set(languages)),
        dangerous_language_found=bool(dangerous),
        flags=flags,
    )
