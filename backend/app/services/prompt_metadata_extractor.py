"""
Commit 110: Prompt Metadata Extractor
========================================
Extracts structural metadata from a prompt string without
performing any content analysis. Used upstream for routing
and logging decisions.

Metadata fields:
  - char_count, word_count, line_count
  - has_code_fences, has_urls, has_numbered_list
  - starts_with_instruction_verb
  - question_count (lines/sentences ending with ?)
  - exclamation_count
"""

import re
from dataclasses import dataclass

_URL_RE     = re.compile(r"https?://\S+")
_FENCE_RE   = re.compile(r"^```", re.MULTILINE)
_NUM_LIST   = re.compile(r"^\s*\d+\.", re.MULTILINE)
_INST_VERBS = {"write","generate","create","list","explain","summarize","translate",
               "describe","ignore","forget","bypass","show","give","tell","find","make"}
_QUESTION_END = re.compile(r"\?")
_EXCL_END     = re.compile(r"!")


@dataclass
class PromptMetadata:
    char_count: int
    word_count: int
    line_count: int
    has_code_fences: bool
    has_urls: bool
    has_numbered_list: bool
    starts_with_instruction_verb: bool
    question_count: int
    exclamation_count: int

    def to_dict(self) -> dict:
        return self.__dict__


def extract_metadata(text: str) -> PromptMetadata:
    lines = text.splitlines()
    words = text.split()
    first_word = words[0].lower().rstrip(",.!?:") if words else ""

    return PromptMetadata(
        char_count=len(text),
        word_count=len(words),
        line_count=len(lines),
        has_code_fences=bool(_FENCE_RE.search(text)),
        has_urls=bool(_URL_RE.search(text)),
        has_numbered_list=bool(_NUM_LIST.search(text)),
        starts_with_instruction_verb=first_word in _INST_VERBS,
        question_count=len(_QUESTION_END.findall(text)),
        exclamation_count=len(_EXCL_END.findall(text)),
    )
