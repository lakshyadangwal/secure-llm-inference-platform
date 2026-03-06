import re
import logging
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)

class OutputDLPEngine:
    """
    Data Loss Prevention (DLP) Engine for Neuro-Sentry.
    Scans LLM outputs post-inference before returning to the user.
    Detects and redacts sensitive information like PII, API keys, and internal secrets.
    """
    
    PATTERNS = {
        "AWS_API_KEY": r"(?i)AKIA[0-9A-Z]{16}",
        "OPENAI_API_KEY": r"sk-[a-zA-Z0-9]{48}",
        "GROQ_API_KEY": r"gsk_[a-zA-Z0-9]{36}",
        "CREDIT_CARD": r"\b(?:\d[ -]*?){13,16}\b",
        "SSN": r"\b\d{3}[-]?\d{2}[-]?\d{4}\b",
        "EMAIL": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b",
        "SYSTEM_PROMPT_LEAK": r"(?i)(you are a|your instructions are|system prompt|ignore previous instructions)",
        "BEARER_TOKEN": r"(?i)bearer [a-zA-Z0-9_\-\.]{20,}",
        "PRIVATE_KEY": r"-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----",
    }
    