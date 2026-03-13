"""
Comprehensive Data Validation and Sanitization Engine
Provides robust input validation, data sanitization, schema validation,
and security-specific validation for the Neuro-Sentry Defense Platform.

Features:
- Input sanitization (XSS, SQL injection, command injection prevention)
- Schema validation with type checking and constraints
- API request validation middleware
- PII detection and redaction
- Content moderation helpers
- Data normalization utilities
"""

import re
import json
import html
import hashlib
import ipaddress
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any, Union, Callable
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse, unquote

logger = logging.getLogger(__name__)


# ===========================================================================
# Enums
# ===========================================================================

class ValidationSeverity(Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class DataType(Enum):
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    EMAIL = "email"
    URL = "url"
    IP_ADDRESS = "ip_address"
    UUID = "uuid"
    DATE = "date"
    DATETIME = "datetime"
    JSON = "json"
    BASE64 = "base64"
    LIST = "list"
    DICT = "dict"
    PHONE = "phone"


# ===========================================================================
# Validation Result
# ===========================================================================

@dataclass
class ValidationResult:
    """Result of a validation check."""
    valid: bool = True
    errors: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[Dict[str, Any]] = field(default_factory=list)
    sanitized_value: Any = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_error(self, field_name: str, message: str, code: str = "validation_error"):
        self.valid = False
        self.errors.append({
            "field": field_name,
            "message": message,
            "code": code,
            "severity": ValidationSeverity.ERROR.value,
        })

    def add_warning(self, field_name: str, message: str, code: str = "validation_warning"):
        self.warnings.append({
            "field": field_name,
            "message": message,
            "code": code,
            "severity": ValidationSeverity.WARNING.value,
        })

    def to_dict(self) -> Dict:
        return {
            "valid": self.valid,
            "errors": self.errors,
            "warnings": self.warnings,
            "error_count": len(self.errors),
            "warning_count": len(self.warnings),
            "metadata": self.metadata,
        }


# ===========================================================================
# Input Sanitizer
# ===========================================================================

class InputSanitizer:
    """Sanitizes user input to prevent various injection attacks."""

    # XSS patterns
    XSS_PATTERNS = [
        re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
        re.compile(r'javascript\s*:', re.IGNORECASE),
        re.compile(r'vbscript\s*:', re.IGNORECASE),
        re.compile(r'on\w+\s*=', re.IGNORECASE),
        re.compile(r'<\s*img[^>]+src\s*=\s*["\']?javascript:', re.IGNORECASE),
        re.compile(r'<\s*iframe', re.IGNORECASE),
        re.compile(r'<\s*object', re.IGNORECASE),
        re.compile(r'<\s*embed', re.IGNORECASE),
        re.compile(r'<\s*applet', re.IGNORECASE),
        re.compile(r'<\s*form', re.IGNORECASE),
        re.compile(r'<\s*input', re.IGNORECASE),
        re.compile(r'<\s*button', re.IGNORECASE),
        re.compile(r'expression\s*\(', re.IGNORECASE),
        re.compile(r'url\s*\(\s*["\']?\s*javascript:', re.IGNORECASE),
        re.compile(r'data\s*:\s*text/html', re.IGNORECASE),
    ]

    # SQL injection patterns
    SQL_PATTERNS = [
        re.compile(r"('\s*(OR|AND)\s*'?\s*\d+\s*=\s*\d+)", re.IGNORECASE),
        re.compile(r"(UNION\s+(ALL\s+)?SELECT)", re.IGNORECASE),
        re.compile(r"(;\s*(DROP|DELETE|UPDATE|INSERT|ALTER|CREATE|EXEC)\s)", re.IGNORECASE),
        re.compile(r"(--\s|/\*|\*/)", re.IGNORECASE),
        re.compile(r"(SLEEP\s*\(|WAITFOR\s+DELAY|BENCHMARK\s*\()", re.IGNORECASE),
        re.compile(r"(LOAD_FILE\s*\(|INTO\s+(OUTFILE|DUMPFILE))", re.IGNORECASE),
        re.compile(r"(CHAR\s*\(\d+\)|CONCAT\s*\(|GROUP_CONCAT\s*\()", re.IGNORECASE),
        re.compile(r"(information_schema|sys\.objects|sysobjects)", re.IGNORECASE),
        re.compile(r"(xp_cmdshell|sp_executesql|sp_makewebtask)", re.IGNORECASE),
        re.compile(r"(HAVING\s+\d+\s*=\s*\d+)", re.IGNORECASE),
    ]

    # Command injection patterns
    CMD_PATTERNS = [
        re.compile(r"[;&|`$]"),
        re.compile(r"\$\(.*\)"),
        re.compile(r"`.*`"),
        re.compile(r"\|\|"),
        re.compile(r"&&"),
        re.compile(r">\s*/dev/"),
        re.compile(r"<\s*/"),
        re.compile(r"\b(cat|ls|rm|mv|cp|chmod|chown|wget|curl|nc|ncat|bash|sh|zsh|python|perl|ruby|php|node)\b"),
        re.compile(r"/etc/(passwd|shadow|hosts|crontab)"),
        re.compile(r"\.\./"),
    ]

    # Path traversal patterns
    PATH_PATTERNS = [
        re.compile(r"\.\./"),
        re.compile(r"\.\.\\"),
        re.compile(r"%2e%2e[/\\]", re.IGNORECASE),
        re.compile(r"%252e%252e", re.IGNORECASE),
        re.compile(r"\.%2e", re.IGNORECASE),
        re.compile(r"%2e\.", re.IGNORECASE),
        re.compile(r"\.\./\.\./", re.IGNORECASE),
    ]

    @classmethod
    def sanitize_html(cls, text: str) -> str:
        """Remove all HTML tags and encode entities."""
        text = re.sub(r'<[^>]+>', '', text)
        text = html.escape(text, quote=True)
        return text

    @classmethod
    def sanitize_sql(cls, text: str) -> str:
        """Escape SQL special characters."""
        replacements = {
            "'": "''",
            "\\": "\\\\",
            "\x00": "",
            "\n": "\\n",
            "\r": "\\r",
            "\x1a": "\\Z",
        }
        for char, replacement in replacements.items():
            text = text.replace(char, replacement)
        return text

    @classmethod
    def sanitize_command(cls, text: str) -> str:
        """Remove command injection characters."""
        dangerous_chars = ['&', '|', ';', '`', '$', '(', ')', '{', '}', '<', '>', '\n', '\r']
        for char in dangerous_chars:
            text = text.replace(char, '')
        return text

    @classmethod
    def sanitize_path(cls, text: str) -> str:
        """Remove path traversal sequences."""
        text = text.replace('..', '')
        text = unquote(text)
        text = text.replace('..', '')
        text = re.sub(r'[/\\]+', '/', text)
        return text.strip('/')

    @classmethod
    def detect_xss(cls, text: str) -> List[Dict]:
        """Detect potential XSS attack patterns."""
        findings = []
        decoded = unquote(text)
        for pattern in cls.XSS_PATTERNS:
            matches = pattern.findall(decoded)
            if matches:
                findings.append({
                    "type": "xss",
                    "pattern": pattern.pattern,
                    "matches": [str(m)[:100] for m in matches[:5]],
                })
        return findings

    @classmethod
    def detect_sql_injection(cls, text: str) -> List[Dict]:
        """Detect potential SQL injection patterns."""
        findings = []
        decoded = unquote(text)
        for pattern in cls.SQL_PATTERNS:
            matches = pattern.findall(decoded)
            if matches:
                findings.append({
                    "type": "sql_injection",
                    "pattern": pattern.pattern,
                    "matches": [str(m)[:100] for m in matches[:5]],
                })
        return findings

    @classmethod
    def detect_command_injection(cls, text: str) -> List[Dict]:
        """Detect potential command injection patterns."""
        findings = []
        for pattern in cls.CMD_PATTERNS:
            matches = pattern.findall(text)
            if matches:
                findings.append({
                    "type": "command_injection",
                    "pattern": pattern.pattern,
                    "matches": [str(m)[:100] for m in matches[:5]],
                })
        return findings

    @classmethod
    def detect_path_traversal(cls, text: str) -> List[Dict]:
        """Detect potential path traversal attempts."""
        findings = []
        decoded = unquote(unquote(text))
        for pattern in cls.PATH_PATTERNS:
            if pattern.search(decoded):
                findings.append({
                    "type": "path_traversal",
                    "pattern": pattern.pattern,
                })
        return findings

    @classmethod
    def full_scan(cls, text: str) -> Dict:
        """Perform a comprehensive security scan on input text."""
        xss = cls.detect_xss(text)
        sqli = cls.detect_sql_injection(text)
        cmdi = cls.detect_command_injection(text)
        path = cls.detect_path_traversal(text)

        all_findings = xss + sqli + cmdi + path
        risk_score = min(10.0, len(all_findings) * 2.5)

        return {
            "safe": len(all_findings) == 0,
            "findings": all_findings,
            "finding_count": len(all_findings),
            "risk_score": risk_score,
            "categories": {
                "xss": len(xss),
                "sql_injection": len(sqli),
                "command_injection": len(cmdi),
                "path_traversal": len(path),
            },
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        }


# ===========================================================================
# PII Detector
# ===========================================================================

class PIIDetector:
    """Detects and redacts Personally Identifiable Information (PII)."""

    PATTERNS = {
        "email": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        "phone_us": re.compile(r'\b(?:\+1)?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'),
        "phone_international": re.compile(r'\+\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}'),
        "ssn": re.compile(r'\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b'),
        "credit_card": re.compile(r'\b(?:\d{4}[-.\s]?){3}\d{4}\b'),
        "credit_card_amex": re.compile(r'\b3[47]\d{2}[-.\s]?\d{6}[-.\s]?\d{5}\b'),
        "ip_address": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
        "date_of_birth": re.compile(r'\b(?:0[1-9]|1[0-2])[/.-](?:0[1-9]|[12]\d|3[01])[/.-](?:19|20)\d{2}\b'),
        "passport": re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'),
        "iban": re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b'),
        "aws_key": re.compile(r'(?:AKIA|ASIA)[A-Z0-9]{16}'),
        "api_key_generic": re.compile(r'(?:api[_-]?key|apikey|access[_-]?token)\s*[:=]\s*["\']?([A-Za-z0-9_\-\.]{20,})["\']?', re.IGNORECASE),
        "jwt_token": re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
        "private_key": re.compile(r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----'),
        "password_field": re.compile(r'(?:password|passwd|pwd)\s*[:=]\s*["\']?([^\s"\']{4,})["\']?', re.IGNORECASE),
    }

    REDACTION_LABELS = {
        "email": "[REDACTED_EMAIL]",
        "phone_us": "[REDACTED_PHONE]",
        "phone_international": "[REDACTED_PHONE]",
        "ssn": "[REDACTED_SSN]",
        "credit_card": "[REDACTED_CC]",
        "credit_card_amex": "[REDACTED_CC]",
        "ip_address": "[REDACTED_IP]",
        "date_of_birth": "[REDACTED_DOB]",
        "passport": "[REDACTED_PASSPORT]",
        "iban": "[REDACTED_IBAN]",
        "aws_key": "[REDACTED_AWS_KEY]",
        "api_key_generic": "[REDACTED_API_KEY]",
        "jwt_token": "[REDACTED_JWT]",
        "private_key": "[REDACTED_PRIVATE_KEY]",
        "password_field": "[REDACTED_PASSWORD]",
    }

    @classmethod
    def detect(cls, text: str, categories: List[str] = None) -> Dict:
        """Detect PII in text."""
        findings = []
        patterns_to_check = cls.PATTERNS
        if categories:
            patterns_to_check = {k: v for k, v in cls.PATTERNS.items() if k in categories}

        for pii_type, pattern in patterns_to_check.items():
            for match in pattern.finditer(text):
                value = match.group()
                if pii_type == "ip_address" and not cls._is_valid_ip(value):
                    continue
                if pii_type == "credit_card" and not cls._luhn_check(value):
                    continue

                findings.append({
                    "type": pii_type,
                    "value": cls._partial_mask(value, pii_type),
                    "position": {"start": match.start(), "end": match.end()},
                    "confidence": cls._get_confidence(pii_type, value),
                })

        return {
            "has_pii": len(findings) > 0,
            "findings": findings,
            "finding_count": len(findings),
            "types_found": list(set(f["type"] for f in findings)),
            "risk_level": cls._calculate_risk(findings),
        }

    @classmethod
    def redact(cls, text: str, categories: List[str] = None) -> Tuple[str, Dict]:
        """Redact PII from text."""
        detection = cls.detect(text, categories)
        redacted = text
        offset = 0
        for finding in sorted(detection["findings"], key=lambda f: f["position"]["start"]):
            start = finding["position"]["start"] + offset
            end = finding["position"]["end"] + offset
            label = cls.REDACTION_LABELS.get(finding["type"], "[REDACTED]")
            redacted = redacted[:start] + label + redacted[end:]
            offset += len(label) - (end - start - offset + offset)

        return redacted, detection

    @classmethod
    def _partial_mask(cls, value: str, pii_type: str) -> str:
        """Partially mask a PII value for logging."""
        if len(value) <= 4:
            return "****"
        if pii_type in ("email",):
            parts = value.split("@")
            return parts[0][:2] + "***@" + parts[1] if len(parts) == 2 else "****"
        if pii_type in ("credit_card", "credit_card_amex", "ssn"):
            return "****" + value[-4:]
        if pii_type in ("phone_us", "phone_international"):
            return "****" + value[-4:]
        return value[:3] + "***" + value[-2:]

    @classmethod
    def _luhn_check(cls, card_number: str) -> bool:
        """Validate credit card number using Luhn algorithm."""
        digits = re.sub(r'[^0-9]', '', card_number)
        if len(digits) < 13 or len(digits) > 19:
            return False
        total = 0
        reverse_digits = digits[::-1]
        for i, d in enumerate(reverse_digits):
            n = int(d)
            if i % 2 == 1:
                n *= 2
                if n > 9:
                    n -= 9
            total += n
        return total % 10 == 0

    @classmethod
    def _is_valid_ip(cls, ip: str) -> bool:
        """Validate IP address."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    @classmethod
    def _get_confidence(cls, pii_type: str, value: str) -> float:
        """Estimate confidence of PII detection."""
        high_confidence = {"ssn", "credit_card", "credit_card_amex", "aws_key", "jwt_token", "private_key"}
        medium_confidence = {"email", "iban", "api_key_generic", "password_field"}
        if pii_type in high_confidence:
            return 0.95
        if pii_type in medium_confidence:
            return 0.85
        return 0.7

    @classmethod
    def _calculate_risk(cls, findings: List[Dict]) -> str:
        """Calculate overall risk level from PII findings."""
        if not findings:
            return "none"
        critical_types = {"ssn", "credit_card", "credit_card_amex", "private_key", "password_field"}
        high_types = {"aws_key", "api_key_generic", "jwt_token", "iban"}
        types_found = set(f["type"] for f in findings)
        if types_found & critical_types:
            return "critical"
        if types_found & high_types:
            return "high"
        if len(findings) > 5:
            return "high"
        if len(findings) > 2:
            return "medium"
        return "low"


# ===========================================================================
# Schema Validator
# ===========================================================================

class SchemaValidator:
    """Validates data against a defined schema."""

    TYPE_VALIDATORS = {
        DataType.STRING: lambda v: isinstance(v, str),
        DataType.INTEGER: lambda v: isinstance(v, int) and not isinstance(v, bool),
        DataType.FLOAT: lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
        DataType.BOOLEAN: lambda v: isinstance(v, bool),
        DataType.LIST: lambda v: isinstance(v, list),
        DataType.DICT: lambda v: isinstance(v, dict),
    }

    def __init__(self, schema: Dict[str, Dict]):
        """
        Initialize with a schema definition.
        Schema format:
        {
            "field_name": {
                "type": DataType.STRING,
                "required": True,
                "min_length": 1,
                "max_length": 100,
                "pattern": r"^[a-zA-Z]+$",
                "min": 0,
                "max": 100,
                "choices": ["a", "b", "c"],
                "default": "a",
                "validator": lambda v: None or "error message",
                "nested_schema": {...},
                "items_schema": {...},
            }
        }
        """
        self.schema = schema

    def validate(self, data: Dict) -> ValidationResult:
        """Validate data against the schema."""
        result = ValidationResult()

        for field_name, field_schema in self.schema.items():
            value = data.get(field_name)

            # Check required
            if field_schema.get("required", False) and value is None:
                if "default" in field_schema:
                    data[field_name] = field_schema["default"]
                    continue
                result.add_error(field_name, f"{field_name} is required", "required")
                continue

            if value is None:
                if "default" in field_schema:
                    data[field_name] = field_schema["default"]
                continue

            # Type check
            expected_type = field_schema.get("type")
            if expected_type:
                type_validator = self.TYPE_VALIDATORS.get(expected_type)
                if type_validator and not type_validator(value):
                    result.add_error(
                        field_name,
                        f"{field_name} must be of type {expected_type.value}",
                        "invalid_type"
                    )
                    continue

                # Special type validations
                if expected_type == DataType.EMAIL:
                    if not self._validate_email(str(value)):
                        result.add_error(field_name, f"{field_name} is not a valid email", "invalid_email")
                        continue
                elif expected_type == DataType.URL:
                    if not self._validate_url(str(value)):
                        result.add_error(field_name, f"{field_name} is not a valid URL", "invalid_url")
                        continue
                elif expected_type == DataType.IP_ADDRESS:
                    if not self._validate_ip(str(value)):
                        result.add_error(field_name, f"{field_name} is not a valid IP address", "invalid_ip")
                        continue
                elif expected_type == DataType.UUID:
                    if not self._validate_uuid(str(value)):
                        result.add_error(field_name, f"{field_name} is not a valid UUID", "invalid_uuid")
                        continue

            # String constraints
            if isinstance(value, str):
                if "min_length" in field_schema and len(value) < field_schema["min_length"]:
                    result.add_error(
                        field_name,
                        f"{field_name} must be at least {field_schema['min_length']} characters",
                        "min_length"
                    )
                if "max_length" in field_schema and len(value) > field_schema["max_length"]:
                    result.add_error(
                        field_name,
                        f"{field_name} must be at most {field_schema['max_length']} characters",
                        "max_length"
                    )
                if "pattern" in field_schema:
                    if not re.match(field_schema["pattern"], value):
                        result.add_error(
                            field_name,
                            field_schema.get("pattern_message", f"{field_name} format is invalid"),
                            "pattern"
                        )

            # Numeric constraints
            if isinstance(value, (int, float)):
                if "min" in field_schema and value < field_schema["min"]:
                    result.add_error(field_name, f"{field_name} must be at least {field_schema['min']}", "min")
                if "max" in field_schema and value > field_schema["max"]:
                    result.add_error(field_name, f"{field_name} must be at most {field_schema['max']}", "max")

            # Choices
            if "choices" in field_schema and value not in field_schema["choices"]:
                result.add_error(
                    field_name,
                    f"{field_name} must be one of: {', '.join(str(c) for c in field_schema['choices'])}",
                    "invalid_choice"
                )

            # List constraints
            if isinstance(value, list):
                if "min_items" in field_schema and len(value) < field_schema["min_items"]:
                    result.add_error(field_name, f"{field_name} must have at least {field_schema['min_items']} items", "min_items")
                if "max_items" in field_schema and len(value) > field_schema["max_items"]:
                    result.add_error(field_name, f"{field_name} must have at most {field_schema['max_items']} items", "max_items")
                if "items_schema" in field_schema:
                    item_validator = SchemaValidator({"item": field_schema["items_schema"]})
                    for i, item in enumerate(value):
                        item_result = item_validator.validate({"item": item})
                        for error in item_result.errors:
                            result.add_error(f"{field_name}[{i}]", error["message"], error["code"])

            # Nested schema
            if isinstance(value, dict) and "nested_schema" in field_schema:
                nested_validator = SchemaValidator(field_schema["nested_schema"])
                nested_result = nested_validator.validate(value)
                for error in nested_result.errors:
                    result.add_error(f"{field_name}.{error['field']}", error["message"], error["code"])
                for warning in nested_result.warnings:
                    result.add_warning(f"{field_name}.{warning['field']}", warning["message"])

            # Custom validator
            if "validator" in field_schema:
                custom_error = field_schema["validator"](value)
                if custom_error:
                    result.add_error(field_name, custom_error, "custom_validation")

        # Check for unknown fields
        known_fields = set(self.schema.keys())
        unknown_fields = set(data.keys()) - known_fields
        for unknown in unknown_fields:
            result.add_warning(unknown, f"Unknown field: {unknown}", "unknown_field")

        result.sanitized_value = data
        return result

    @staticmethod
    def _validate_email(email: str) -> bool:
        pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        return bool(pattern.match(email))

    @staticmethod
    def _validate_url(url: str) -> bool:
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False

    @staticmethod
    def _validate_ip(ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    @staticmethod
    def _validate_uuid(value: str) -> bool:
        pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)
        return bool(pattern.match(value))


# ===========================================================================
# API Request Validator
# ===========================================================================

class APIRequestValidator:
    """Validates incoming API requests for the security platform."""

    # Predefined schemas for common endpoints
    PROMPT_SCHEMA = {
        "prompt": {
            "type": DataType.STRING,
            "required": True,
            "min_length": 1,
            "max_length": 50000,
        },
        "model": {
            "type": DataType.STRING,
            "required": False,
            "max_length": 100,
            "default": "default",
        },
        "temperature": {
            "type": DataType.FLOAT,
            "required": False,
            "min": 0.0,
            "max": 2.0,
            "default": 0.7,
        },
        "max_tokens": {
            "type": DataType.INTEGER,
            "required": False,
            "min": 1,
            "max": 100000,
            "default": 2048,
        },
        "top_p": {
            "type": DataType.FLOAT,
            "required": False,
            "min": 0.0,
            "max": 1.0,
            "default": 1.0,
        },
        "stream": {
            "type": DataType.BOOLEAN,
            "required": False,
            "default": False,
        },
    }

    RULE_SCHEMA = {
        "name": {
            "type": DataType.STRING,
            "required": True,
            "min_length": 1,
            "max_length": 200,
            "pattern": r'^[a-zA-Z0-9_\-\s]+$',
            "pattern_message": "Rule name can only contain letters, numbers, spaces, hyphens, and underscores",
        },
        "description": {
            "type": DataType.STRING,
            "required": False,
            "max_length": 1000,
        },
        "pattern": {
            "type": DataType.STRING,
            "required": True,
            "min_length": 1,
            "max_length": 5000,
            "validator": lambda v: "Invalid regex pattern" if not APIRequestValidator._is_valid_regex(v) else None,
        },
        "severity": {
            "type": DataType.STRING,
            "required": True,
            "choices": ["critical", "high", "medium", "low", "info"],
        },
        "action": {
            "type": DataType.STRING,
            "required": True,
            "choices": ["block", "alert", "log", "challenge", "rate_limit"],
        },
        "enabled": {
            "type": DataType.BOOLEAN,
            "required": False,
            "default": True,
        },
    }

    SETTINGS_SCHEMA = {
        "defense_level": {
            "type": DataType.STRING,
            "required": False,
            "choices": ["paranoid", "strict", "moderate", "permissive"],
        },
        "rate_limit": {
            "type": DataType.INTEGER,
            "required": False,
            "min": 1,
            "max": 10000,
        },
        "enable_dlp": {
            "type": DataType.BOOLEAN,
            "required": False,
        },
        "enable_threat_intel": {
            "type": DataType.BOOLEAN,
            "required": False,
        },
        "blocked_categories": {
            "type": DataType.LIST,
            "required": False,
            "max_items": 50,
        },
        "whitelisted_ips": {
            "type": DataType.LIST,
            "required": False,
            "max_items": 1000,
        },
    }

    @classmethod
    def validate_prompt_request(cls, data: Dict) -> ValidationResult:
        """Validate a prompt/chat request."""
        validator = SchemaValidator(cls.PROMPT_SCHEMA)
        result = validator.validate(data)
        if result.valid and "prompt" in data:
            scan = InputSanitizer.full_scan(data["prompt"])
            if not scan["safe"]:
                for finding in scan["findings"]:
                    result.add_warning(
                        "prompt",
                        f"Potential {finding['type']} detected in prompt",
                        f"security_{finding['type']}"
                    )
            pii = PIIDetector.detect(data["prompt"])
            if pii["has_pii"]:
                for finding in pii["findings"]:
                    result.add_warning(
                        "prompt",
                        f"PII detected: {finding['type']}",
                        "pii_detected"
                    )
                result.metadata["pii_risk_level"] = pii["risk_level"]
        return result

    @classmethod
    def validate_rule_request(cls, data: Dict) -> ValidationResult:
        """Validate a security rule creation/update request."""
        validator = SchemaValidator(cls.RULE_SCHEMA)
        return validator.validate(data)

    @classmethod
    def validate_settings_request(cls, data: Dict) -> ValidationResult:
        """Validate a settings update request."""
        validator = SchemaValidator(cls.SETTINGS_SCHEMA)
        result = validator.validate(data)
        if "whitelisted_ips" in data and result.valid:
            for ip in data.get("whitelisted_ips", []):
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    try:
                        ipaddress.ip_network(ip, strict=False)
                    except ValueError:
                        result.add_error("whitelisted_ips", f"Invalid IP address or CIDR: {ip}", "invalid_ip")
        return result

    @staticmethod
    def _is_valid_regex(pattern: str) -> bool:
        """Check if a string is a valid regex pattern."""
        try:
            re.compile(pattern)
            return True
        except re.error:
            return False


# ===========================================================================
# Data Normalizer
# ===========================================================================

class DataNormalizer:
    """Normalizes and cleans data for consistent processing."""

    @staticmethod
    def normalize_text(text: str) -> str:
        """Normalize text by removing extra whitespace and standardizing."""
        text = re.sub(r'\s+', ' ', text).strip()
        text = text.replace('\u200b', '').replace('\u200c', '').replace('\u200d', '')
        text = text.replace('\ufeff', '').replace('\u00a0', ' ')
        return text

    @staticmethod
    def normalize_email(email: str) -> str:
        """Normalize email address."""
        email = email.strip().lower()
        parts = email.split('@')
        if len(parts) == 2:
            local = parts[0].split('+')[0]
            if parts[1] in ('gmail.com', 'googlemail.com'):
                local = local.replace('.', '')
            return f"{local}@{parts[1]}"
        return email

    @staticmethod
    def normalize_phone(phone: str) -> str:
        """Normalize phone number to digits only."""
        digits = re.sub(r'[^0-9+]', '', phone)
        if digits.startswith('00'):
            digits = '+' + digits[2:]
        return digits

    @staticmethod
    def normalize_ip(ip: str) -> str:
        """Normalize IP address."""
        try:
            return str(ipaddress.ip_address(ip.strip()))
        except ValueError:
            return ip.strip()

    @staticmethod
    def normalize_url(url: str) -> str:
        """Normalize URL for comparison."""
        url = url.strip().lower()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        parsed = urlparse(url)
        path = parsed.path.rstrip('/') or '/'
        return f"{parsed.scheme}://{parsed.netloc}{path}"

    @staticmethod
    def truncate(text: str, max_length: int, suffix: str = "...") -> str:
        """Truncate text to max length with suffix."""
        if len(text) <= max_length:
            return text
        return text[:max_length - len(suffix)] + suffix

    @staticmethod
    def mask_sensitive(text: str, visible_chars: int = 4) -> str:
        """Mask sensitive data showing only last N characters."""
        if len(text) <= visible_chars:
            return '*' * len(text)
        return '*' * (len(text) - visible_chars) + text[-visible_chars:]

    @staticmethod
    def hash_value(value: str, algorithm: str = "sha256") -> str:
        """Create a hash of a value for storage/comparison."""
        h = hashlib.new(algorithm)
        h.update(value.encode('utf-8'))
        return h.hexdigest()

    @staticmethod
    def generate_fingerprint(data: Dict) -> str:
        """Generate a deterministic fingerprint from a dictionary."""
        normalized = json.dumps(data, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(normalized.encode()).hexdigest()
