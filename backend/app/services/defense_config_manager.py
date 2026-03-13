"""
Commit 83: Defense Configuration Manager
==========================================
Centralised runtime configuration manager for all defense modules.
Supports:
  - Per-module enable/disable toggle
  - Threshold overrides (e.g., change block threshold without restart)
  - Keyword list hot-reload
  - Feature flags (e.g., "multilingual_detection_enabled")
  - Config versioning and change audit trail
  - Environment-variable bootstrap for initial values
  - JSON import/export for config portability

Configuration hierarchy:
  ENV_VARS  →  defaults  →  runtime overrides (highest priority last)

Config key format: "<module>.<parameter>" e.g., "jailbreak_scanner.threshold"
"""

import json
import logging
import os
import time
from dataclasses import dataclass, field
from threading import RLock
from typing import Any, Optional, Union

logger = logging.getLogger(__name__)

# ── Type alias ────────────────────────────────────────────────────────────────
ConfigValue = Union[str, int, float, bool, list, dict]

# ── Default configuration values ─────────────────────────────────────────────
_DEFAULTS: dict[str, ConfigValue] = {
    # Global toggles
    "global.defense_enabled":                    True,
    "global.audit_logging_enabled":              True,
    "global.rate_limiting_enabled":              True,
    "global.output_filtering_enabled":           True,

    # Jailbreak scanner
    "jailbreak_scanner.enabled":                 True,
    "jailbreak_scanner.threshold":               0.25,
    "jailbreak_scanner.hard_block_threshold":    0.75,
    "jailbreak_scanner.log_all_hits":            False,

    # Obfuscation detector
    "obfuscation_detector.enabled":              True,
    "obfuscation_detector.block_threshold":      0.50,
    "obfuscation_detector.normalize_before_scan": True,

    # Social engineering detector
    "social_engineering_detector.enabled":       True,
    "social_engineering_detector.threshold":     0.35,

    # Output filter
    "output_filter.enabled":                     True,
    "output_filter.block_threshold":             0.40,
    "output_filter.pii_redaction_enabled":       True,

    # Keyword engine
    "keyword_engine.enabled":                    True,
    "keyword_engine.warn_threshold":             0.30,
    "keyword_engine.block_threshold":            0.55,
    "keyword_engine.negation_discount":          0.50,

    # Language threat detector
    "language_threat_detector.enabled":          True,
    "language_threat_detector.block_threshold":  0.30,
    "language_threat_detector.languages":        [
        "es", "fr", "de", "pt", "it", "ar_roman", "hi_roman", "ru_roman", "zh_pinyin"
    ],

    # Adaptive rate limiter
    "rate_limiter.enabled":                      True,
    "rate_limiter.clean_rpm":                    60,
    "rate_limiter.critical_rpm":                 1,
    "rate_limiter.circuit_breaker_rpm":          5000,

    # Session threat tracker
    "session_tracker.enabled":                   True,
    "session_tracker.decay_rate":                0.95,
    "session_tracker.decay_interval_seconds":    60,
    "session_tracker.red_threshold":             0.75,

    # Anomaly detector
    "anomaly_detector.enabled":                  True,
    "anomaly_detector.ewma_alpha":               0.20,
    "anomaly_detector.spike_z_threshold":        3.0,
    "anomaly_detector.anomaly_threshold":        0.35,

    # Content classifier
    "content_classifier.enabled":               True,
    "content_classifier.block_on_labels":        ["child_safety", "self_harm", "dangerous_info"],

    # Prompt intent classifier
    "intent_classifier.enabled":                 True,
    "intent_classifier.score_threshold":         0.25,
    "intent_classifier.block_on_intents":        ["jailbreak_attempt", "harmful_instruction"],

    # Circuit breaker defaults
    "circuit_breaker.llm_api.failure_threshold": 3,
    "circuit_breaker.llm_api.timeout_seconds":   15,
    "circuit_breaker.database.failure_threshold": 5,
    "circuit_breaker.database.timeout_seconds":  30,

    # Security policy enforcer
    "policy_enforcer.hard_threshold":            0.75,
    "policy_enforcer.soft_threshold":            0.55,
    "policy_enforcer.warn_threshold":            0.30,

    # IP threat intelligence
    "ip_intel.enabled":                          True,
    "ip_intel.auto_flag_threshold":              0.70,
    "ip_intel.auto_flag_ttl_seconds":            3600,

    # Conversation context analyzer
    "context_analyzer.enabled":                  True,
    "context_analyzer.escalation_window":        5,
    "context_analyzer.max_history":              50,
    "context_analyzer.session_ttl_seconds":      3600,
}


@dataclass
class ConfigChange:
    key: str
    old_value: ConfigValue
    new_value: ConfigValue
    changed_by: str
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "changed_by": self.changed_by,
            "timestamp": self.timestamp,
        }


class DefenseConfigManager:
    """
    Runtime configuration manager for all defense modules.
    Changes take effect immediately without a server restart.
    """

    MAX_HISTORY = 500

    def __init__(self) -> None:
        self._config: dict[str, ConfigValue] = dict(_DEFAULTS)
        self._overrides: dict[str, ConfigValue] = {}
        self._change_history: list[ConfigChange] = []
        self._lock = RLock()
        self._version = 1
        self._bootstrap_from_env()
        logger.info("⚙️  DefenseConfigManager ready — %d config keys", len(self._config))

    def get(self, key: str, default: Optional[ConfigValue] = None) -> ConfigValue:
        """Get a config value. Runtime overrides take priority over defaults."""
        with self._lock:
            if key in self._overrides:
                return self._overrides[key]
            return self._config.get(key, default)  # type: ignore[return-value]

    def get_bool(self, key: str, default: bool = False) -> bool:
        val = self.get(key, default)
        return bool(val)

    def get_float(self, key: str, default: float = 0.0) -> float:
        val = self.get(key, default)
        try:
            return float(val)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return default

    def get_int(self, key: str, default: int = 0) -> int:
        val = self.get(key, default)
        try:
            return int(val)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return default

    def get_list(self, key: str, default: Optional[list] = None) -> list:
        val = self.get(key, default or [])
        if isinstance(val, list):
            return val
        return default or []

    def set(self, key: str, value: ConfigValue, changed_by: str = "system") -> None:
        """Set a runtime override for a config key."""
        with self._lock:
            old = self.get(key)
            self._overrides[key] = value
            self._version += 1
            change = ConfigChange(key=key, old_value=old, new_value=value, changed_by=changed_by)
            self._change_history.append(change)
            if len(self._change_history) > self.MAX_HISTORY:
                self._change_history = self._change_history[-self.MAX_HISTORY:]  # type: ignore[index]
        logger.info("⚙️  Config '%s' = %r (by %s)", key, value, changed_by)

    def reset(self, key: str, changed_by: str = "system") -> None:
        """Remove a runtime override, reverting to the default value."""
        with self._lock:
            if key in self._overrides:
                old = self._overrides.pop(key)
                self._version += 1
                change = ConfigChange(
                    key=key,
                    old_value=old,
                    new_value=self._config.get(key),  # type: ignore[arg-type]
                    changed_by=changed_by,
                )
                self._change_history.append(change)
        logger.info("⚙️  Config '%s' reset to default (by %s)", key, changed_by)

    def reset_all(self, changed_by: str = "system") -> None:
        """Clear all runtime overrides, reverting to defaults."""
        with self._lock:
            self._overrides.clear()
            self._version += 1
        logger.warning("⚙️  ALL config overrides cleared by %s", changed_by)

    def is_module_enabled(self, module_key: str) -> bool:
        """Check if a module is enabled. E.g., `is_module_enabled('jailbreak_scanner')`."""
        global_ok = self.get_bool("global.defense_enabled", default=True)
        module_ok = self.get_bool(f"{module_key}.enabled", default=True)
        return global_ok and module_ok

    def export_json(self) -> str:
        """Export current effective config as JSON."""
        with self._lock:
            effective = dict(self._config)
            effective.update(self._overrides)
        return json.dumps(effective, indent=2, default=str)

    def import_json(self, json_str: str, changed_by: str = "admin") -> int:
        """Import config overrides from a JSON string. Returns number of keys set."""
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as e:
            logger.error("⚙️  Config import failed: %s", e)
            return 0
        count = 0
        for k, v in data.items():
            if k in _DEFAULTS:
                self.set(k, v, changed_by=changed_by)
                count += 1
        logger.info("⚙️  Imported %d config keys from JSON (by %s)", count, changed_by)
        return count

    def get_all_defaults(self) -> dict:
        return dict(_DEFAULTS)

    def get_all_overrides(self) -> dict:
        with self._lock:
            return dict(self._overrides)

    def get_change_history(self, limit: int = 50) -> list[dict]:
        with self._lock:
            return [c.to_dict() for c in self._change_history[-limit:]]  # type: ignore[index]

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "config_version": self._version,
                "total_keys": len(self._config),
                "override_keys": len(self._overrides),
                "change_history_count": len(self._change_history),
            }

    def _bootstrap_from_env(self) -> None:
        """Read DEFENSE_CFG_* env vars to set initial overrides."""
        prefix = "DEFENSE_CFG_"
        count = 0
        for env_key, env_val in os.environ.items():
            if env_key.startswith(prefix):
                cfg_key = env_key[len(prefix):].lower().replace("__", ".")
                # Try to parse as JSON first (handles booleans, numbers, lists)
                try:
                    parsed: ConfigValue = json.loads(env_val)
                except (json.JSONDecodeError, ValueError):
                    parsed = env_val
                self._overrides[cfg_key] = parsed
                count += 1
        if count:
            logger.info("⚙️  Bootstrapped %d config values from environment", count)


defense_config_manager = DefenseConfigManager()
