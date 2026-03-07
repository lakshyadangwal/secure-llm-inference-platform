"""
Commit 35: Advanced Defense Test Suite
========================================
Comprehensive tests for all 10 new defense modules:
  - DLP Engine          (commit 26)
  - Threat Cache        (commit 27)
  - Anomaly Detector    (commit 28)
  - Input Sanitizer     (commit 29)
  - Circuit Breaker     (commit 30)
  - Context Guard       (commit 31)
  - Defense Metrics     (commit 32)
  - Audit route         (commit 33)
  - Admin route         (commit 34)
  - Integration tests   (commit 35)
"""

import base64
import sys
import os
import time
from unittest.mock import MagicMock, patch

import pytest

# ── Ensure backend/ is importable ─────────────────────────────────────────────
_backend = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _backend not in sys.path:
    sys.path.insert(0, _backend)

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  SECTION 1 — DLP Engine Tests  (Commit 26)                             ║
# ╚══════════════════════════════════════════════════════════════════════════╝

class TestDLPEngine:
    def setup_method(self):
        from app.services.dlp_engine import DLPEngine
        self.dlp = DLPEngine(redact=True)

    def test_detects_email(self):
        r = self.dlp.scan("Contact us at admin@example.com for support.")
        assert r.has_leak
        assert any(l["type"] == "email" for l in r.leaks)

    def test_detects_jwt_token(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123XYZ"
        r = self.dlp.scan(f"Token: {jwt}")
        assert r.has_leak

    def test_detects_aws_access_key(self):
        r = self.dlp.scan("Key: AKIAIOSFODNN7EXAMPLE is exposed here")
        assert r.has_leak
        assert any(l["type"] == "aws_access_key" for l in r.leaks)

    def test_detects_private_key_header(self):
        r = self.dlp.scan("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK")
        assert r.has_leak
        assert any(l["type"] == "private_key_header" for l in r.leaks)

    def test_detects_ssn(self):
        r = self.dlp.scan("SSN: 123-45-6789")
        assert r.has_leak
        assert any(l["type"] == "ssn" for l in r.leaks)

    def test_redacts_detected_leak(self):
        r = self.dlp.scan("Email: user@test.com here")
        assert "[REDACTED:" in r.redacted_text
        assert "user@test.com" not in r.redacted_text

    def test_clean_text_no_leak(self):
        r = self.dlp.scan("The sky is blue and the grass is green.")
        assert not r.has_leak

    def test_highest_severity_is_max(self):
        # AWS key should score higher than email
        r = self.dlp.scan("AKIAIOSFODNN7EXAMPLE user@test.com")
        assert r.highest_severity >= 0.4

    def test_leak_types_property(self):
        r = self.dlp.scan("user@test.com AKIAIOSFODNN7EXAMPLE")
        types = r.leak_types
        assert isinstance(types, list)

    def test_stats_increment(self):
        before = self.dlp.get_stats()["total_scanned"]
        self.dlp.scan("hello")
        after = self.dlp.get_stats()["total_scanned"]
        assert after == before + 1


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  SECTION 2 — Threat Cache Tests  (Commit 27)                           ║
# ╚══════════════════════════════════════════════════════════════════════════╝

class TestThreatCache:
    def setup_method(self):
        from app.services.threat_cache import ThreatCache
        self.cache = ThreatCache(max_size=10, ttl_seconds=60.0)

    def test_miss_on_empty(self):
        result = self.cache.get("some unknown prompt")
        assert result is None

    def test_put_and_get(self):
        self.cache.put("ignore all previous", True, "injection", 0.9)
        entry = self.cache.get("ignore all previous")
        assert entry is not None
        assert entry.is_threat is True
        assert entry.threat_type == "injection"

    def test_normalisation_collapses_whitespace(self):
        self.cache.put("ignore  previous  instructions", True, "injection", 0.8)
        entry = self.cache.get("ignore previous instructions")
        assert entry is not None

    def test_case_insensitive_lookup(self):
        self.cache.put("IGNORE PREVIOUS", True, "injection", 0.8)
        entry = self.cache.get("ignore previous")
        assert entry is not None

    def test_ttl_expiry(self):
        short_cache = __import__("app.services.threat_cache", fromlist=["ThreatCache"]).ThreatCache(
            max_size=5, ttl_seconds=0.05
        )
        short_cache.put("test prompt", True, "jailbreak", 0.5)
        time.sleep(0.1)
        result = short_cache.get("test prompt")
        assert result is None

    def test_lru_eviction(self):
        tiny = __import__("app.services.threat_cache", fromlist=["ThreatCache"]).ThreatCache(
            max_size=3, ttl_seconds=60.0
        )
        tiny.put("prompt one", True, "a", 0.5)
        tiny.put("prompt two", True, "b", 0.5)
        tiny.put("prompt three", True, "c", 0.5)
        tiny.put("prompt four", True, "d", 0.5)  # evicts "prompt one"
        assert tiny.get("prompt one") is None
        assert tiny.get("prompt four") is not None

    def test_invalidate(self):
        self.cache.put("remove me", False, "none", 0.0)
        assert self.cache.get("remove me") is not None
        self.cache.invalidate("remove me")
        assert self.cache.get("remove me") is None

    def test_flush(self):
        self.cache.put("a", True, "x", 0.5)
        self.cache.put("b", True, "y", 0.5)
        removed = self.cache.flush()
        assert removed == 2
        assert len(self.cache) == 0

    def test_hit_rate_tracking(self):
        self.cache.put("known threat", True, "injection", 0.9)
        self.cache.get("known threat")   # hit
        self.cache.get("unknown")         # miss
        stats = self.cache.get_stats()
        assert stats["cache_hits"] >= 1
        assert stats["cache_misses"] >= 1


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  SECTION 3 — Anomaly Detector Tests  (Commit 28)                       ║
# ╚══════════════════════════════════════════════════════════════════════════╝

class TestAnomalyDetector:
    def setup_method(self):
        from app.services.anomaly_detector import AnomalyDetector
        self.det = AnomalyDetector(
            velocity_threshold=5,
            burst_threshold=3,
            burst_window=1.0,
            threat_ratio_threshold=0.6,
        )

    def test_no_anomaly_on_fresh_ip(self):
        result = self.det.check("1.2.3.4", "Hello there")
        assert result.is_anomalous is False

    def test_velocity_spike_detected(self):
        for _ in range(6):
            self.det.record("5.6.7.8", "prompt", False)
        result = self.det.check("5.6.7.8", "new prompt")
        signals = [s.signal for s in result.signals]
        assert "velocity_spike" in signals

    def test_burst_detected(self):
        for _ in range(4):
            self.det.record("9.9.9.9", "burst prompt", False)
        result = self.det.check("9.9.9.9", "another")
        signals = [s.signal for s in result.signals]
        assert "burst" in signals

    def test_high_threat_ratio(self):
        for _ in range(8):
            self.det.record("evil.ip", "jailbreak", True)
        for _ in range(2):
            self.det.record("evil.ip", "benign", False)
        result = self.det.check("evil.ip", "new prompt")
        signals = [s.signal for s in result.signals]
        assert "high_threat_ratio" in signals

    def test_prompt_repetition(self):
        for _ in range(4):
            self.det.record("rep.ip", "same prompt exactly", False)
        result = self.det.check("rep.ip", "same prompt exactly")
        signals = [s.signal for s in result.signals]
        assert "prompt_repetition" in signals

    def test_clear_ip(self):
        self.det.record("clear.me", "p", False)
        self.det.clear_ip("clear.me")
        result = self.det.check("clear.me", "p")
        assert result.is_anomalous is False


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  SECTION 4 — Input Sanitizer Tests  (Commit 29)                        ║
# ╚══════════════════════════════════════════════════════════════════════════╝

class TestInputSanitizer:
    def setup_method(self):
        from app.services.input_sanitizer import InputSanitizer
        self.s = InputSanitizer(max_chars=500)

    def test_strips_null_bytes(self):
        r = self.s.sanitize("hello\x00world")
        assert "\x00" not in r.sanitized_text
        assert "null_byte_removal" in r.transforms_applied

    def test_decodes_html_entities(self):
        r = self.s.sanitize("&lt;script&gt;alert(1)&lt;/script&gt;")
        assert "&lt;" not in r.sanitized_text
        assert "html_entity_decode" in r.transforms_applied

    def test_strips_html_tags(self):
        r = self.s.sanitize("<b>bold</b> and <script>evil()</script>")
        assert "<b>" not in r.sanitized_text
        assert "html_tag_strip" in r.transforms_applied

    def test_detects_script_event_handlers(self):
        r = self.s.sanitize('Say <div onclick="evil()">click</div>')
        assert "script_event_handler_detected" in r.flag_reasons

    def test_strips_sql_comments(self):
        r = self.s.sanitize("SELECT * FROM users -- drop table")
        assert "--" not in r.sanitized_text

    def test_collapses_path_traversal(self):
        r = self.s.sanitize("../../etc/passwd")
        assert "path_traversal_detected" in r.flag_reasons

    def test_truncates_at_max_chars(self):
        r = self.s.sanitize("A" * 1000)
        assert len(r.sanitized_text) <= 500
        assert "hard_truncation" in r.transforms_applied

    def test_clean_text_unchanged(self):
        text = "What is the capital of France?"
        r = self.s.sanitize(text)
        assert r.sanitized_text == text
        assert not r.was_modified


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  SECTION 5 — Circuit Breaker Tests  (Commit 30)                        ║
# ╚══════════════════════════════════════════════════════════════════════════╝

class TestCircuitBreaker:
    def setup_method(self):
        from app.services.circuit_breaker import CircuitBreaker, CircuitState
        self.CircuitState = CircuitState
        self.cb = CircuitBreaker("test", failure_threshold=3, reset_timeout_seconds=0.1)

    def test_starts_closed(self):
        snap = self.cb.get_snapshot()
        assert snap.state == self.CircuitState.CLOSED

    def test_successful_call_passes_through(self):
        result = self.cb.call(lambda: "ok")
        assert result == "ok"

    def test_opens_after_threshold_failures(self):
        from app.services.circuit_breaker import CircuitOpenError
        for _ in range(3):
            try:
                self.cb.call(lambda: (_ for _ in ()).throw(RuntimeError("fail")))
            except RuntimeError:
                pass
        snap = self.cb.get_snapshot()
        assert snap.state == self.CircuitState.OPEN

    def test_rejects_calls_when_open(self):
        from app.services.circuit_breaker import CircuitOpenError
        for _ in range(3):
            try:
                self.cb.call(lambda: (_ for _ in ()).throw(RuntimeError("fail")))
            except RuntimeError:
                pass
        with pytest.raises(CircuitOpenError):
            self.cb.call(lambda: "should not execute")

    def test_transitions_to_half_open_after_timeout(self):
        from app.services.circuit_breaker import CircuitOpenError
        for _ in range(3):
            try:
                self.cb.call(lambda: (_ for _ in ()).throw(RuntimeError("fail")))
            except RuntimeError:
                pass
        time.sleep(0.15)  # wait past reset_timeout_seconds=0.1
        snap = self.cb.get_snapshot()
        # Transition happens on next call attempt
        try:
            self.cb.call(lambda: "probe")
        except Exception:
            pass
        snap2 = self.cb.get_snapshot()
        assert snap2.state in (self.CircuitState.CLOSED, self.CircuitState.HALF_OPEN)

    def test_manual_reset_closes_circuit(self):
        from app.services.circuit_breaker import CircuitOpenError
        for _ in range(3):
            try:
                self.cb.call(lambda: (_ for _ in ()).throw(RuntimeError("fail")))
            except RuntimeError:
                pass
        self.cb.reset()
        assert self.cb.get_snapshot().state == self.CircuitState.CLOSED


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  SECTION 6 — Context Guard Tests  (Commit 31)                          ║
# ╚══════════════════════════════════════════════════════════════════════════╝

class TestContextGuard:
    def setup_method(self):
        from app.services.context_guard import ContextGuard
        self.guard = ContextGuard(max_tokens=100, padding_threshold=20, invisible_threshold=5)

    def test_safe_short_prompt_passes(self):
        r = self.guard.check("What is the speed of light?")
        assert not r.is_violation

    def test_token_overflow_detected(self):
        r = self.guard.check("word " * 500)
        assert r.is_violation
        assert "token_overflow" in r.violations

    def test_padding_bomb_detected(self):
        r = self.guard.check("A" * 50)
        assert "padding_bomb" in r.violations

    def test_invisible_char_flood_detected(self):
        invisible = "\u200b" * 10
        r = self.guard.check(f"hello {invisible} world")
        assert "invisible_char_flood" in r.violations

    def test_injection_depth_detected(self):
        payload = "[INST] outer [INST] middle [INST] inner [INST] deep"
        r = self.guard.check(payload)
        assert "deep_injection_nesting" in r.violations

    def test_token_estimate_returned(self):
        r = self.guard.check("hello world")
        assert r.estimated_tokens > 0


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  SECTION 7 — Admin & Audit Endpoints  (Commits 33–34)                  ║
# ╚══════════════════════════════════════════════════════════════════════════╝

class TestAdminEndpoints:
    def test_cache_status(self):
        resp = client.get("/api/admin/cache/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "size" in data
        assert "hit_rate_pct" in data

    def test_cache_flush(self):
        resp = client.post("/api/admin/cache/flush")
        assert resp.status_code == 200
        assert "entries_removed" in resp.json()

    def test_circuit_status(self):
        resp = client.get("/api/admin/circuit/status")
        assert resp.status_code == 200
        assert resp.json()["state"] in ("closed", "open", "half_open")

    def test_circuit_reset(self):
        resp = client.post("/api/admin/circuit/reset")
        assert resp.status_code == 200
        assert resp.json()["circuit"] == "closed"

    def test_dlp_test_probe_clean(self):
        resp = client.post("/api/admin/dlp/test", json={"text": "Hello world!"})
        assert resp.status_code == 200
        assert resp.json()["has_leak"] is False

    def test_dlp_test_probe_leak(self):
        resp = client.post("/api/admin/dlp/test", json={"text": "admin@example.com"})
        assert resp.status_code == 200
        assert resp.json()["has_leak"] is True

    def test_sanitizer_test_probe(self):
        resp = client.post("/api/admin/sanitizer/test", json={"text": "<b>Hello</b>"})
        assert resp.status_code == 200
        data = resp.json()
        assert "html_tag_strip" in data["transforms_applied"]

    def test_context_guard_test_probe(self):
        resp = client.post("/api/admin/context/test", json={"text": "A" * 2000})
        assert resp.status_code == 200
        assert "violations" in resp.json()

    def test_system_summary(self):
        resp = client.get("/api/admin/system/summary")
        assert resp.status_code == 200
        d = resp.json()
        assert "overall_health" in d
        assert "block_rate_pct" in d

    def test_audit_log(self):
        resp = client.get("/api/audit")
        assert resp.status_code == 200
        d = resp.json()
        assert "events" in d
        assert "total_in_buffer" in d

    def test_audit_summary(self):
        resp = client.get("/api/audit/summary")
        assert resp.status_code == 200
        d = resp.json()
        assert "by_event_type" in d
        assert "health_signal" in d

    def test_defense_metrics(self):
        resp = client.get("/api/defense/metrics")
        assert resp.status_code == 200
        d = resp.json()
        assert "overall_health" in d
        assert "core" in d
        assert "circuit_breaker" in d
