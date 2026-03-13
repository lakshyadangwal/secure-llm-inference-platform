"""
Commit 95: Test Suite — Defense Batch 5
==========================================
Unit tests for all 9 batch-5 defense utility modules.
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ── token_counter ──────────────────────────────────────────────────────────────
class TestTokenCounter:
    def setup_method(self):
        from app.services.token_counter import count, fits_in_budget, truncate_to, TokenBudgetGuard
        self.count = count
        self.fits = fits_in_budget
        self.truncate = truncate_to
        self.guard = TokenBudgetGuard(max_tokens_per_session=50)

    def test_empty_string_zero(self):
        assert self.count("") == 0

    def test_single_word(self):
        assert self.count("hello") >= 1

    def test_fits_in_budget_true(self):
        assert self.fits("short text", 100)

    def test_fits_in_budget_false(self):
        long_text = "word " * 200
        assert not self.fits(long_text, 10)

    def test_truncate_reduces_length(self):
        long_text = "word " * 100
        truncated = self.truncate(long_text, 10)
        assert len(truncated) < len(long_text)

    def test_guard_consume_allows(self):
        allowed, used = self.guard.consume("user1", "hello world")
        assert allowed
        assert used >= 1

    def test_guard_consume_blocks_over_budget(self):
        self.guard.consume("user2", "word " * 100)  # far over 50 tokens
        # second call should fail
        allowed, _ = self.guard.consume("user2", "anything")
        assert not allowed

    def test_guard_reset(self):
        self.guard.consume("user3", "word " * 40)
        self.guard.reset("user3")
        assert self.guard.usage("user3") == 0


# ── prompt_sanitizer ──────────────────────────────────────────────────────────
class TestPromptSanitizer:
    def setup_method(self):
        from app.services.prompt_sanitizer import sanitize, normalize_unicode, is_safe_length
        self.sanitize = sanitize
        self.normalize = normalize_unicode
        self.safe_len = is_safe_length

    def test_null_bytes_removed(self):
        assert "\x00" not in self.sanitize("hello\x00world")

    def test_zero_width_removed(self):
        assert "\u200b" not in self.sanitize("hello\u200bworld")

    def test_html_tags_removed(self):
        result = self.sanitize("<script>alert(1)</script>hello")
        assert "<script>" not in result

    def test_length_limit(self):
        long = "a" * 100_000
        assert len(self.sanitize(long, max_length=100)) <= 100

    def test_is_safe_length_true(self):
        assert self.safe_len("short text")

    def test_is_safe_length_false_chars(self):
        assert not self.safe_len("x" * 100_000)


# ── response_length_guard ─────────────────────────────────────────────────────
class TestResponseLengthGuard:
    def setup_method(self):
        from app.services.response_length_guard import ResponseLengthGuard, LengthVerdict
        self.guard = ResponseLengthGuard(min_chars=10, max_chars=100)
        self.verdict = LengthVerdict

    def test_ok_verdict(self):
        result = self.guard.check("This is a normal length response.")
        assert result.verdict == self.verdict.OK

    def test_too_short(self):
        result = self.guard.check("hi")
        assert result.verdict == self.verdict.TOO_SHORT

    def test_too_long(self):
        result = self.guard.check("word " * 50)
        assert result.verdict == self.verdict.TOO_LONG

    def test_to_dict(self):
        d = self.guard.check("Hello world").to_dict()
        assert "verdict" in d and "char_count" in d


# ── blocklist_manager ─────────────────────────────────────────────────────────
class TestBlocklistManager:
    def setup_method(self):
        from app.services.blocklist_manager import BlocklistManager, MatchType
        self.mgr = BlocklistManager()
        self.MatchType = MatchType

    def test_seeded_rules_present(self):
        assert self.mgr.get_stats()["rule_count"] >= 10

    def test_exact_match_blocked(self):
        result = self.mgr.check("kill yourself")
        assert result.matched

    def test_clean_text_not_blocked(self):
        result = self.mgr.check("What is the weather in London today?")
        assert not result.matched

    def test_add_and_check_rule(self):
        self.mgr.add_rule("test_001", "test_cat", self.MatchType.EXACT, "forbidden phrase")
        result = self.mgr.check("this has a forbidden phrase in it")
        assert result.matched

    def test_remove_rule(self):
        self.mgr.add_rule("rem_001", "test", self.MatchType.EXACT, "removeme")
        self.mgr.remove_rule("rem_001")
        result = self.mgr.check("removeme")
        # Should not be in test category anymore
        assert "rem_001" not in (result.matched_rules or [])

    def test_to_dict(self):
        d = self.mgr.check("hello").to_dict()
        assert "matched" in d


# ── user_trust_scorer ─────────────────────────────────────────────────────────
class TestUserTrustScorer:
    def setup_method(self):
        from app.services.user_trust_scorer import UserTrustScorer
        self.scorer = UserTrustScorer()

    def test_initial_score_neutral(self):
        status = self.scorer.get_status("new_user")
        assert 0.40 <= status.score <= 0.60

    def test_positive_raises_score(self):
        self.scorer.record_positive("u1", delta=0.1)
        status = self.scorer.get_status("u1")
        assert status.score > 0.5

    def test_negative_lowers_score(self):
        self.scorer.record_negative("u2", delta=0.2)
        status = self.scorer.get_status("u2")
        assert status.score < 0.5

    def test_level_high(self):
        for _ in range(10):
            self.scorer.record_positive("u3", delta=0.1)
        status = self.scorer.get_status("u3")
        assert status.level == "HIGH"

    def test_level_untrust(self):
        for _ in range(10):
            self.scorer.record_negative("u4", delta=0.1)
        status = self.scorer.get_status("u4")
        assert status.level in ("LOW", "UNTRUST")

    def test_to_dict(self):
        d = self.scorer.get_status("u5").to_dict()
        assert "score" in d and "level" in d


# ── header_security_checker ───────────────────────────────────────────────────
class TestHeaderSecurityChecker:
    def setup_method(self):
        from app.services.header_security_checker import HeaderSecurityChecker
        self.checker = HeaderSecurityChecker(allowed_origins=["https://example.com"])

    def test_good_response_headers_pass(self):
        headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "Referrer-Policy": "no-referrer",
        }
        result = self.checker.check_response_headers(headers)
        assert result.passed

    def test_missing_headers_flagged(self):
        result = self.checker.check_response_headers({"X-Custom": "value"})
        assert not result.passed
        assert len(result.missing_headers) > 0

    def test_header_injection_flagged(self):
        result = self.checker.check_request_headers({"X-Custom": "value\r\nInjected: header"})
        assert not result.passed

    def test_clean_request_passes(self):
        result = self.checker.check_request_headers({"Content-Type": "application/json"})
        assert result.passed

    def test_invalid_origin_flagged(self):
        result = self.checker.check_request_headers({"origin": "https://evil.com"})
        assert not result.passed


# ── input_normalizer ──────────────────────────────────────────────────────────
class TestInputNormalizer:
    def setup_method(self):
        from app.services.input_normalizer import InputNormalizer
        self.norm = InputNormalizer()

    def test_lowercase_applied(self):
        result = self.norm.normalize("Hello World")
        assert result.normalized == result.normalized.lower()

    def test_contractions_expanded(self):
        result = self.norm.normalize("I don't want to")
        assert "do not" in result.normalized

    def test_whitespace_collapsed(self):
        result = self.norm.normalize("too    many   spaces")
        assert "  " not in result.normalized

    def test_steps_recorded(self):
        result = self.norm.normalize("Hello   World")
        assert len(result.steps_applied) > 0

    def test_to_dict(self):
        d = self.norm.normalize("test").to_dict()
        assert "normalized" in d and "steps_applied" in d


# ── defense_health_monitor ────────────────────────────────────────────────────
class TestDefenseHealthMonitor:
    def setup_method(self):
        from app.services.defense_health_monitor import DefenseHealthMonitor
        self.monitor = DefenseHealthMonitor()

    def test_register_and_check(self):
        self.monitor.register("test_mod", lambda: {"ok": True})
        report = self.monitor.check_all()
        names = [m.name for m in report.modules]
        assert "test_mod" in names

    def test_healthy_system(self):
        self.monitor.register("m1", lambda: {"x": 1})
        self.monitor.register("m2", lambda: {"y": 2})
        report = self.monitor.check_all()
        assert report.system_health.value in ("healthy", "degraded")

    def test_failing_module_flagged(self):
        from app.services.defense_health_monitor import ModuleHealth
        def bad_fn():
            raise RuntimeError("boom")
        self.monitor.register("failing_mod", bad_fn)
        status = self.monitor.check_module("failing_mod")
        assert status.health != ModuleHealth.OK

    def test_to_dict(self):
        self.monitor.register("d1", lambda: {})
        d = self.monitor.check_all().to_dict()
        assert "system_health" in d and "modules" in d


# ── allowlist_guard ───────────────────────────────────────────────────────────
class TestAllowlistGuard:
    def setup_method(self):
        from app.services.allowlist_guard import AllowlistGuard, AllowlistType
        self.guard = AllowlistGuard()
        self.Type = AllowlistType

    def test_exact_prompt_allowed(self):
        self.guard.add("e1", self.Type.EXACT_PROMPT, "What is 2+2?", "math")
        result = self.guard.check_prompt("What is 2+2?")
        assert result.allowed

    def test_regex_prompt_allowed(self):
        self.guard.add("r1", self.Type.REGEX_PROMPT, r"capital of \w+", "geography")
        result = self.guard.check_prompt("What is the capital of France?")
        assert result.allowed

    def test_unknown_prompt_not_allowed(self):
        result = self.guard.check_prompt("some completely random prompt")
        assert not result.allowed

    def test_user_allowlist(self):
        self.guard.add("u1", self.Type.USER_ID, "trusted_user_42", "trusted")
        assert self.guard.check_user("trusted_user_42").allowed
        assert not self.guard.check_user("random_user").allowed

    def test_api_key_prefix(self):
        self.guard.add("k1", self.Type.API_KEY_PREFIX, "trusted_", "internal")
        assert self.guard.check_api_key("trusted_abc123").allowed
        assert not self.guard.check_api_key("untrusted_key").allowed

    def test_remove_entry(self):
        self.guard.add("rem1", self.Type.USER_ID, "temp_user", "temp")
        self.guard.remove("rem1")
        assert not self.guard.check_user("temp_user").allowed

    def test_stats(self):
        stats = self.guard.get_stats()
        assert "entry_count" in stats and "total_checked" in stats
