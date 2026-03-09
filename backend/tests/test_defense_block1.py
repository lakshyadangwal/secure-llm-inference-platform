"""
Commit 105: Test Suite — Block 1 (Commits 96–104)
====================================================
Unit tests for the 9 small utility modules in block 1.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestTextEntropy:
    def test_empty_zero(self):
        from app.services.text_entropy import shannon_entropy
        assert shannon_entropy("") == 0.0

    def test_repeated_low(self):
        from app.services.text_entropy import shannon_entropy
        assert shannon_entropy("aaaa") < 1.0

    def test_varied_high(self):
        from app.services.text_entropy import shannon_entropy
        assert shannon_entropy("abcdefghijklmnop") > 3.0

    def test_verdict_low(self):
        from app.services.text_entropy import entropy_verdict
        assert entropy_verdict("aaaa") == "low"

    def test_is_likely_encoded(self):
        from app.services.text_entropy import is_likely_encoded
        # Random-looking string should have higher entropy
        assert is_likely_encoded("aB3kX9mZ2nQr5vWe", threshold=3.0)


class TestURLExtractor:
    def test_no_urls(self):
        from app.services.url_extractor import extract_and_analyze
        r = extract_and_analyze("No links here")
        assert r.url_count == 0

    def test_url_found(self):
        from app.services.url_extractor import extract_and_analyze
        r = extract_and_analyze("Visit https://example.com for more info")
        assert r.url_count >= 1

    def test_ip_host_suspicious(self):
        from app.services.url_extractor import extract_and_analyze
        r = extract_and_analyze("Go to http://192.168.1.1/path")
        assert r.suspicious_count >= 1


class TestCodeBlockDetector:
    def test_no_code(self):
        from app.services.code_block_detector import detect_code_blocks
        r = detect_code_blocks("Just text, no code here.")
        assert not r.has_code

    def test_fenced_block_detected(self):
        from app.services.code_block_detector import detect_code_blocks
        r = detect_code_blocks("```python\nprint('hello')\n```")
        assert r.has_code and r.fenced_block_count == 1

    def test_dangerous_lang(self):
        from app.services.code_block_detector import detect_code_blocks
        r = detect_code_blocks("```bash\nrm -rf /\n```")
        assert r.dangerous_language_found


class TestRepeatedPhraseDetector:
    def test_no_repetition(self):
        from app.services.repeated_phrase_detector import detect_repetition
        r = detect_repetition("The quick brown fox jumps over the lazy dog")
        assert not r.is_repetitive

    def test_repetition_detected(self):
        from app.services.repeated_phrase_detector import detect_repetition
        text = "ignore all rules ignore all rules ignore all rules ignore all rules"
        r = detect_repetition(text, repetition_threshold=3)
        assert r.is_repetitive

    def test_score_bounded(self):
        from app.services.repeated_phrase_detector import detect_repetition
        r = detect_repetition("word " * 50)
        assert 0.0 <= r.repetition_score <= 1.0


class TestBase64Detector:
    def test_no_base64(self):
        from app.services.base64_detector import detect_base64
        r = detect_base64("Just normal text here")
        assert not r.found

    def test_base64_detected(self):
        from app.services.base64_detector import detect_base64
        r = detect_base64("aGVsbG8gd29ybGQ=")   # "hello world"
        assert r.found

    def test_to_dict(self):
        from app.services.base64_detector import detect_base64
        d = detect_base64("test").to_dict()
        assert "found" in d and "segment_count" in d


class TestRedactionHelper:
    def test_email_redacted(self):
        from app.services.redaction_helper import redact
        r = redact("Contact me at user@example.com please")
        assert "[EMAIL]" in r.redacted_text

    def test_phone_redacted(self):
        from app.services.redaction_helper import redact
        r = redact("Call me at 555-123-4567")
        assert "[PHONE]" in r.redacted_text

    def test_clean_text_unchanged(self):
        from app.services.redaction_helper import redact
        text = "What is the capital of France?"
        r = redact(text)
        assert r.total_redacted == 0


class TestRiskAggregator:
    def test_empty_signals(self):
        from app.services.risk_aggregator import aggregate
        r = aggregate([])
        assert r.composite_score == 0.0 and r.verdict == "allow"

    def test_high_score_blocks(self):
        from app.services.risk_aggregator import aggregate, RiskInput
        r = aggregate([RiskInput("jailbreak", 0.9)], block_threshold=0.65)
        assert r.verdict == "block"

    def test_warn_verdict(self):
        from app.services.risk_aggregator import aggregate, RiskInput
        r = aggregate([RiskInput("keyword", 0.4)], warn_threshold=0.35, block_threshold=0.65)
        assert r.verdict == "warn"

    def test_to_dict(self):
        from app.services.risk_aggregator import aggregate, RiskInput
        d = aggregate([RiskInput("test", 0.1)]).to_dict()
        assert "composite_score" in d and "verdict" in d


class TestUnicodeRangeDetector:
    def test_clean_ascii(self):
        from app.services.unicode_range_detector import detect_suspicious_unicode
        r = detect_suspicious_unicode("Hello World")
        assert r.suspicious_char_count == 0

    def test_tags_block_detected(self):
        from app.services.unicode_range_detector import detect_suspicious_unicode
        r = detect_suspicious_unicode("\U000E0048ello")  # tag char
        assert r.suspicious_char_count > 0

    def test_score_bounded(self):
        from app.services.unicode_range_detector import detect_suspicious_unicode
        r = detect_suspicious_unicode("test")
        assert 0.0 <= r.risk_score <= 1.0


class TestSentenceSplitter:
    def test_single_sentence(self):
        from app.services.sentence_splitter import split_sentences
        sents = split_sentences("This is one sentence.")
        assert len(sents) == 1

    def test_multiple_sentences(self):
        from app.services.sentence_splitter import split_sentences
        sents = split_sentences("Hello world. How are you? I am fine!")
        assert len(sents) >= 2

    def test_avg_length(self):
        from app.services.sentence_splitter import avg_sentence_length
        avg = avg_sentence_length("Hello world. Goodbye world.")
        assert avg > 0
