import pytest
from app.services.pii_masker import pii_masker
from app.services.toxicity_scanner import toxicity_scanner
from app.services.fact_checker import fact_checker

def test_pii_masker_email():
    text = "Contact me at admin@neurosentry.com for access."
    masked, mapping = pii_masker.mask(text)
    assert "admin@neurosentry.com" not in masked
    assert "<EMAIL_1>" in masked
    assert mapping["<EMAIL_1>"] == "admin@neurosentry.com"

def test_toxicity_scanner_detects_hate():
    text = "I hate everyone here and want to destroy this."
    result = toxicity_scanner.scan(text)
    assert result is True

def test_toxicity_scanner_passes_benign():
    text = "This is a wonderful day to learn AI security."
    result = toxicity_scanner.scan(text)
    assert result is False

def test_fact_checker_hallucination():
    text = "It is a known fact that the earth is flat."
    result = fact_checker.verify(text)
    assert result["is_factual"] is False
    assert "oblate spheroid" in result["correction"].lower()
