import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.sanitizer import sanitize_observation_fields, sanitize_text  # noqa: E402


def test_sanitize_text_redacts_common_sensitive_values():
    result = sanitize_text(
        "Contact admin@example.com or +66 81-234-5678. "
        "Bearer abcdefghijklmnop secret and api_key=abc123456789 192.168.1.15"
    )

    assert "[REDACTED_EMAIL]" in result["text"]
    assert "[REDACTED_PHONE]" in result["text"]
    assert "Bearer [REDACTED_TOKEN]" in result["text"]
    assert "[REDACTED_SECRET]" in result["text"]
    assert "[REDACTED_PRIVATE_IP]" in result["text"]
    assert result["redaction_counts"]["email"] == 1
    assert result["redaction_counts"]["private_ip"] == 1


def test_sanitize_observation_fields_returns_summary_flags():
    result = sanitize_observation_fields(
        descriptions=["User john@example.com observed on 10.20.30.40"],
        references=["token=abcdef1234567890"],
        tags=["notify +66 99 999 9999", "malware"],
    )

    assert result["summary"]["sanitized"] is True
    assert "description" in result["summary"]["flagged_fields"]
    assert "reference" in result["summary"]["flagged_fields"]
    assert "tags" in result["summary"]["flagged_fields"]
    assert "redacted_email" in result["summary"]["flags"]
    assert "redacted_private_ip" in result["summary"]["flags"]
    assert "redacted_phone" in result["summary"]["flags"]
    assert any("[REDACTED_" in value for value in result["descriptions"])
    assert any("[REDACTED_" in value for value in result["references"])
