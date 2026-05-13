import json
from pathlib import Path


def test_golden_news_fixture_has_reviewable_coverage():
    fixture = Path(__file__).resolve().parent / "fixtures/golden_news_labels.jsonl"
    rows = [json.loads(line) for line in fixture.read_text().splitlines() if line.strip()]

    assert 50 <= len(rows) <= 100
    assert all(row.get("source_doc_id") for row in rows)
    assert all(row.get("text") for row in rows)
    assert all(isinstance(row.get("expected_labels"), list) for row in rows)
    assert {"Data Breach", "Exploited Vulnerability", "Phishing", "No Incident"} & {
        label
        for row in rows
        for label in row.get("expected_labels", [])
    }
