"""
Evaluate current pipeline classification against a golden news fixture.

Example:
  python scripts/ops/evaluate_golden_news_labels.py --fixture tests/fixtures/golden_news_labels.jsonl
"""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
from typing import Any, Dict, List, Set

import sys

AI_SERVICE_ROOT = Path(__file__).resolve().parents[2]
if str(AI_SERVICE_ROOT) not in sys.path:
    sys.path.insert(0, str(AI_SERVICE_ROOT))

from utils.pipeline_documents import build_enriched_ioc_document  # noqa: E402


def _load_fixture(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for line in path.read_text().splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def _doc_from_fixture(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "_id": row.get("source_doc_id"),
        "_index": row.get("source_index") or "golden-news",
        "adapter_name": "golden_news_fixture",
        "ioc_type": row.get("ioc_type") or "domain",
        "ioc_value": row.get("ioc_value") or row.get("source_doc_id") or "unknown.example",
        "source_name": row.get("source_name") or "Golden News",
        "source_type": "news",
        "description": "\n".join(part for part in [row.get("title"), row.get("text")] if part),
        "threat_type": [],
        "severity": "medium",
        "confidence": 0,
        "event_time": row.get("event_time") or "2026-01-01T00:00:00+00:00",
        "collect_time": row.get("collect_time") or "2026-01-01T00:00:00+00:00",
    }


def _score(expected: Set[str], predicted: Set[str]) -> Dict[str, Any]:
    if "No Incident" in expected:
        expected = set()
    matched = expected & predicted
    missing = expected - predicted
    extra = predicted - expected
    return {
        "matched": sorted(matched),
        "missing": sorted(missing),
        "extra": sorted(extra),
        "pass": not missing,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate pipeline against golden news labels.")
    parser.add_argument("--fixture", default=str(AI_SERVICE_ROOT / "tests/fixtures/golden_news_labels.jsonl"))
    parser.add_argument("--details", action="store_true")
    args = parser.parse_args()

    rows = _load_fixture(Path(args.fixture))
    failures: List[Dict[str, Any]] = []
    mode_counts: Counter[str] = Counter()
    label_counts: Counter[str] = Counter()
    passed = 0

    for row in rows:
        pipeline_doc = build_enriched_ioc_document([_doc_from_fixture(row)])["document"]
        predicted = set(pipeline_doc.get("ai_threat_types") or [])
        expected = set(row.get("expected_labels") or [])
        result = _score(expected, predicted)
        mode_counts[pipeline_doc.get("classification_mode") or "unknown"] += 1
        label_counts.update(predicted or ["<empty>"])
        if result["pass"]:
            passed += 1
        else:
            failures.append(
                {
                    "source_doc_id": row.get("source_doc_id"),
                    "title": row.get("title"),
                    "expected": sorted(expected),
                    "predicted": sorted(predicted),
                    "missing": result["missing"],
                    "extra": result["extra"],
                    "mode": pipeline_doc.get("classification_mode"),
                    "reason": pipeline_doc.get("classification_reason"),
                }
            )

    summary = {
        "total": len(rows),
        "passed": passed,
        "failed": len(failures),
        "recall_pass_rate": round((passed / len(rows)) * 100, 2) if rows else 0,
        "mode_counts": dict(mode_counts),
        "label_counts": dict(label_counts),
        "failures": failures if args.details else failures[:10],
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
