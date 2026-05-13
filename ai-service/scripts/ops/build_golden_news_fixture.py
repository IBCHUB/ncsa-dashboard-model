"""
Build a small golden-label fixture from real customer datalake news records.

The fixture is intentionally compact: it stores source/id/title/text snippets and
human-reviewable expected labels. Use this as a starting point, then edit the
expected labels when analysts disagree with the heuristic seed.

Example:
  python scripts/ops/build_golden_news_fixture.py --limit 80 --output tests/fixtures/golden_news_labels.jsonl
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Any, Dict, Iterable, List

import sys

AI_SERVICE_ROOT = Path(__file__).resolve().parents[2]
if str(AI_SERVICE_ROOT) not in sys.path:
    sys.path.insert(0, str(AI_SERVICE_ROOT))

from elastic_client import ElasticClient  # noqa: E402


NEWS_QUERIES = [
    {"match_phrase": {"source.name": "BleepingComputer News"}},
    {"match_phrase": {"source.name": "The Hacker News"}},
    {"match_phrase": {"source.name": "DarkReading"}},
]


def _text(raw: Dict[str, Any]) -> str:
    source = raw.get("source")
    first_source = source[0] if isinstance(source, list) and source and isinstance(source[0], dict) else {}
    return "\n".join(
        str(part or "").strip()
        for part in [
            first_source.get("title") or raw.get("title"),
            first_source.get("description") or raw.get("description"),
        ]
        if str(part or "").strip()
    )


def _expected_labels(text: str) -> List[str]:
    text = re.split(
        r"\b(Related Articles|Download The Report|Red Report \d{4}|Visit Advertiser|Continue watching after the ad|GO TO PAGE)\b",
        text,
        maxsplit=1,
        flags=re.IGNORECASE,
    )[0][:1800]
    lowered = text.lower()
    labels: List[str] = []
    if re.search(
        r"\bhow\s+to\s+(use|install|remove|scan|clean)\b|\bremoval\s+guide\b|"
        r"\btable\s+of\s+contents\b|\bkali\s+linux\s+\d{4}\.\d+\w*\s+released\b|"
        r"\bannual\s+theme\s+refresh\b|\byou\s+consumed\s+your\s+\d+\s+free\s+requests\b|"
        r"\bsmart\s+proxy\s+subscription\b",
        lowered,
    ):
        return ["No Incident"]
    if any(token in lowered for token in ("data theft", "data breach", "stolen data", "leaked data", "extortion", "shinyhunters")):
        labels.append("Data Breach")
    if any(token in lowered for token in ("remote code execution", " rce ", "command injection", "arbitrary code", "arbitrary commands")):
        labels.append("Remote Code Execution")
    if any(token in lowered for token in ("cve-", "actively exploited", "known exploited", "kev", "vulnerability", "critical flaw", "exploit kit", "exploit chain", "hard-coded flaw", "vendor flaw")):
        if "Data Breach" not in labels or any(token in lowered for token in ("cve-", "remote code execution", "known exploited", "kev", "exploit kit", "exploit chain")):
            labels.append("Exploited Vulnerability")
    if "phishing" in lowered:
        labels.append("Phishing")
    if "ransomware" in lowered:
        labels.append("Ransomware")
    if re.search(r"\bapt\d*\b|\bstate-sponsored\b|\bnation-state\b", lowered):
        labels.append("APT")
    if any(token in lowered for token in ("deploy malware", "deployed malware", "malware campaign", "backdoor", "trojan", "infostealer", "stealer")):
        labels.append("Malware")
    return list(dict.fromkeys(labels)) or ["Other"]


def _fetch_news(client: ElasticClient, per_query: int) -> Iterable[Dict[str, Any]]:
    seen = set()
    for query in NEWS_QUERIES:
        result = client.search_index(
            client.datalake_index,
            {"query": query, "size": per_query, "sort": [{"_doc": {"order": "asc"}}]},
        )
        for hit in result.get("hits", {}).get("hits", []):
            doc_id = hit.get("_id")
            if doc_id in seen:
                continue
            seen.add(doc_id)
            yield hit


def main() -> int:
    parser = argparse.ArgumentParser(description="Build golden news label fixture from datalake.")
    parser.add_argument("--limit", type=int, default=80)
    parser.add_argument("--output", default=str(AI_SERVICE_ROOT / "tests/fixtures/golden_news_labels.jsonl"))
    parser.add_argument("--max-text-chars", type=int, default=1400)
    args = parser.parse_args()

    client = ElasticClient()
    rows: List[Dict[str, Any]] = []
    for hit in _fetch_news(client, per_query=max(args.limit, 20)):
        raw = hit.get("_source", {})
        text = _text(raw)
        if not text:
            continue
        fixture_text = re.split(
            r"\b(Related Articles|Download The Report|Red Report \d{4}|Visit Advertiser|Continue watching after the ad|GO TO PAGE)\b",
            text,
            maxsplit=1,
            flags=re.IGNORECASE,
        )[0][: args.max_text_chars]
        normalized = ElasticClient._normalize_datalake_hit(hit)
        rows.append(
            {
                "source_doc_id": hit.get("_id"),
                "source_index": hit.get("_index"),
                "source_name": normalized.get("source_name"),
                "ioc_type": normalized.get("ioc_type"),
                "ioc_value": normalized.get("ioc_value"),
                "title": (raw.get("source") or [{}])[0].get("title") if isinstance(raw.get("source"), list) else raw.get("title"),
                "text": fixture_text,
                "expected_labels": _expected_labels(fixture_text),
                "review_status": "heuristic_seed",
            }
        )
        if len(rows) >= args.limit:
            break

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n")
    print(json.dumps({"output": str(output_path), "records": len(rows)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
