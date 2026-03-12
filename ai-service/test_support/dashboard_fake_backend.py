from __future__ import annotations

from copy import deepcopy
from datetime import datetime


def _parse_dt(value):
    if value is None:
        return None
    text = str(value)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text)


class FakeElasticClient:
    def __init__(self):
        self.datalake_index = "test-datalake"
        self.warehouse_index = "test-warehouse"
        self.processed_index = "test-processed"
        self.index_docs = {
            self.warehouse_index: {
                "wh-1": {
                    "ioc_value": "malicious.example",
                    "ioc_type": "domain",
                    "description": "Phishing domain impersonating government login",
                    "source_name": "AbuseIPDB,ThreatFox",
                    "ai_risk_score": 92,
                    "ai_severity": "critical",
                    "ai_threat_types": ["Phishing"],
                    "ai_threat_actors": ["Lazarus"],
                    "ai_top_factors": [
                        {
                            "factor": "cross_source",
                            "score": 25,
                            "weighted_score": 25,
                            "label": "Cross Source",
                        }
                    ],
                    "ai_score_breakdown": {
                        "target_sector": {
                            "sector": "government",
                            "sector_name": "Government",
                            "sector_name_th": "ภาครัฐ",
                            "icon": "🏛️",
                        }
                    },
                    "event_time": "2026-03-11T08:00:00Z",
                    "first_seen": "2026-03-10T08:00:00Z",
                    "last_seen": "2026-03-11T09:00:00Z",
                    "score_model_version": "v2.0.0",
                    "action_required": True,
                    "action_status": "open",
                    "action_title": "Review Critical Threat",
                    "action_reason": "critical_threat",
                    "action_opened_at": "2026-03-11T08:05:00Z",
                    "action_updated_at": "2026-03-11T08:05:00Z",
                },
                "wh-2": {
                    "ioc_value": "185.10.10.10",
                    "ioc_type": "ip",
                    "description": "Malware callback IP",
                    "source_name": "ThreatFox",
                    "ai_risk_score": 81,
                    "ai_severity": "high",
                    "ai_threat_types": ["Malware"],
                    "ai_threat_actors": ["APT28"],
                    "ai_top_factors": [
                        {
                            "factor": "threat_actor",
                            "score": 10,
                            "weighted_score": 10,
                            "label": "Threat Actor",
                        }
                    ],
                    "ai_score_breakdown": {
                        "target_sector": {
                            "sector": "financial",
                            "sector_name": "Financial",
                            "sector_name_th": "การเงิน",
                            "icon": "🏦",
                        }
                    },
                    "event_time": "2026-03-11T06:00:00Z",
                    "first_seen": "2026-03-11T06:00:00Z",
                    "last_seen": "2026-03-11T07:30:00Z",
                    "score_model_version": "v2.0.0",
                },
                "wh-review-1": {
                    "ioc_value": "suspicious-review.example",
                    "ioc_type": "domain",
                    "description": "Pending analyst review for phishing domain",
                    "source_name": "AbuseIPDB",
                    "ai_risk_score": 88,
                    "ai_severity": "critical",
                    "ai_threat_types": ["Phishing"],
                    "ai_threat_actors": ["Lazarus"],
                    "ai_classification_confidence": 0.96,
                    "processed_at": "2026-03-11T08:30:00Z",
                    "reviewed_by": None,
                    "reviewed_at": None,
                    "review_notes": None,
                    "first_seen": "2026-03-11T08:00:00Z",
                    "last_seen": "2026-03-11T08:30:00Z",
                },
            },
            self.datalake_index: {
                "dl-1": {
                    "ioc_value": "malicious.example",
                    "ioc_type": "domain",
                    "description": "Government phishing kit hosted on malicious.example",
                    "reference": "https://intel.example/phishing-1",
                    "source_name": "AbuseIPDB",
                    "severity": "critical",
                    "threat_type": ["Phishing"],
                    "event_time": "2026-03-11T08:15:00Z",
                    "collect_time": "2026-03-11T08:16:00Z",
                    "source_ip": "185.10.10.10",
                    "target_ip": "10.10.10.10",
                    "enrichment": {
                        "ip_info": {"country": "Russia"},
                        "related_entities": {"malware_family": ["AgentTesla"]},
                    },
                    "geo_info": {"city": "Moscow"},
                    "whois": {"org": "Example Registrar", "registrant_email": "abuse@example.net"},
                    "asn_data": {"asn": "AS64500", "org": "Example Hosting"},
                    "cluster_label": 7,
                },
                "dl-2": {
                    "ioc_value": "185.10.10.10",
                    "ioc_type": "ip",
                    "description": "Callback infrastructure for credential stealer",
                    "reference": "https://intel.example/malware-1",
                    "source_name": "ThreatFox",
                    "severity": "high",
                    "threat_type": ["Malware"],
                    "event_time": "2026-03-11T06:05:00Z",
                    "collect_time": "2026-03-11T06:06:00Z",
                    "source_ip": "185.10.10.10",
                    "target_ip": "172.16.0.10",
                    "enrichment": {"ip_info": {"country": "Singapore"}},
                    "asn_data": {"asn": "AS64510", "org": "Threat Hosting"},
                },
                "dl-3": {
                    "ioc_value": "https://news.example/article",
                    "ioc_type": "url",
                    "description": "TheHackerNews reports a phishing campaign against Thai agencies.",
                    "reference": "https://thehackernews.example/article-1",
                    "source_name": "TheHackerNews",
                    "source_type": "news",
                    "severity": "medium",
                    "threat_type": ["Phishing"],
                    "event_time": "2026-03-11T04:00:00Z",
                    "collect_time": "2026-03-11T04:05:00Z",
                },
                "dl-4": {
                    "ioc_value": "suspicious-review.example",
                    "ioc_type": "domain",
                    "description": "Analyst needs to confirm this government phishing indicator",
                    "reference": "https://intel.example/review-1",
                    "source_name": "AbuseIPDB",
                    "severity": "critical",
                    "threat_type": ["Phishing"],
                    "event_time": "2026-03-11T08:20:00Z",
                    "collect_time": "2026-03-11T08:21:00Z",
                    "source_ip": "203.0.113.10",
                    "target_ip": "10.10.99.10",
                    "enrichment": {"ip_info": {"country": "Thailand"}},
                },
            },
            self.processed_index: {},
        }

    def _extract_field(self, doc, field):
        current = doc
        for part in field.split("."):
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
        return current

    def _match_term(self, doc, field, value):
        current = self._extract_field(doc, field)
        if isinstance(current, list):
            return any(str(item).lower() == str(value).lower() for item in current)
        return str(current).lower() == str(value).lower()

    def _match_terms(self, doc, field, values):
        return any(self._match_term(doc, field, value) for value in values)

    def _match_range(self, doc, field, bounds):
        current = self._extract_field(doc, field)
        if current is None:
            return False
        current_dt = _parse_dt(current)
        if current_dt is None:
            return False
        lower = _parse_dt(bounds.get("gte")) if bounds.get("gte") else None
        upper = _parse_dt(bounds.get("lte")) if bounds.get("lte") else None
        if lower and current_dt < lower:
            return False
        if upper and current_dt > upper:
            return False
        return True

    def _match_multi(self, doc, query, fields):
        text = str(query).lower()
        haystack = []
        for field in fields:
            current = self._extract_field(doc, field.split("^")[0])
            if isinstance(current, list):
                haystack.extend(str(item).lower() for item in current)
            elif current is not None:
                haystack.append(str(current).lower())
        return any(text in item for item in haystack)

    def _match_clause(self, doc, clause):
        if "match_all" in clause:
            return True
        if "exists" in clause:
            field = clause["exists"]["field"]
            return self._extract_field(doc, field) is not None
        if "term" in clause:
            field, value = next(iter(clause["term"].items()))
            return self._match_term(doc, field, value)
        if "terms" in clause:
            field, values = next(iter(clause["terms"].items()))
            return self._match_terms(doc, field, values)
        if "range" in clause:
            field, bounds = next(iter(clause["range"].items()))
            return self._match_range(doc, field, bounds)
        if "multi_match" in clause:
            return self._match_multi(doc, clause["multi_match"]["query"], clause["multi_match"]["fields"])
        if "bool" in clause:
            return self._match_query(doc, clause["bool"])
        return True

    def _match_query(self, doc, bool_query):
        for clause in bool_query.get("must", []):
            if not self._match_clause(doc, clause):
                return False
        for clause in bool_query.get("filter", []):
            if not self._match_clause(doc, clause):
                return False
        for clause in bool_query.get("must_not", []):
            if self._match_clause(doc, clause):
                return False
        should = bool_query.get("should", [])
        if should:
            required = int(bool_query.get("minimum_should_match", 1))
            matches = sum(1 for clause in should if self._match_clause(doc, clause))
            if matches < required:
                return False
        return True

    def _select_docs(self, index):
        return list(self.index_docs[index].items())

    def search_index(self, index, body):
        docs = self._select_docs(index)
        query = body.get("query", {"match_all": {}})
        if "bool" in query:
            filtered = [(doc_id, doc) for doc_id, doc in docs if self._match_query(doc, query["bool"])]
        elif "match_all" in query:
            filtered = docs
        else:
            filtered = [(doc_id, doc) for doc_id, doc in docs if self._match_clause(doc, query)]

        start = int(body.get("from", 0))
        size = int(body.get("size", 10))
        hits = [
            {"_id": doc_id, "_source": deepcopy(doc)}
            for doc_id, doc in filtered[start:start + size]
        ]
        return {"hits": {"total": {"value": len(filtered)}, "hits": hits}}

    def get_index_document(self, index, doc_id):
        document = self.index_docs.get(index, {}).get(doc_id)
        return {"_id": doc_id, **deepcopy(document)} if document else None

    def get_warehouse_document(self, doc_id):
        document = self.index_docs[self.warehouse_index].get(doc_id)
        if not document:
            return None
        return {"_id": doc_id, **deepcopy(document)}

    def update_warehouse_document(self, doc_id, fields):
        document = self.index_docs[self.warehouse_index].get(doc_id)
        if not document:
            return False
        document.update(deepcopy(fields))
        return True

    def save_to_warehouse(self, document):
        doc_id = f"wh-{len(self.index_docs[self.warehouse_index]) + 1}"
        self.index_docs[self.warehouse_index][doc_id] = deepcopy(document)
        return doc_id
