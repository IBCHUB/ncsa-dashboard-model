"""
Elasticsearch Client for AI Service

Provides connection to Elasticsearch for:
- Data Lake (raw/semi-processed IOCs)
- Data Warehouse (AI-processed IOCs)

Supports external ELK stack with per-index API key authentication.
"""

import os
import copy
import json
import logging
from typing import Dict, Any, List, Optional, Sequence, Tuple
from datetime import datetime, timezone
import hashlib
import base64
import re
from urllib.parse import quote

from datalake_adapters import normalize_datalake_hit

try:
    import httpx
except ImportError:  # pragma: no cover - tests can exercise pure helpers without HTTP clients
    httpx = None

logger = logging.getLogger(__name__)


def json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))

# Configuration
ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
DATALAKE_ELASTICSEARCH_URL = os.getenv("DATALAKE_ELASTICSEARCH_URL", ELASTICSEARCH_URL)
WAREHOUSE_ELASTICSEARCH_URL = os.getenv("WAREHOUSE_ELASTICSEARCH_URL", ELASTICSEARCH_URL)
DATALAKE_INDEX = os.getenv("DATALAKE_INDEX", "cyber-logs-datalake")
WAREHOUSE_INDEX = os.getenv("WAREHOUSE_INDEX", "cyber-logs-datawarehouse")
PIPELINE_WAREHOUSE_INDEX = os.getenv("PIPELINE_WAREHOUSE_INDEX", WAREHOUSE_INDEX)
PROCESSED_INDEX = os.getenv("PROCESSED_INDEX", "cyber-logs-processed")
QUARANTINE_INDEX = os.getenv("QUARANTINE_INDEX", "cyber-logs-quarantine")
ML_FEEDBACK_INDEX = os.getenv("ML_FEEDBACK_INDEX", "cyber-logs-ml-feedback")
DATALAKE_QUERY_MODE = os.getenv("DATALAKE_QUERY_MODE", "ai_processed_false")
DATALAKE_READONLY = os.getenv("DATALAKE_READONLY", "false").lower() == "true"
DATALAKE_SCAN_BATCH_SIZE = int(os.getenv("DATALAKE_SCAN_BATCH_SIZE", "200"))
DATALAKE_SCAN_MAX_PAGES = int(os.getenv("DATALAKE_SCAN_MAX_PAGES", "50"))
DATALAKE_SCAN_USE_CURSOR = os.getenv("DATALAKE_SCAN_USE_CURSOR", "true").lower() == "true"
DATALAKE_SCAN_CURSOR_ID = os.getenv("DATALAKE_SCAN_CURSOR_ID", "datalake-readonly-default")
ELASTIC_BULK_CHUNK_SIZE = int(os.getenv("ELASTIC_BULK_CHUNK_SIZE", "500"))

# API Keys (Per-index access)
DATALAKE_API_KEY = os.getenv("DATALAKE_API_KEY", "")
WAREHOUSE_API_KEY = os.getenv("WAREHOUSE_API_KEY", "")
DATALAKE_USERNAME = os.getenv("DATALAKE_USERNAME", "")
DATALAKE_PASSWORD = os.getenv("DATALAKE_PASSWORD", "")
WAREHOUSE_USERNAME = os.getenv("WAREHOUSE_USERNAME", "")
WAREHOUSE_PASSWORD = os.getenv("WAREHOUSE_PASSWORD", "")

# Try to import elasticsearch, fallback to httpx if not available
try:
    from elasticsearch import Elasticsearch
    ES_CLIENT_AVAILABLE = True
except ImportError:
    ES_CLIENT_AVAILABLE = False


class ElasticClient:
    """
    Elasticsearch client wrapper for TCTI platform.
    
    Supports two indices with separate API keys:
    - DATALAKE_INDEX (cyber-logs-datalake): Raw IOCs, Input
    - WAREHOUSE_INDEX (cyber-logs-datawarehouse): Enriched IOCs, Output
    """
    
    def __init__(self, url: str = ELASTICSEARCH_URL):
        self.url = url
        self.datalake_url = DATALAKE_ELASTICSEARCH_URL
        self.warehouse_url = WAREHOUSE_ELASTICSEARCH_URL
        self.datalake_index = DATALAKE_INDEX
        self.warehouse_index = WAREHOUSE_INDEX
        self.pipeline_warehouse_index = PIPELINE_WAREHOUSE_INDEX
        
        self.datalake_api_key = DATALAKE_API_KEY
        self.warehouse_api_key = WAREHOUSE_API_KEY
        self.datalake_basic_auth = (
            (DATALAKE_USERNAME, DATALAKE_PASSWORD)
            if DATALAKE_USERNAME and DATALAKE_PASSWORD
            else None
        )
        self.warehouse_basic_auth = (
            (WAREHOUSE_USERNAME, WAREHOUSE_PASSWORD)
            if WAREHOUSE_USERNAME and WAREHOUSE_PASSWORD
            else None
        )
        
        if ES_CLIENT_AVAILABLE:
            self.datalake_client = Elasticsearch(
                self.datalake_url,
                basic_auth=self.datalake_basic_auth,
                request_timeout=30,
            )
            self.warehouse_client = Elasticsearch(
                self.warehouse_url,
                basic_auth=self.warehouse_basic_auth,
                request_timeout=30,
            )
            self.client = self.warehouse_client
        else:
            self.client = None
            self.datalake_client = None
            self.warehouse_client = None
            logger.warning("elasticsearch-py not installed, using httpx fallback")
    
    def _get_api_key(self, index: str) -> Optional[str]:
        """Get API Key for specific index."""
        if index == self.datalake_index:
            return self.datalake_api_key
        elif index in (self.warehouse_index, PROCESSED_INDEX, QUARANTINE_INDEX, ML_FEEDBACK_INDEX):
            return self.warehouse_api_key
        return None

    def _get_client(self, index: str):
        """Get Elasticsearch client configured for specific index."""
        if not ES_CLIENT_AVAILABLE:
            return None

        client = self.datalake_client if index == self.datalake_index else self.warehouse_client
        if not client:
            return None

        api_key = self._get_api_key(index)
        if api_key:
            return client.options(api_key=api_key)
        return client

    def _get_url(self, index: str) -> str:
        return self.datalake_url if index == self.datalake_index else self.warehouse_url

    def _get_basic_auth(self, index: str) -> Optional[tuple]:
        return self.datalake_basic_auth if index == self.datalake_index else self.warehouse_basic_auth

    def _get_headers(self, index: str) -> Dict[str, str]:
        """Get HTTP headers for httpx fallback."""
        headers = {"Content-Type": "application/json"}
        api_key = self._get_api_key(index)
        if api_key:
            headers["Authorization"] = f"ApiKey {api_key}"
            return headers
        basic_auth = self._get_basic_auth(index)
        if basic_auth:
            raw = f"{basic_auth[0]}:{basic_auth[1]}".encode("utf-8")
            headers["Authorization"] = f"Basic {base64.b64encode(raw).decode('ascii')}"
        return headers

    def _bulk_request(
        self,
        index: str,
        operations: Sequence[Dict[str, Any]],
        *,
        refresh: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Execute Elasticsearch bulk operations with the correct endpoint/auth.

        ``refresh`` accepts ES values ``"true"``, ``"false"``, or
        ``"wait_for"`` and is appended as ``?refresh=...`` on the bulk URL.
        Use ``"wait_for"`` when the next operation in the same iteration
        needs to read/update the docs just written (e.g. clustering pass
        after bulk-index) — avoids ``document_missing_exception``.
        """
        if not operations:
            return {"success": 0, "failed": 0, "failed_ids": []}

        lines: List[str] = []
        for operation in operations:
            lines.append(json_dumps(operation["action"]))
            source = operation.get("source")
            if source is not None:
                lines.append(json_dumps(source))
        payload = "\n".join(lines) + "\n"

        if httpx is None:
            raise RuntimeError("httpx is required for bulk requests")

        url = f"{self._get_url(index)}/_bulk"
        if refresh:
            url = f"{url}?refresh={refresh}"
        response = httpx.post(
            url,
            content=payload,
            timeout=60,
            headers={**self._get_headers(index), "Content-Type": "application/x-ndjson"},
        )
        response.raise_for_status()
        body = response.json()
        success = 0
        failed_ids: List[str] = []
        for item in body.get("items", []) or []:
            result = next(iter(item.values()), {})
            status = int(result.get("status") or 0)
            doc_id = str(result.get("_id") or "")
            if 200 <= status < 300:
                success += 1
            else:
                if doc_id:
                    failed_ids.append(doc_id)
                logger.error("Bulk operation failed for %s: %s", doc_id, result.get("error"))
        return {
            "success": success,
            "failed": len(failed_ids),
            "failed_ids": failed_ids,
            "errors": bool(body.get("errors")),
        }

    @staticmethod
    def _bulk_operation_id(operation: Dict[str, Any]) -> str:
        action = operation.get("action") or {}
        for body in action.values():
            if isinstance(body, dict) and body.get("_id"):
                return str(body["_id"])
        return ""

    def _bulk_request_chunked(
        self,
        index: str,
        operations: Sequence[Dict[str, Any]],
        *,
        chunk_size: Optional[int] = None,
        refresh: Optional[str] = None,
    ) -> Dict[str, Any]:
        chunk_size = max(1, chunk_size or ELASTIC_BULK_CHUNK_SIZE)
        total_success = 0
        failed_ids: List[str] = []
        for start in range(0, len(operations), chunk_size):
            chunk = list(operations[start:start + chunk_size])
            try:
                result = self._bulk_request(index, chunk, refresh=refresh)
                total_success += int(result.get("success", 0) or 0)
                failed_ids.extend(str(item) for item in result.get("failed_ids", []) or [])
            except Exception as e:
                chunk_failed_ids = [
                    doc_id
                    for doc_id in (self._bulk_operation_id(operation) for operation in chunk)
                    if doc_id
                ]
                logger.error(
                    "Bulk chunk failed for index=%s size=%s: %s",
                    index,
                    len(chunk),
                    e,
                )
                failed_ids.extend(chunk_failed_ids)
        return {
            "success": total_success,
            "failed": len(failed_ids),
            "failed_ids": failed_ids,
            "errors": bool(failed_ids),
        }

    def _search_index(self, index: str, body: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a search against a specific index."""
        client = self._get_client(index)
        if ES_CLIENT_AVAILABLE and client:
            return client.search(index=index, body=body)

        response = httpx.post(
            f"{self._get_url(index)}/{index}/_search",
            json=body,
            timeout=30,
            headers=self._get_headers(index)
        )
        response.raise_for_status()
        return response.json()

    def search_index(self, index: str, body: Dict[str, Any]) -> Dict[str, Any]:
        """Public wrapper for raw index searches used by dashboard-facing APIs."""
        return self._search_index(index, body)

    def scroll_search(
        self,
        index: str,
        body: Dict[str, Any],
        page_size: int = 2000,
        max_docs: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Fetch matching documents using scroll API. Returns list of hits.

        If *max_docs* is set, scrolling stops as soon as that many documents
        have been collected (the scroll context is cleared before returning).
        This prevents the background export from pulling millions of docs when
        the caller has already validated an upper-bound row limit.
        """
        body = {**body, "size": page_size}
        body.pop("from", None)
        all_hits: List[Dict[str, Any]] = []
        client = self._get_client(index)

        def _limit_reached() -> bool:
            return max_docs is not None and len(all_hits) >= max_docs

        if ES_CLIENT_AVAILABLE and client:
            result = client.search(index=index, body=body, scroll="2m")
            scroll_id = result.get("_scroll_id")
            hits = result.get("hits", {}).get("hits", [])
            all_hits.extend(hits)
            while hits and not _limit_reached():
                result = client.scroll(scroll_id=scroll_id, scroll="2m")
                scroll_id = result.get("_scroll_id")
                hits = result.get("hits", {}).get("hits", [])
                all_hits.extend(hits)
            if scroll_id:
                try:
                    client.clear_scroll(scroll_id=scroll_id)
                except Exception:
                    pass
            return all_hits[:max_docs] if max_docs is not None else all_hits

        url = self._get_url(index)
        headers = self._get_headers(index)
        response = httpx.post(
            f"{url}/{index}/_search?scroll=2m",
            json=body,
            timeout=60,
            headers=headers,
        )
        response.raise_for_status()
        result = response.json()
        scroll_id = result.get("_scroll_id")
        hits = result.get("hits", {}).get("hits", [])
        all_hits.extend(hits)
        while hits and not _limit_reached():
            response = httpx.post(
                f"{url}/_search/scroll",
                json={"scroll": "2m", "scroll_id": scroll_id},
                timeout=60,
                headers=headers,
            )
            response.raise_for_status()
            result = response.json()
            scroll_id = result.get("_scroll_id")
            hits = result.get("hits", {}).get("hits", [])
            all_hits.extend(hits)
        if scroll_id:
            try:
                httpx.delete(
                    f"{url}/_search/scroll",
                    json={"scroll_id": scroll_id},
                    timeout=10,
                    headers=headers,
                )
            except Exception:
                pass
        return all_hits[:max_docs] if max_docs is not None else all_hits

    def _get_document(self, index: str, doc_id: str) -> Optional[Dict[str, Any]]:
        client = self._get_client(index)
        if ES_CLIENT_AVAILABLE and client:
            try:
                result = client.get(index=index, id=doc_id)
            except Exception as e:
                if getattr(e, "status_code", None) == 404:
                    return None
                raise
            if not result.get("found"):
                return None
            return {"_id": result.get("_id"), **result.get("_source", {})}

        response = httpx.get(
            f"{self._get_url(index)}/{index}/_doc/{quote(doc_id, safe='')}",
            timeout=30,
            headers=self._get_headers(index)
        )
        if response.status_code == 404:
            return None
        response.raise_for_status()
        body = response.json()
        if not body.get("found", True):
            return None
        return {"_id": body.get("_id", doc_id), **body.get("_source", {})}

    def get_index_document(self, index: str, doc_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single document from any configured index."""
        return self._get_document(index, doc_id)

    def _update_document(self, index: str, doc_id: str, fields: Dict[str, Any]) -> bool:
        client = self._get_client(index)
        if ES_CLIENT_AVAILABLE and client:
            client.update(index=index, id=doc_id, body={"doc": fields})
            return True

        response = httpx.post(
            f"{self._get_url(index)}/{index}/_update/{quote(doc_id, safe='')}",
            json={"doc": fields},
            timeout=30,
            headers=self._get_headers(index)
        )
        return response.status_code == 200

    def count_documents(self, index: str) -> int:
        """Count documents in a specific index with the correct API key."""
        try:
            client = self._get_client(index)
            if ES_CLIENT_AVAILABLE and client:
                result = client.count(index=index, query={"match_all": {}})
                return int(result.get("count", 0))

            response = httpx.get(
                f"{self._get_url(index)}/{index}/_count",
                headers=self._get_headers(index),
                timeout=30,
            )
            response.raise_for_status()
            return int(response.json().get("count", 0))
        except Exception as e:
            logger.error(f"Failed to count index {index}: {e}")
            return 0

    def health_check(self) -> Dict[str, Any]:
        """Check index accessibility without requiring cluster-level permissions."""
        statuses: Dict[str, str] = {}
        available = 0

        for index in [self.datalake_index, self.warehouse_index, PROCESSED_INDEX]:
            try:
                self._search_index(index, {"size": 0, "query": {"match_all": {}}})
                statuses[index] = "available"
                available += 1
            except Exception as e:
                logger.error(f"Health check failed for {index}: {e}")
                statuses[index] = "error"

        if available >= 2 and statuses.get(self.datalake_index) == "available" and statuses.get(self.warehouse_index) == "available":
            status = "green"
        elif available:
            status = "degraded"
        else:
            status = "unavailable"

        try:
            return {
                "status": status,
                "indices": statuses,
                "available": available > 0
            }
        except Exception as e:
            logger.error(f"Elasticsearch health check failed: {e}")
            return {"status": "unavailable", "error": str(e)}

    @staticmethod
    def normalize_ioc_type(ioc_type: Any) -> str:
        value = str(ioc_type or "unknown").strip().lower()
        aliases = {
            "ip_addresses": "ip",
            "ip_address": "ip",
            "ip-src": "ip",
            "ip-dst": "ip",
            "ipv4": "ip",
            "ipv6": "ip",
            "hostname": "domain",
            "domain|ip": "domain",
            "domains": "domain",
            "urls": "url",
            "uri": "url",
            "link": "url",
            "md5": "md5",
            "sha1": "sha1",
            "sha256": "sha256",
            "sha-1": "sha1",
            "sha-256": "sha256",
            "filename|md5": "md5",
            "filename|sha1": "sha1",
            "filename|sha256": "sha256",
            "file/sha1": "sha1",
            "file/sha256": "sha256",
            "hash/sha1": "sha1",
            "hash/sha256": "sha256",
        }
        return aliases.get(value, value or "unknown")

    @staticmethod
    def normalize_ioc_value(ioc_value: Any) -> str:
        value = str(ioc_value or "").strip()
        if not value:
            return ""

        value = value.replace("hxxps://", "https://").replace("hxxp://", "http://")
        value = value.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
        value = value.replace("[://]", "://")
        value = re.sub(r"\s+", "", value)
        return value.lower()

    @classmethod
    def canonical_ioc_key(cls, doc: Dict[str, Any]) -> str:
        return f"{cls.normalize_ioc_type(doc.get('ioc_type'))}:{cls.normalize_ioc_value(doc.get('ioc_value'))}"

    @staticmethod
    def _build_warehouse_doc_id(ioc_data: Dict[str, Any]) -> str:
        ioc_type = ElasticClient.normalize_ioc_type(ioc_data.get("ioc_type"))
        ioc_value = ElasticClient.normalize_ioc_value(ioc_data.get("ioc_value"))
        payload = f"{ioc_type}:{ioc_value}".encode("utf-8")
        digest = hashlib.sha256(payload).hexdigest()[:24]
        return f"{ioc_type}:{digest}"

    @staticmethod
    def _build_datalake_doc_id(doc: Dict[str, Any]) -> str:
        ioc_type = ElasticClient.normalize_ioc_type(doc.get("ioc_type"))
        ioc_value = ElasticClient.normalize_ioc_value(doc.get("ioc_value"))
        source = str(doc.get("source_name", "unknown")).strip().lower()
        source_type = str(doc.get("source_type", "unknown")).strip().lower()
        event_time = str(doc.get("event_time", "")).strip()
        collect_time = str(doc.get("collect_time", "")).strip()
        reference = str(doc.get("reference", "")).strip()
        # Hash everything (including ioc_value) — raw IOC values can be 300+
        # byte URLs which blow past ES's 512-byte doc_id limit when embedded
        # verbatim. The hash gives a fixed 40-char id while still being
        # unique per (ioc, source, event-time, ...) observation.
        fingerprint_src = (
            f"{ioc_type}|{ioc_value}|{source}|{source_type}|"
            f"{event_time}|{collect_time}|{reference}|"
            f"{str(doc.get('description', ''))[:256]}"
        )
        digest = hashlib.sha256(fingerprint_src.encode("utf-8")).hexdigest()
        return f"{ioc_type}:{digest[:32]}"

    @staticmethod
    def _build_processed_state_id(doc: Dict[str, Any]) -> str:
        source_index = str(doc.get("_index") or doc.get("source_index") or DATALAKE_INDEX).strip()
        source_doc_id = str(
            doc.get("_id")
            or doc.get("source_doc_id")
            or doc.get("source_id")
            or doc.get("id")
            or doc.get("source_fingerprint")
            or ElasticClient.canonical_ioc_key(doc)
        ).strip()
        payload = f"{source_index}:{source_doc_id}"
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        return f"src:{digest[:40]}"
    
    def create_indexes(self) -> Dict[str, bool]:
        """Create indexes if they don't exist."""
        results = {}
        
        # Mappings omitted for brevity, logic remains same but uses _get_client(index)
        # Note: We rely on pre-created indices or permissions to create them.
        
        # Data Lake index mapping
        datalake_mapping = {
            "mappings": {
                "dynamic": False, 
                "properties": {
                    "ioc_value": {"type": "keyword"},
                    "ioc_type": {"type": "keyword"},
                    "canonical_ioc_key": {"type": "keyword"},
                    "original_ioc_values": {"type": "keyword"},
                    "original_ioc_types": {"type": "keyword"},
                    "source_name": {"type": "keyword"},
                    "source_type": {"type": "keyword"},
                    "description": {"type": "text"},
                    "threat_type": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "tags": {"type": "keyword"},
                    "reference": {"type": "text"},
                    "collect_time": {"type": "date"},
                    "event_time": {"type": "date"},
                    "geo_country": {"type": "keyword"},
                    "ai_processed": {"type": "boolean"},
                    "created_at": {"type": "date"},
                    # Source confidence & traceability
                    "confidence": {"type": "integer"},
                    "source_url": {"type": "keyword"},
                    "source_id": {"type": "keyword"},
                    "partner_id": {"type": "keyword"},
                    "submitted_by_partner": {"type": "keyword"},
                    "tlp": {"type": "keyword"},
                    "published_at": {"type": "date"},
                    "last_shared_at": {"type": "date"},
                    "revoked_at": {"type": "date"},
                    "sharing_status": {"type": "keyword"},
                    # IOC relationships
                    "related_hash": {"type": "keyword"},
                    "related_domain": {"type": "keyword"},
                    # Computed from enrichment
                    "domain_age_days": {"type": "integer"},
                    # Enrichment blob (stored in _source, not indexed)
                    "enrichment": {"type": "object", "enabled": False}
                }
            }
        }
        
        # Data Warehouse index mapping
        warehouse_mapping = {
            "mappings": {
                "properties": {
                    "ioc_value": {"type": "keyword"},
                    "ioc_type": {"type": "keyword"},
                    "source_name": {"type": "keyword"},
                    "source_type": {"type": "keyword"},
                    "sources": {"type": "keyword"},
                    "source_types": {"type": "keyword"},
                    "source_count": {"type": "integer"},
                    "source_urls": {"type": "keyword"},
                    "description": {"type": "text"},
                    "threat_type": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "tags": {"type": "keyword"},
                    "reference": {"type": "text"},
                    "collect_time": {"type": "date"},
                    "event_time": {"type": "date"},
                    "first_seen": {"type": "date"},
                    "last_seen": {"type": "date"},
                    "ioc_age_days": {"type": "integer"},
                    "geo_country": {"type": "keyword"},
                    "target_sector": {"type": "keyword"},
                    "target_sector_name": {"type": "keyword"},
                    "target_sector_name_th": {"type": "keyword"},
                    "target_sector_icon": {"type": "keyword"},
                    "ai_risk_score": {"type": "integer"},
                    "ai_severity": {"type": "keyword"},
                    "ai_severity_th": {"type": "keyword"},
                    "score_model_version": {"type": "keyword"},
                    "score_config_version": {"type": "keyword"},
                    "credibility_score": {"type": "integer"},
                    "impact_score": {"type": "integer"},
                    "ai_threat_types": {"type": "keyword"},
                    "ai_threat_actors": {"type": "keyword"},
                    "ai_mitre_techniques": {"type": "keyword"},
                    "ai_classification_confidence": {"type": "float"},
                    "source_risk_score": {"type": "integer"},
                    "source_actionable": {"type": "boolean"},
                    "external_evidence_sources": {"type": "keyword"},
                    "virustotal_malicious": {"type": "integer"},
                    "virustotal_suspicious": {"type": "integer"},
                    "related_doc_count": {"type": "integer"},
                    "source_campaigns": {"type": "keyword"},
                    "source_target_countries": {"type": "keyword"},
                    "source_malware_family": {"type": "keyword"},
                    "source_evidence": {"type": "object", "enabled": False},
                    "classification_mode": {"type": "keyword"},
                    "classification_reason": {"type": "keyword"},
                    "classifier_input_chars": {"type": "integer"},
                    "classifier_effective_input_chars": {"type": "integer"},
                    "classification_time_ms": {"type": "integer"},
                    "ai_score_breakdown": {"type": "object", "enabled": False},
                    "ai_top_factors": {"type": "object", "enabled": False},
                    "validation_status": {"type": "keyword"},
                    "validation_reasons": {"type": "keyword"},
                    "warehouse_eligible": {"type": "boolean"},
                    "review_required": {"type": "boolean"},
                    "review_state": {"type": "keyword"},
                    "reviewed_by": {"type": "keyword"},
                    "reviewed_at": {"type": "date"},
                    "review_notes": {"type": "text"},
                    "action_required": {"type": "boolean"},
                    "action_status": {"type": "keyword"},
                    "action_title": {"type": "text"},
                    "action_reason": {"type": "keyword"},
                    "action_opened_at": {"type": "date"},
                    "action_updated_at": {"type": "date"},
                    "action_closed_at": {"type": "date"},
                    "action_closed_reason": {"type": "keyword"},
                    "cleaning_flags": {"type": "keyword"},
                    "sanitization_summary": {"type": "object", "enabled": False},
                    "partner_id": {"type": "keyword"},
                    "submitted_by_partner": {"type": "keyword"},
                    "tlp": {"type": "keyword"},
                    "published_at": {"type": "date"},
                    "last_shared_at": {"type": "date"},
                    "revoked_at": {"type": "date"},
                    "sharing_status": {"type": "keyword"},
                    "cluster_label": {"type": "integer"},
                    "cluster_probability": {"type": "float"},
                    "processed_at": {"type": "date"},
                    "created_at": {"type": "date"}
                }
            }
        }

        processed_mapping = {
            "mappings": {
                "properties": {
                    "source_index": {"type": "keyword"},
                    "source_doc_id": {"type": "keyword"},
                    "source_fingerprint": {"type": "keyword"},
                    "ioc_type": {"type": "keyword"},
                    "ioc_value": {"type": "keyword"},
                    "canonical_ioc_key": {"type": "keyword"},
                    "original_ioc_type": {"type": "keyword"},
                    "original_ioc_value": {"type": "keyword"},
                    "warehouse_doc_id": {"type": "keyword"},
                    "status": {"type": "keyword"},
                    "attempt_count": {"type": "integer"},
                    "first_seen_at": {"type": "date"},
                    "last_attempt_at": {"type": "date"},
                    "processed_at": {"type": "date"},
                    "error": {"type": "text"},
                    "adapter_name": {"type": "keyword"},
                }
            }
        }

        quarantine_mapping = {
            "mappings": {
                "properties": {
                    "source_index": {"type": "keyword"},
                    "source_doc_id": {"type": "keyword"},
                    "source_fingerprint": {"type": "keyword"},
                    "adapter_name": {"type": "keyword"},
                    "adapter_status": {"type": "keyword"},
                    "quarantine_reason": {"type": "keyword"},
                    "raw_keys": {"type": "keyword"},
                    "raw_sample": {"type": "object", "enabled": False},
                    "created_at": {"type": "date"},
                }
            }
        }

        ml_feedback_mapping = {
            "mappings": {
                "properties": {
                    "feedback_id": {"type": "keyword"},
                    "warehouse_doc_id": {"type": "keyword"},
                    "ioc_type": {"type": "keyword"},
                    "ioc_value": {"type": "keyword"},
                    "current_labels": {"type": "keyword"},
                    "expected_labels": {"type": "keyword"},
                    "feedback_type": {"type": "keyword"},
                    "reviewer": {"type": "keyword"},
                    "note": {"type": "text"},
                    "source": {"type": "keyword"},
                    "status": {"type": "keyword"},
                    "created_at": {"type": "date"},
                    "updated_at": {"type": "date"},
                }
            }
        }
        
        for index, mapping in [
            (self.datalake_index, datalake_mapping),
            (self.warehouse_index, warehouse_mapping),
            (PROCESSED_INDEX, processed_mapping),
            (QUARANTINE_INDEX, quarantine_mapping),
            (ML_FEEDBACK_INDEX, ml_feedback_mapping),
        ]:
            if index == self.datalake_index and DATALAKE_READONLY:
                logger.info("Skipping datalake index create for read-only source: %s", index)
                results[index] = True
                continue
            try:
                client = self._get_client(index)
                if ES_CLIENT_AVAILABLE and client:
                    if not client.indices.exists(index=index):
                        client.indices.create(index=index, body=mapping)
                        results[index] = True
                        logger.info(f"Created index: {index}")
                    else:
                        results[index] = True
                        logger.info(f"Index already exists: {index}")
                else:
                    # Check if exists
                    check = httpx.head(
                        f"{self._get_url(index)}/{index}", 
                        timeout=10, 
                        headers=self._get_headers(index)
                    )
                    if check.status_code == 404:
                        resp = httpx.put(
                            f"{self._get_url(index)}/{index}",
                            json=mapping,
                            timeout=30,
                            headers=self._get_headers(index)
                        )
                        results[index] = resp.status_code in (200, 201)
                    else:
                        results[index] = True
            except Exception as e:
                logger.error(f"Failed to create index {index}: {e}")
                results[index] = False
        
        return results

    def create_processed_index(self) -> bool:
        return self.create_indexes().get(PROCESSED_INDEX, False)

    def create_quarantine_index(self) -> bool:
        return self.create_indexes().get(QUARANTINE_INDEX, False)

    def create_ml_feedback_index(self) -> bool:
        return self.create_indexes().get(ML_FEEDBACK_INDEX, False)

    @staticmethod
    def _build_feedback_doc_id(feedback: Dict[str, Any]) -> str:
        seed = "|".join(
            [
                str(feedback.get("warehouse_doc_id") or ""),
                str(feedback.get("ioc_type") or ""),
                str(feedback.get("ioc_value") or ""),
                str(feedback.get("feedback_type") or ""),
                str(feedback.get("created_at") or ""),
            ]
        )
        return f"fb:{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:32]}"

    def save_ml_feedback(self, feedback: Dict[str, Any]) -> Optional[str]:
        now = datetime.now(timezone.utc).isoformat()
        document = copy.deepcopy(feedback)
        document.setdefault("created_at", now)
        document.setdefault("updated_at", now)
        document.setdefault("status", "open")
        doc_id = document.get("feedback_id") or self._build_feedback_doc_id(document)
        document["feedback_id"] = doc_id
        try:
            self.create_ml_feedback_index()
            client = self._get_client(ML_FEEDBACK_INDEX)
            if ES_CLIENT_AVAILABLE and client:
                client.index(index=ML_FEEDBACK_INDEX, id=doc_id, body=document)
                return doc_id
            response = httpx.put(
                f"{self._get_url(ML_FEEDBACK_INDEX)}/{ML_FEEDBACK_INDEX}/_doc/{quote(doc_id, safe='')}",
                json=document,
                timeout=30,
                headers=self._get_headers(ML_FEEDBACK_INDEX),
            )
            if response.status_code in (200, 201):
                return doc_id
            logger.error("Failed saving ML feedback: %s", response.text)
            return None
        except Exception as e:
            logger.error("Failed saving ML feedback: %s", e)
            return None

    def search_ml_feedback(
        self,
        status: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        filters: List[Dict[str, Any]] = []
        if status:
            filters.append({"term": {"status": status}})
        body = {
            "query": {"bool": {"filter": filters}} if filters else {"match_all": {}},
            "sort": [{"created_at": {"order": "desc", "missing": "_last", "unmapped_type": "date"}}],
            "from": offset,
            "size": limit,
        }
        try:
            self.create_ml_feedback_index()
            return self._search_index(ML_FEEDBACK_INDEX, body)
        except Exception as e:
            logger.error("Failed searching ML feedback: %s", e)
            return {"hits": {"total": {"value": 0}, "hits": []}}

    def _get_processed_state(self, doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        state_id = self._build_processed_state_id(doc)
        try:
            return self._get_document(PROCESSED_INDEX, state_id)
        except Exception as e:
            logger.warning("Failed to read processed state for %s: %s", state_id, e)
            return None

    def is_source_processed(self, doc: Dict[str, Any]) -> bool:
        state = self._get_processed_state(doc)
        return bool(state and state.get("status") in {"processed", "rejected", "quarantined"})

    def get_processed_state_map(self, docs: Sequence[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Fetch processed-state documents for a batch of source documents."""
        ids = [self._build_processed_state_id(doc) for doc in docs]
        if not ids:
            return {}
        try:
            client = self._get_client(PROCESSED_INDEX)
            if ES_CLIENT_AVAILABLE and client:
                result = client.mget(index=PROCESSED_INDEX, ids=ids)
                return {
                    str(item.get("_id")): item.get("_source", {})
                    for item in result.get("docs", []) or []
                    if item.get("found")
                }

            if httpx is None:
                return {}
            response = httpx.post(
                f"{self.warehouse_url}/{PROCESSED_INDEX}/_mget",
                json={"ids": ids},
                timeout=30,
                headers=self._get_headers(PROCESSED_INDEX),
            )
            response.raise_for_status()
            return {
                str(item.get("_id")): item.get("_source", {})
                for item in response.json().get("docs", []) or []
                if item.get("found")
            }
        except Exception as e:
            logger.warning("Failed to bulk-read processed state: %s", e)
            return {}

    def _pipeline_cursor_doc_id(self, suffix: str = "") -> str:
        raw = f"cursor:{DATALAKE_SCAN_CURSOR_ID}{suffix}:{self.datalake_index}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def get_datalake_scan_cursor(self, suffix: str = "") -> Optional[List[Any]]:
        if not DATALAKE_SCAN_USE_CURSOR:
            return None
        try:
            doc = self._get_document(PROCESSED_INDEX, self._pipeline_cursor_doc_id(suffix)) or {}
            last_sort = doc.get("last_sort")
            return last_sort if isinstance(last_sort, list) and last_sort else None
        except Exception as e:
            logger.warning("Failed to read datalake scan cursor: %s", e)
            return None

    def save_datalake_scan_cursor(self, last_sort: Optional[List[Any]], suffix: str = "") -> bool:
        if not DATALAKE_SCAN_USE_CURSOR:
            return True
        now = datetime.now(timezone.utc).isoformat()
        doc_id = self._pipeline_cursor_doc_id(suffix)
        body = {
            "source_index": self.datalake_index,
            "source_doc_id": doc_id,
            "source_fingerprint": doc_id,
            "status": "cursor",
            "adapter_name": "pipeline_cursor",
            "last_sort": last_sort or [],
            "last_attempt_at": now,
            "processed_at": None,
        }
        try:
            client = self._get_client(PROCESSED_INDEX)
            if ES_CLIENT_AVAILABLE and client:
                client.index(index=PROCESSED_INDEX, id=doc_id, body=body)
                return True
            if httpx is None:
                return False
            response = httpx.put(
                f"{self.warehouse_url}/{PROCESSED_INDEX}/_doc/{quote(doc_id, safe='')}",
                json=body,
                timeout=10,
                headers=self._get_headers(PROCESSED_INDEX),
            )
            return response.status_code in (200, 201)
        except Exception as e:
            logger.warning("Failed to save datalake scan cursor: %s", e)
            return False

    def mark_source_state(
        self,
        doc: Dict[str, Any],
        status: str,
        warehouse_doc_id: Optional[str] = None,
        error: Optional[str] = None,
    ) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        state_id, state_doc = self._build_source_state_doc(
            doc,
            status=status,
            warehouse_doc_id=warehouse_doc_id,
            error=error,
            now=now,
        )

        try:
            existing = self._get_document(PROCESSED_INDEX, state_id)
            state_doc["first_seen_at"] = (existing or {}).get("first_seen_at") or now
            state_doc["attempt_count"] = int((existing or {}).get("attempt_count") or 0) + 1
        except Exception:
            state_doc["first_seen_at"] = now
            state_doc["attempt_count"] = 1

        try:
            client = self._get_client(PROCESSED_INDEX)
            if ES_CLIENT_AVAILABLE and client:
                client.index(index=PROCESSED_INDEX, id=state_id, body=state_doc)
                return True

            resp = httpx.put(
                f"{self.warehouse_url}/{PROCESSED_INDEX}/_doc/{quote(state_id, safe='')}",
                json=state_doc,
                timeout=10,
                headers=self._get_headers(PROCESSED_INDEX),
            )
            return resp.status_code in (200, 201)
        except Exception as e:
            logger.error("Failed to mark processed state for %s: %s", state_id, e)
            return False

    def _build_source_state_doc(
        self,
        doc: Dict[str, Any],
        *,
        status: str,
        warehouse_doc_id: Optional[str] = None,
        error: Optional[str] = None,
        now: Optional[str] = None,
    ) -> tuple[str, Dict[str, Any]]:
        now = now or datetime.now(timezone.utc).isoformat()
        state_id = self._build_processed_state_id(doc)
        source_doc_id = str(doc.get("_id") or "")
        source_index = str(doc.get("_index") or self.datalake_index)
        return state_id, {
            "source_index": source_index,
            "source_doc_id": source_doc_id,
            "source_fingerprint": state_id,
            "ioc_type": ElasticClient.normalize_ioc_type(doc.get("ioc_type")),
            "ioc_value": ElasticClient.normalize_ioc_value(doc.get("ioc_value")),
            "canonical_ioc_key": ElasticClient.canonical_ioc_key(doc) if doc.get("ioc_value") else None,
            "original_ioc_type": doc.get("original_ioc_type") or doc.get("ioc_type"),
            "original_ioc_value": doc.get("original_ioc_value") or doc.get("ioc_value"),
            "warehouse_doc_id": warehouse_doc_id,
            "status": status,
            "first_seen_at": now,
            "last_attempt_at": now,
            "processed_at": now if status in {"processed", "rejected", "quarantined"} else None,
            "attempt_count": 1,
            "error": error,
            "adapter_name": doc.get("adapter_name"),
        }

    def bulk_mark_source_states(
        self,
        items: Sequence[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Mark many source records in the processed-state index in one bulk call."""
        now = datetime.now(timezone.utc).isoformat()
        operations: List[Dict[str, Any]] = []
        for item in items:
            state_id, state_doc = self._build_source_state_doc(
                item["doc"],
                status=item["status"],
                warehouse_doc_id=item.get("warehouse_doc_id"),
                error=item.get("error"),
                now=now,
            )
            operations.append({
                "action": {"index": {"_index": PROCESSED_INDEX, "_id": state_id}},
                "source": state_doc,
            })
        try:
            return self._bulk_request_chunked(PROCESSED_INDEX, operations)
        except Exception as e:
            logger.error("Bulk processed-state write failed: %s", e)
            failed_ids = [
                doc_id
                for doc_id in (self._bulk_operation_id(operation) for operation in operations)
                if doc_id
            ]
            return {"success": 0, "failed": len(failed_ids), "failed_ids": failed_ids}

    def save_quarantine(self, doc: Dict[str, Any], reason: Optional[str] = None) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        state_id = self._build_processed_state_id(doc)
        quarantine_doc = {
            "source_index": str(doc.get("_index") or self.datalake_index),
            "source_doc_id": str(doc.get("_id") or ""),
            "source_fingerprint": state_id,
            "adapter_name": doc.get("adapter_name") or "unknown",
            "adapter_status": "quarantined",
            "quarantine_reason": reason or doc.get("quarantine_reason") or "unsupported_datalake_schema",
            "raw_keys": doc.get("raw_keys") or [],
            "raw_sample": doc.get("raw") or {},
            "created_at": now,
        }

        try:
            client = self._get_client(QUARANTINE_INDEX)
            if ES_CLIENT_AVAILABLE and client:
                client.index(index=QUARANTINE_INDEX, id=state_id, body=quarantine_doc)
            else:
                resp = httpx.put(
                    f"{self.warehouse_url}/{QUARANTINE_INDEX}/_doc/{quote(state_id, safe='')}",
                    json=quarantine_doc,
                    timeout=10,
                    headers=self._get_headers(QUARANTINE_INDEX),
                )
                if resp.status_code not in (200, 201):
                    return False
            return self.mark_source_state(doc, "quarantined", error=quarantine_doc["quarantine_reason"])
        except Exception as e:
            logger.error("Failed to save quarantine for %s: %s", state_id, e)
            return False
    
    def get_unprocessed_iocs(
        self,
        limit: int = 100,
        worker_id: int = 0,
        worker_total: int = 1,
    ) -> List[Dict[str, Any]]:
        if DATALAKE_QUERY_MODE == "all":
            return self._get_unprocessed_iocs_from_readonly_feed(limit, worker_id, worker_total)
        else:
            # Match docs where ai_processed does not exist (old-style) OR is explicitly false
            # (new docs indexed via bulk_index_datalake which sets ai_processed=False by default).
            query = {
                "query": {
                    "bool": {
                        "should": [
                            {"bool": {"must_not": [{"exists": {"field": "ai_processed"}}]}},
                            {"term": {"ai_processed": False}},
                        ],
                        "minimum_should_match": 1,
                    }
                },
                "sort": [
                    {"event_time": {"order": "desc", "missing": "_last"}},
                    {"collect_time": {"order": "desc", "missing": "_last"}}
                ],
                "size": limit
            }
        
        try:
            logger.info(f"Searching datalake with query: {query}")
            result = self._search_index(self.datalake_index, query)
            hits = result["hits"]["hits"]
            logger.info(f"Found {len(hits)} hits in datalake")
            return [self._normalize_datalake_hit(hit) for hit in hits]

        except Exception as e:
            logger.error(f"Failed to get unprocessed IOCs: {e}")
            return []

    def _get_unprocessed_iocs_from_readonly_feed(
        self,
        limit: int,
        worker_id: int = 0,
        worker_total: int = 1,
    ) -> List[Dict[str, Any]]:
        documents: List[Dict[str, Any]] = []
        batch_size = max(DATALAKE_SCAN_BATCH_SIZE, min(limit, 1000))
        # Per-worker cursor — each worker gets its own slice and advances
        # independently so they don't race on a shared cursor.
        cursor_suffix = f"-w{worker_id}of{worker_total}" if worker_total > 1 else ""
        search_after = self.get_datalake_scan_cursor(suffix=cursor_suffix)

        # Date filter — covers up to BACKFILL_DAYS days of datalake history.
        # Each worker takes a disjoint date slice (e.g. 730 days / 4 workers
        # = ~182 days each). Tunable via env so we can run a short window
        # first (e.g. 60d) then extend to all history once that's caught up.
        # Custom boundaries: PIPELINE_WORKER_BOUNDARIES=0,7,16,24,... (days ago, newest to oldest)
        # Must have worker_total+1 values. Falls back to equal time-slice split.
        _boundaries_env = os.getenv("PIPELINE_WORKER_BOUNDARIES", "")
        if _boundaries_env and worker_total > 1:
            _b = [int(x.strip()) for x in _boundaries_env.split(",")]
            lower_offset = _b[worker_id]
            upper_offset = _b[worker_id + 1]
        else:
            total_days = int(os.getenv("BACKFILL_DAYS", "730"))
            days_per_worker = max(1, total_days // worker_total)
            lower_offset = worker_id * days_per_worker
            if worker_id == worker_total - 1:
                upper_offset = total_days
            else:
                upper_offset = (worker_id + 1) * days_per_worker
        date_range = {"gte": f"now-{upper_offset}d"}
        if lower_offset > 0:
            date_range["lt"] = f"now-{lower_offset}d"
        # Use OR clause so docs with EITHER observation_date OR @timestamp
        # in range get matched. Cyberint docs have observation_date; news
        # sources (BleepingComputer, The Hacker News, Zone-H, DarkReading,
        # Sandbox) have only @timestamp. Without the OR clause, the news
        # sources are silently filtered out and never reach the classifier
        # → DeBERTa/BGE-M3 ML never runs.
        base_query: Dict[str, Any] = {
            "bool": {
                "should": [
                    {"range": {"observation_date": date_range}},
                    {"range": {"@timestamp": date_range}},
                ],
                "minimum_should_match": 1,
            }
        }

        for _ in range(max(1, DATALAKE_SCAN_MAX_PAGES)):
            query: Dict[str, Any] = {
                "query": base_query,
                "sort": [
                    {"event_time": {"order": "desc", "missing": "_last", "unmapped_type": "date"}},
                    {"collect_time": {"order": "desc", "missing": "_last", "unmapped_type": "date"}},
                    {"_doc": {"order": "desc"}},
                ],
                "size": batch_size,
            }
            if search_after:
                query["search_after"] = search_after

            try:
                logger.info("Searching read-only datalake with query: %s", query)
                result = self._search_index(self.datalake_index, query)
                hits = result["hits"]["hits"]
                logger.info("Found %s hits in read-only datalake page search_after=%s", len(hits), search_after)
            except Exception as e:
                logger.error(f"Failed to get read-only datalake IOCs: {e}")
                return documents

            if not hits:
                if search_after:
                    self.save_datalake_scan_cursor(None, suffix=cursor_suffix)
                return documents

            last_sort = hits[-1].get("sort")
            search_after = last_sort if isinstance(last_sort, list) else None
            if search_after:
                self.save_datalake_scan_cursor(search_after, suffix=cursor_suffix)

            normalized_page = [self._normalize_datalake_hit(hit) for hit in hits]
            processed_state = self.get_processed_state_map(normalized_page)
            finished_statuses = {"processed", "rejected", "quarantined"}
            for doc in normalized_page:
                state_id = self._build_processed_state_id(doc)
                state = processed_state.get(state_id)
                if state and state.get("status") in finished_statuses:
                    continue
                documents.append(doc)
                if len(documents) >= limit:
                    return documents

        logger.warning(
            "Reached DATALAKE_SCAN_MAX_PAGES=%s before collecting %s unprocessed docs",
            DATALAKE_SCAN_MAX_PAGES,
            limit,
        )
        return documents

    @staticmethod
    def _first_source(raw: Dict[str, Any]) -> Dict[str, Any]:
        source = raw.get("source")
        if isinstance(source, list) and source:
            return source[0] if isinstance(source[0], dict) else {}
        if isinstance(source, dict):
            return source
        return {}

    @classmethod
    def _normalize_datalake_hit(cls, hit: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize current and external feed documents into pipeline fields."""
        return normalize_datalake_hit(hit, cls.normalize_ioc_type, cls.normalize_ioc_value)

    def search_datalake_documents(
        self,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        only_processed: Optional[bool] = None
    ) -> List[Dict[str, Any]]:
        """Search Data Lake documents for backfill or analytics support."""
        filters: List[Dict[str, Any]] = []

        if only_processed is not None:
            filters.append({"term": {"ai_processed": only_processed}})

        if date_from or date_to:
            range_query: Dict[str, str] = {}
            if date_from:
                range_query["gte"] = date_from
            if date_to:
                range_query["lte"] = date_to

            filters.append({
                "bool": {
                    "should": [
                        {"range": {"event_time": range_query}},
                        {"range": {"collect_time": range_query}}
                    ],
                    "minimum_should_match": 1
                }
            })

        body = {
            "query": {
                "bool": {
                    "filter": filters
                }
            } if filters else {"match_all": {}},
            "sort": [
                {"event_time": {"order": "desc", "missing": "_last", "unmapped_type": "date"}},
                {"collect_time": {"order": "desc", "missing": "_last", "unmapped_type": "date"}}
            ],
            "from": offset,
            "size": limit
        }

        try:
            result = self._search_index(self.datalake_index, body)
            return [hit["_source"] | {"_id": hit["_id"]} for hit in result["hits"]["hits"]]
        except Exception as e:
            logger.error(f"Failed to search datalake documents: {e}")
            return []
    
    def mark_as_processed(self, doc_id: str, index: str = None) -> bool:
        if DATALAKE_READONLY:
            logger.info("Skipping mark_as_processed for read-only datalake doc %s", doc_id)
            return True
        target = index or self.datalake_index
        try:
            client = self._get_client(self.datalake_index)
            if ES_CLIENT_AVAILABLE and client:
                client.update(
                    index=target,

                    id=doc_id,
                    body={"doc": {"ai_processed": True}}
                )
                return True
            else:
                resp = httpx.post(
                    f"{self.datalake_url}/{target}/_update/{quote(doc_id, safe='')}",

                    json={"doc": {"ai_processed": True}},
                    timeout=10,
                    headers=self._get_headers(self.datalake_index)
                )
                return resp.status_code == 200
        except Exception as e:
            logger.error(f"Failed to mark IOC as processed: {e}")
            return False
    
    @staticmethod
    def _prepare_warehouse_document(ioc_data: Dict[str, Any]) -> Dict[str, Any]:
        document = copy.deepcopy(ioc_data)
        now = datetime.now(timezone.utc).isoformat()
        processed_at = document.get("processed_at") or now
        document["processed_at"] = processed_at
        if "created_at" not in document:
            document["created_at"] = processed_at
        document["validation_status"] = document.get("validation_status", "validated")
        document["warehouse_eligible"] = bool(document.get("warehouse_eligible", True))
        document["review_required"] = bool(document.get("review_required", False))
        document["review_state"] = document.get("review_state", "not_required")
        document["reviewed_by"] = document.get("reviewed_by")
        document["reviewed_at"] = document.get("reviewed_at")
        document["review_notes"] = document.get("review_notes")
        document["action_required"] = bool(document.get("action_required", False))
        document["action_status"] = document.get("action_status")
        document["action_title"] = document.get("action_title")
        document["action_reason"] = document.get("action_reason")
        document["action_opened_at"] = document.get("action_opened_at")
        document["action_updated_at"] = document.get("action_updated_at")
        document["action_closed_at"] = document.get("action_closed_at")
        document["action_closed_reason"] = document.get("action_closed_reason")
        document["validation_reasons"] = document.get("validation_reasons", [])
        document["cleaning_flags"] = document.get("cleaning_flags", [])
        document["sanitization_summary"] = document.get("sanitization_summary", {})
        document["partner_id"] = document.get("partner_id")
        document["submitted_by_partner"] = document.get("submitted_by_partner")
        document["tlp"] = document.get("tlp", "amber")
        document["published_at"] = document.get("published_at", processed_at)
        document["last_shared_at"] = document.get("last_shared_at", document["published_at"])
        document["revoked_at"] = document.get("revoked_at")
        document["sharing_status"] = document.get("sharing_status", "active")
        document["cluster_label"] = document.get("cluster_label")
        document["cluster_probability"] = document.get("cluster_probability")
        return document

    def save_to_warehouse(self, ioc_data: Dict[str, Any]) -> Optional[str]:
        warehouse_doc = self._prepare_warehouse_document(ioc_data)
        try:
            # 1:1 observation mode — every datalake observation becomes its own
            # warehouse doc. Earlier this used canonical_ioc_key (dedupe by IOC),
            # which collapsed re-observations of the same IOC into a single row
            # and undercounted attack events; per-event uniqueness uses the
            # source-fingerprinted datalake doc id instead.
            doc_id = self._build_datalake_doc_id(warehouse_doc)
            client = self._get_client(self.pipeline_warehouse_index)
            if ES_CLIENT_AVAILABLE and client:
                result = client.index(
                    index=self.pipeline_warehouse_index,
                    body=warehouse_doc,
                    id=doc_id
                )
                return result.get("_id")
            else:
                resp = httpx.put(
                    f"{self.warehouse_url}/{self.pipeline_warehouse_index}/_doc/{quote(doc_id, safe='')}",
                    json=warehouse_doc,
                    timeout=10,
                    headers=self._get_headers(self.pipeline_warehouse_index)
                )
                if resp.status_code in (200, 201):
                    return resp.json().get("_id")
                return None
        except Exception as e:
            logger.error(f"Failed to save to warehouse: {e}")
            return None

    def bulk_save_to_warehouse(
        self,
        items: Sequence[Dict[str, Any]],
        *,
        wait_for_refresh: bool = False,
    ) -> Dict[str, Any]:
        """Save many warehouse documents in one bulk request.

        Each item can provide a precomputed ``doc_id`` and ``document``.  The
        document is still passed through the same warehouse preparation path as
        single-document writes.

        ``wait_for_refresh=True`` makes ES block until the new docs are
        visible to searches before returning. Use this when the caller will
        immediately follow up with bulk-update against the same doc_ids
        (the clustering pass would otherwise race and hit
        ``document_missing_exception`` on every doc).
        """
        operations: List[Dict[str, Any]] = []
        for item in items:
            warehouse_doc = self._prepare_warehouse_document(dict(item["document"]))
            doc_id = str(item.get("doc_id") or self._build_datalake_doc_id(warehouse_doc))
            operations.append({
                "action": {"index": {"_index": self.pipeline_warehouse_index, "_id": doc_id}},
                "source": warehouse_doc,
            })
        try:
            return self._bulk_request_chunked(
                self.pipeline_warehouse_index,
                operations,
                refresh="wait_for" if wait_for_refresh else None,
            )
        except Exception as e:
            logger.error("Bulk warehouse write failed: %s", e)
            failed_ids = [
                doc_id
                for doc_id in (self._bulk_operation_id(operation) for operation in operations)
                if doc_id
            ]
            return {"success": 0, "failed": len(failed_ids), "failed_ids": failed_ids}

    def bulk_index_datalake(self, documents: List[Dict]) -> Dict[str, int]:
        if not documents:
            return {"success": 0, "failed": 0}

        now = datetime.now(timezone.utc).isoformat()
        operations: List[Dict[str, Any]] = []
        for original_doc in documents:
            doc = copy.deepcopy(original_doc)
            doc.setdefault("ai_processed", False)
            doc.setdefault("created_at", now)
            ioc_id = self._build_datalake_doc_id(doc)
            operations.append({
                "action": {"index": {"_index": self.datalake_index, "_id": ioc_id}},
                "source": doc,
            })

        try:
            result = self._bulk_request_chunked(self.datalake_index, operations)
            return {"success": int(result.get("success", 0)), "failed": int(result.get("failed", 0))}
        except Exception as e:
            logger.error("bulk_index_datalake failed: %s", e)
            return {"success": 0, "failed": len(documents)}

    def search_review_documents(
        self,
        validation_status: Optional[str] = None,
        review_state: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> Dict[str, Any]:
        filters: List[Dict[str, Any]] = []

        if validation_status:
            filters.append({"term": {"validation_status": validation_status}})
        if review_state:
            filters.append({"term": {"review_state": review_state}})

        search_body = {
            "query": {"bool": {"filter": filters}} if filters else {"match_all": {}},
            "sort": [
                {"review_required": {"order": "desc"}},
                {"ai_risk_score": {"order": "desc", "missing": "_last"}},
                {"processed_at": {"order": "desc", "missing": "_last"}}
            ],
            "from": offset,
            "size": limit
        }

        try:
            result = self._search_index(self.warehouse_index, search_body)
            return {
                "total": result["hits"]["total"]["value"],
                "data": [{"_id": hit["_id"], **hit["_source"]} for hit in result["hits"]["hits"]]
            }
        except Exception as e:
            logger.error(f"Review queue search failed: {e}")
            return {"total": 0, "data": [], "error": "Search failed"}

    def bulk_get_warehouse_documents(self, doc_ids: List[str]) -> Dict[str, Dict[str, Any]]:
        ids = [str(d) for d in doc_ids if d]
        if not ids:
            return {}
        try:
            client = self._get_client(self.warehouse_index)
            if ES_CLIENT_AVAILABLE and client:
                result = client.mget(index=self.warehouse_index, ids=ids)
                return {
                    str(item.get("_id")): item.get("_source", {})
                    for item in result.get("docs", []) or []
                    if item.get("found")
                }

            if httpx is None:
                return {}
            response = httpx.post(
                f"{self.warehouse_url}/{self.warehouse_index}/_mget",
                json={"ids": ids},
                timeout=30,
                headers=self._get_headers(self.warehouse_index),
            )
            response.raise_for_status()
            return {
                str(item.get("_id")): item.get("_source", {})
                for item in response.json().get("docs", []) or []
                if item.get("found")
            }
        except Exception as e:
            logger.warning("Failed to bulk-read warehouse documents: %s", e)
            return {}

    def get_warehouse_document(self, doc_id: str) -> Optional[Dict[str, Any]]:
        try:
            return self._get_document(self.warehouse_index, doc_id)
        except Exception as e:
            logger.error(f"Failed to get warehouse document {doc_id}: {e}")
            return None

    def update_warehouse_document(self, doc_id: str, fields: Dict[str, Any]) -> bool:
        try:
            return self._update_document(self.warehouse_index, doc_id, fields)
        except Exception as e:
            logger.error(f"Failed to update warehouse document {doc_id}: {e}")
            return False

    def bulk_update_warehouse_documents(
        self, updates: Sequence[Tuple[str, Dict[str, Any]]]
    ) -> Dict[str, Any]:
        """Apply partial updates to many warehouse documents in a single bulk call.

        Each entry is ``(doc_id, fields_dict)``. Uses ES ``_bulk`` with the
        ``update`` action so behaviour matches ``_update_document`` (merge,
        not replace). Returns the same shape as ``bulk_save_to_warehouse``
        for symmetry with the rest of the bulk-write callsites.

        This exists because the clustering pass in ``main._run_pipeline_once_sync``
        otherwise issues N individual ``_update`` HTTP requests per batch —
        with HDBSCAN clustering ~95% of every 2000-doc batch, that's
        ~1900 round-trips at ~50 ms each (~95 s wasted per iteration).
        One bulk request collapses that into a single round-trip.
        """
        if not updates:
            return {"success": 0, "failed": 0, "failed_ids": [], "errors": False}
        operations: List[Dict[str, Any]] = []
        for doc_id, fields in updates:
            if not doc_id or not isinstance(fields, dict) or not fields:
                continue
            operations.append({
                "action": {
                    "update": {
                        "_index": self.pipeline_warehouse_index,
                        "_id": doc_id,
                        # retry_on_conflict so concurrent updates from the
                        # ingest pipeline + post-ingest clustering job
                        # don't blow up on version_conflict
                        "retry_on_conflict": 3,
                    },
                },
                "source": {"doc": fields},
            })
        if not operations:
            return {"success": 0, "failed": 0, "failed_ids": [], "errors": False}
        try:
            return self._bulk_request_chunked(self.pipeline_warehouse_index, operations)
        except Exception as e:
            logger.error("Bulk warehouse update failed: %s", e)
            failed_ids = [
                doc_id
                for doc_id in (self._bulk_operation_id(operation) for operation in operations)
                if doc_id
            ]
            return {"success": 0, "failed": len(failed_ids), "failed_ids": failed_ids, "errors": True}



# Singleton instance
_client: Optional[ElasticClient] = None


def get_elastic_client() -> ElasticClient:
    """Get or create Elasticsearch client instance."""
    global _client
    if _client is None:
        _client = ElasticClient()
    return _client
