"""
Elasticsearch Client for AI Service

Provides connection to Elasticsearch for:
- Data Lake (raw/semi-processed IOCs)
- Data Warehouse (AI-processed IOCs)

Supports external ELK stack with per-index API key authentication.
"""

import os
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
import hashlib
from urllib.parse import quote

logger = logging.getLogger(__name__)

# Configuration
ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "https://pluto-elk.ibusiness.co.th")
DATALAKE_INDEX = os.getenv("DATALAKE_INDEX", "cyber-logs-datalake")
PROCESSED_INDEX = os.getenv("PROCESSED_INDEX", "cyber-logs-processed")
WAREHOUSE_INDEX = os.getenv("WAREHOUSE_INDEX", "cyber-logs-datawarehouse")

# API Keys (Per-index access)
DATALAKE_API_KEY = os.getenv("DATALAKE_API_KEY", "")
WAREHOUSE_API_KEY = os.getenv("WAREHOUSE_API_KEY", "")

# Try to import elasticsearch, fallback to httpx if not available
try:
    from elasticsearch import Elasticsearch, helpers
    ES_CLIENT_AVAILABLE = True
except ImportError:
    ES_CLIENT_AVAILABLE = False
    import httpx


class ElasticClient:
    """
    Elasticsearch client wrapper for TCTI platform.
    
    Supports two indices with separate API keys:
    - DATALAKE_INDEX (cyber-logs-datalake): Raw IOCs, Input
    - WAREHOUSE_INDEX (cyber-logs-datawarehouse): Enriched IOCs, Output
    """
    
    def __init__(self, url: str = ELASTICSEARCH_URL):
        self.url = url
        self.datalake_index = DATALAKE_INDEX
        self.processed_index = PROCESSED_INDEX
        self.warehouse_index = WAREHOUSE_INDEX
        
        self.datalake_api_key = DATALAKE_API_KEY
        self.warehouse_api_key = WAREHOUSE_API_KEY
        
        if ES_CLIENT_AVAILABLE:
            # Base client without headers (auth applied per request)
            self.client = Elasticsearch(url)
        else:
            self.client = None
            logger.warning("elasticsearch-py not installed, using httpx fallback")
    
    def _get_api_key(self, index: str) -> Optional[str]:
        """Get API Key for specific index."""
        if index == self.datalake_index:
            return self.datalake_api_key
        elif index == self.warehouse_index:
            return self.warehouse_api_key
        elif index == self.processed_index:
            # Use warehouse key for processed layer (output side) OR datalake key?
            # Prefer Warehouse key as it is 'enriched' data
            return self.warehouse_api_key
        return None

    def _get_client(self, index: str):
        """Get Elasticsearch client configured for specific index."""
        if not ES_CLIENT_AVAILABLE or not self.client:
            return None
        
        api_key = self._get_api_key(index)
        if api_key:
            return self.client.options(api_key=api_key)
        return self.client

    def _get_headers(self, index: str) -> Dict[str, str]:
        """Get HTTP headers for httpx fallback."""
        headers = {"Content-Type": "application/json"}
        api_key = self._get_api_key(index)
        if api_key:
            headers["Authorization"] = f"ApiKey {api_key}"
        return headers

    def _search_index(self, index: str, body: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a search against a specific index."""
        client = self._get_client(index)
        if ES_CLIENT_AVAILABLE and client:
            return client.search(index=index, body=body)

        response = httpx.post(
            f"{self.url}/{index}/_search",
            json=body,
            timeout=30,
            headers=self._get_headers(index)
        )
        response.raise_for_status()
        return response.json()

    def search_index(self, index: str, body: Dict[str, Any]) -> Dict[str, Any]:
        """Public wrapper for raw index searches used by dashboard-facing APIs."""
        return self._search_index(index, body)

    def _get_document(self, index: str, doc_id: str) -> Optional[Dict[str, Any]]:
        client = self._get_client(index)
        if ES_CLIENT_AVAILABLE and client:
            result = client.get(index=index, id=doc_id)
            if not result.get("found"):
                return None
            return {"_id": result.get("_id"), **result.get("_source", {})}

        response = httpx.get(
            f"{self.url}/{index}/_doc/{quote(doc_id, safe='')}",
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
            f"{self.url}/{index}/_update/{quote(doc_id, safe='')}",
            json={"doc": fields},
            timeout=30,
            headers=self._get_headers(index)
        )
        return response.status_code == 200

    def count_documents(self, index: str) -> int:
        """Count documents in a specific index with the correct API key."""
        body = {"size": 0, "query": {"match_all": {}}}
        try:
            result = self._search_index(index, body)
            return int(result.get("hits", {}).get("total", {}).get("value", 0))
        except Exception as e:
            logger.error(f"Failed to count index {index}: {e}")
            return 0

    def health_check(self) -> Dict[str, Any]:
        """Check index accessibility without requiring cluster-level permissions."""
        statuses: Dict[str, str] = {}
        available = 0

        for index in [self.datalake_index, self.warehouse_index]:
            try:
                self._search_index(index, {"size": 0, "query": {"match_all": {}}})
                statuses[index] = "available"
                available += 1
            except Exception as e:
                statuses[index] = f"error: {e}"

        if available == 2:
            status = "green"
        elif available == 1:
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
    def _build_warehouse_doc_id(ioc_data: Dict[str, Any]) -> str:
        ioc_type = str(ioc_data.get("ioc_type", "unknown")).strip().lower()
        ioc_value = str(ioc_data.get("ioc_value", "")).strip().lower()
        payload = f"{ioc_type}:{ioc_value}".encode("utf-8")
        digest = hashlib.sha1(payload).hexdigest()[:24]
        return f"{ioc_type}:{digest}"

    @staticmethod
    def _build_processed_doc_id(ioc_data: Dict[str, Any]) -> str:
        ioc_type = str(ioc_data.get("ioc_type", "unknown")).strip().lower()
        ioc_value = str(ioc_data.get("ioc_value", "")).strip().lower()
        first_seen = str(ioc_data.get("first_seen", "")).strip()
        last_seen = str(ioc_data.get("last_seen", "")).strip()
        sources = ",".join(sorted(ioc_data.get("sources", []) or []))
        payload = f"{ioc_type}:{ioc_value}|{first_seen}|{last_seen}|{sources}".encode("utf-8")
        digest = hashlib.sha1(payload).hexdigest()[:24]
        return f"{ioc_type}:{digest}"

    @staticmethod
    def _build_datalake_doc_id(doc: Dict[str, Any]) -> str:
        ioc_type = str(doc.get("ioc_type", "unknown")).strip().lower()
        ioc_value = str(doc.get("ioc_value", "")).strip().lower()
        source = str(doc.get("source_name", "unknown")).strip().lower()
        source_type = str(doc.get("source_type", "unknown")).strip().lower()
        event_time = str(doc.get("event_time", "")).strip()
        collect_time = str(doc.get("collect_time", "")).strip()
        reference = str(doc.get("reference", "")).strip()
        fingerprint_src = (
            f"{source}|{source_type}|{event_time}|{collect_time}|"
            f"{reference}|{str(doc.get('description', ''))[:256]}"
        )
        digest = hashlib.sha1(fingerprint_src.encode("utf-8")).hexdigest()[:24]
        return f"{ioc_type}:{ioc_value}:{digest}"
    
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
                    # catch-all for other fields if needed, or rely on _source
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
                    "processed_at": {"type": "date"},
                    "created_at": {"type": "date"}
                }
            }
        }
        
        for index, mapping in [
            (self.datalake_index, datalake_mapping),
            (self.warehouse_index, warehouse_mapping),
        ]:
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
                        f"{self.url}/{index}", 
                        timeout=10, 
                        headers=self._get_headers(index)
                    )
                    if check.status_code == 404:
                        resp = httpx.put(
                            f"{self.url}/{index}",
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
    
    def get_unprocessed_iocs(self, limit: int = 100) -> List[Dict[str, Any]]:
        query = {
            "query": {"bool": {"must": [{"term": {"ai_processed": False}}]}},
            "sort": [
                {"event_time": {"order": "asc", "missing": "_last"}},
                {"collect_time": {"order": "asc", "missing": "_last"}}
            ],
            "size": limit
        }
        
        try:
            logger.info(f"Searching datalake with query: {query}")
            result = self._search_index(self.datalake_index, query)
            hits = result["hits"]["hits"]
            logger.info(f"Found {len(hits)} hits in datalake")
            return [hit["_source"] | {"_id": hit["_id"]} for hit in hits]
        except Exception as e:
            logger.error(f"Failed to get unprocessed IOCs: {e}")
            return []

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
                {"event_time": {"order": "asc", "missing": "_last"}},
                {"collect_time": {"order": "asc", "missing": "_last"}}
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
    
    def mark_as_processed(self, doc_id: str) -> bool:
        try:
            client = self._get_client(self.datalake_index)
            if ES_CLIENT_AVAILABLE and client:
                client.update(
                    index=self.datalake_index,
                    id=doc_id,
                    body={"doc": {"ai_processed": True}}
                )
                return True
            else:
                resp = httpx.post(
                    f"{self.url}/{self.datalake_index}/_update/{doc_id}",
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
        document = dict(ioc_data)
        processed_at = document.get("processed_at") or datetime.utcnow().isoformat() + "Z"
        document["processed_at"] = processed_at
        if "created_at" not in document:
            document["created_at"] = processed_at
        document["validation_status"] = document.get("validation_status", "validated_auto")
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
        return document

    def save_to_warehouse(self, ioc_data: Dict[str, Any]) -> Optional[str]:
        warehouse_doc = self._prepare_warehouse_document(ioc_data)
        try:
            doc_id = self._build_warehouse_doc_id(warehouse_doc)
            client = self._get_client(self.warehouse_index)
            if ES_CLIENT_AVAILABLE and client:
                result = client.index(
                    index=self.warehouse_index,
                    body=warehouse_doc,
                    id=doc_id
                )
                return result.get("_id")
            else:
                resp = httpx.put(
                    f"{self.url}/{self.warehouse_index}/_doc/{quote(doc_id, safe='')}",
                    json=warehouse_doc,
                    timeout=10,
                    headers=self._get_headers(self.warehouse_index)
                )
                if resp.status_code in (200, 201):
                    return resp.json().get("_id")
                return None
        except Exception as e:
            logger.error(f"Failed to save to warehouse: {e}")
            return None

    def save_to_processed(self, ioc_data: Dict[str, Any]) -> Optional[str]:
        logger.warning("save_to_processed() is deprecated; writing to warehouse instead")
        return self.save_to_warehouse(ioc_data)
    
    def bulk_index_datalake(self, documents: List[Dict]) -> Dict[str, int]:
        success = 0
        failed = 0
        
        client = self._get_client(self.datalake_index)
        
        for doc in documents:
            doc["ai_processed"] = False
            doc["created_at"] = datetime.utcnow().isoformat() + "Z"
            
            try:
                ioc_id = self._build_datalake_doc_id(doc)
                if ES_CLIENT_AVAILABLE and client:
                    client.index(
                        index=self.datalake_index,
                        body=doc,
                        id=ioc_id
                    )
                    success += 1
                else:
                    resp = httpx.put(
                        f"{self.url}/{self.datalake_index}/_doc/{quote(ioc_id, safe='')}",
                        json=doc,
                        timeout=10,
                        headers=self._get_headers(self.datalake_index)
                    )
                    if resp.status_code in (200, 201):
                        success += 1
                    else:
                        failed += 1
            except Exception as e:
                logger.error(f"Failed to index document: {e}")
                failed += 1
        
        return {"success": success, "failed": failed}

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
            return {"total": 0, "data": [], "error": str(e)}

    def search_processed_documents(
        self,
        validation_status: Optional[str] = None,
        review_state: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> Dict[str, Any]:
        logger.warning("search_processed_documents() is deprecated; querying warehouse instead")
        return self.search_review_documents(
            validation_status=validation_status,
            review_state=review_state,
            limit=limit,
            offset=offset,
        )

    def get_review_document(self, doc_id: str) -> Optional[Dict[str, Any]]:
        try:
            return self._get_document(self.warehouse_index, doc_id)
        except Exception as e:
            logger.error(f"Failed to get review document {doc_id}: {e}")
            return None

    def get_warehouse_document(self, doc_id: str) -> Optional[Dict[str, Any]]:
        try:
            return self._get_document(self.warehouse_index, doc_id)
        except Exception as e:
            logger.error(f"Failed to get warehouse document {doc_id}: {e}")
            return None

    def get_processed_document(self, doc_id: str) -> Optional[Dict[str, Any]]:
        logger.warning("get_processed_document() is deprecated; reading from warehouse instead")
        return self.get_review_document(doc_id)

    def update_warehouse_document(self, doc_id: str, fields: Dict[str, Any]) -> bool:
        try:
            return self._update_document(self.warehouse_index, doc_id, fields)
        except Exception as e:
            logger.error(f"Failed to update warehouse document {doc_id}: {e}")
            return False

    def update_processed_document(self, doc_id: str, fields: Dict[str, Any]) -> bool:
        logger.warning("update_processed_document() is deprecated; updating warehouse instead")
        return self.update_warehouse_document(doc_id, fields)
    
    def search_warehouse(
        self,
        query: str = "*",
        ioc_type: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> Dict[str, Any]:
        must_clauses = []
        
        if query and query != "*":
            must_clauses.append({
                "multi_match": {
                    "query": query,
                    "fields": ["ioc_value^3", "description", "tags"]
                }
            })
        
        if ioc_type:
            must_clauses.append({"term": {"ioc_type": ioc_type}})
        
        if severity:
            must_clauses.append({"term": {"ai_severity": severity}})
        
        search_body = {
            "query": {"bool": {"must": must_clauses if must_clauses else [{"match_all": {}}]}},
            "sort": [{"ai_risk_score": "desc"}, {"processed_at": "desc"}],
            "from": offset,
            "size": limit
        }
        
        try:
            client = self._get_client(self.warehouse_index)
            if ES_CLIENT_AVAILABLE and client:
                result = client.search(index=self.warehouse_index, body=search_body)
            else:
                resp = httpx.post(
                    f"{self.url}/{self.warehouse_index}/_search",
                    json=search_body,
                    timeout=30,
                    headers=self._get_headers(self.warehouse_index)
                )
                result = resp.json()
            
            return {
                "total": result["hits"]["total"]["value"],
                "data": [hit["_source"] for hit in result["hits"]["hits"]]
            }
        except Exception as e:
            logger.error(f"Warehouse search failed: {e}")
            return {"total": 0, "data": [], "error": str(e)}
    
    def get_warehouse_stats(self) -> Dict[str, Any]:
        aggs_body = {
            "size": 0,
            "aggs": {
                "by_severity": {"terms": {"field": "ai_severity"}},
                "by_type": {"terms": {"field": "ioc_type"}},
                "avg_score": {"avg": {"field": "ai_risk_score"}},
                "by_threat_type": {"terms": {"field": "ai_threat_types", "size": 20}}
            }
        }
        
        try:
            client = self._get_client(self.warehouse_index)
            if ES_CLIENT_AVAILABLE and client:
                result = client.search(index=self.warehouse_index, body=aggs_body)
            else:
                resp = httpx.post(
                    f"{self.url}/{self.warehouse_index}/_search",
                    json=aggs_body,
                    timeout=30,
                    headers=self._get_headers(self.warehouse_index)
                )
                result = resp.json()
            
            return {
                "by_severity": result["aggregations"]["by_severity"]["buckets"],
                "by_type": result["aggregations"]["by_type"]["buckets"],
                "avg_score": result["aggregations"]["avg_score"]["value"],
                "by_threat_type": result["aggregations"]["by_threat_type"]["buckets"]
            }
        except Exception as e:
            logger.error(f"Failed to get warehouse stats: {e}")
            return {}


# Singleton instance
_client: Optional[ElasticClient] = None


def get_elastic_client() -> ElasticClient:
    """Get or create Elasticsearch client instance."""
    global _client
    if _client is None:
        _client = ElasticClient()
    return _client
