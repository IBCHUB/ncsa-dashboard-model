"""
Elasticsearch Client for AI Service

Provides connection to Elasticsearch for:
- Data Lake (raw/semi-processed IOCs)
- Data Warehouse (AI-processed IOCs)
"""

import os
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
import hashlib
from urllib.parse import quote

logger = logging.getLogger(__name__)

# Configuration
ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
DATALAKE_INDEX = os.getenv("DATALAKE_INDEX", "tcti-datalake")
PROCESSED_INDEX = os.getenv("PROCESSED_INDEX", "tcti-processed")
WAREHOUSE_INDEX = os.getenv("WAREHOUSE_INDEX", "tcti-warehouse")

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
    
    Supports two indexes:
    - tcti-datalake: Raw/semi-processed IOCs (input for AI)
    - tcti-warehouse: AI-processed IOCs (output, consumed by Dashboard)
    """
    
    def __init__(self, url: str = ELASTICSEARCH_URL):
        self.url = url
        self.datalake_index = DATALAKE_INDEX
        self.processed_index = PROCESSED_INDEX
        self.warehouse_index = WAREHOUSE_INDEX
        
        if ES_CLIENT_AVAILABLE:
            self.client = Elasticsearch(url)
        else:
            self.client = None
            logger.warning("elasticsearch-py not installed, using httpx fallback")
    
    def health_check(self) -> Dict[str, Any]:
        """Check Elasticsearch cluster health."""
        try:
            if ES_CLIENT_AVAILABLE and self.client:
                return self.client.cluster.health()
            else:
                response = httpx.get(f"{self.url}/_cluster/health", timeout=10)
                return response.json()
        except Exception as e:
            logger.error(f"Elasticsearch health check failed: {e}")
            return {"status": "unavailable", "error": str(e)}

    @staticmethod
    def _build_warehouse_doc_id(ioc_data: Dict[str, Any]) -> str:
        """
        Build stable warehouse doc ID by IOC type + value.
        Using hash avoids URL path issues for raw IOC values.
        """
        ioc_type = str(ioc_data.get("ioc_type", "unknown")).strip().lower()
        ioc_value = str(ioc_data.get("ioc_value", "")).strip().lower()
        payload = f"{ioc_type}:{ioc_value}".encode("utf-8")
        digest = hashlib.sha1(payload).hexdigest()[:24]
        return f"{ioc_type}:{digest}"

    @staticmethod
    def _build_processed_doc_id(ioc_data: Dict[str, Any]) -> str:
        """
        Build stable processed doc ID for validation/backup stage.
        Includes time window and source set to preserve changes over runs.
        """
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
        """
        Build unique Data Lake doc ID per IOC observation (not per IOC value).
        This preserves cross-source evidence required for enrichment/scoring.
        """
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
        """Create Data Lake and Data Warehouse indexes if they don't exist."""
        results = {}
        
        # Data Lake index mapping
        datalake_mapping = {
            "mappings": {
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
                    "created_at": {"type": "date"}
                }
            }
        }
        
        # Processed layer mapping (validation and backup before warehouse)
        processed_mapping = {
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
                    "ai_threat_types": {"type": "keyword"},
                    "ai_threat_actors": {"type": "keyword"},
                    "ai_mitre_techniques": {"type": "keyword"},
                    "ai_classification_confidence": {"type": "float"},
                    "ai_score_breakdown": {"type": "object", "enabled": False},
                    "ai_top_factors": {"type": "object", "enabled": False},
                    "score_model_version": {"type": "keyword"},
                    "score_config_version": {"type": "keyword"},
                    "credibility_score": {"type": "integer"},
                    "impact_score": {"type": "integer"},
                    "validation_status": {"type": "keyword"},
                    "processed_at": {"type": "date"},
                    "created_at": {"type": "date"}
                }
            }
        }

        # Data Warehouse index mapping (includes AI fields)
        warehouse_mapping = {
            "mappings": {
                "properties": {
                    "ioc_value": {"type": "keyword"},
                    "ioc_type": {"type": "keyword"},
                    "source_name": {"type": "keyword"},
                    "source_type": {"type": "keyword"},
                    "sources": {"type": "keyword"},  # Array of source names
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
                    # AI Enrichment fields
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
                    "processed_at": {"type": "date"},
                    "created_at": {"type": "date"}
                }
            }
        }
        
        for index, mapping in [
            (self.datalake_index, datalake_mapping),
            (self.processed_index, processed_mapping),
            (self.warehouse_index, warehouse_mapping)
        ]:
            try:
                if ES_CLIENT_AVAILABLE and self.client:
                    if not self.client.indices.exists(index=index):
                        self.client.indices.create(index=index, body=mapping)
                        results[index] = True
                        logger.info(f"Created index: {index}")
                    else:
                        results[index] = True
                        logger.info(f"Index already exists: {index}")
                else:
                    # Check if exists
                    check = httpx.head(f"{self.url}/{index}", timeout=10)
                    if check.status_code == 404:
                        resp = httpx.put(
                            f"{self.url}/{index}",
                            json=mapping,
                            timeout=30
                        )
                        results[index] = resp.status_code in (200, 201)
                    else:
                        results[index] = True
            except Exception as e:
                logger.error(f"Failed to create index {index}: {e}")
                results[index] = False
        
        return results
    
    def get_unprocessed_iocs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get IOCs from Data Lake that haven't been processed by AI yet."""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"ai_processed": False}}
                    ]
                }
            },
            "size": limit
        }
        
        try:
            if ES_CLIENT_AVAILABLE and self.client:
                result = self.client.search(index=self.datalake_index, body=query)
                return [hit["_source"] | {"_id": hit["_id"]} for hit in result["hits"]["hits"]]
            else:
                resp = httpx.post(
                    f"{self.url}/{self.datalake_index}/_search",
                    json=query,
                    timeout=30
                )
                data = resp.json()
                return [hit["_source"] | {"_id": hit["_id"]} for hit in data["hits"]["hits"]]
        except Exception as e:
            logger.error(f"Failed to get unprocessed IOCs: {e}")
            return []
    
    def mark_as_processed(self, doc_id: str) -> bool:
        """Mark an IOC in Data Lake as processed."""
        try:
            if ES_CLIENT_AVAILABLE and self.client:
                self.client.update(
                    index=self.datalake_index,
                    id=doc_id,
                    body={"doc": {"ai_processed": True}}
                )
                return True
            else:
                resp = httpx.post(
                    f"{self.url}/{self.datalake_index}/_update/{doc_id}",
                    json={"doc": {"ai_processed": True}},
                    timeout=10
                )
                return resp.status_code == 200
        except Exception as e:
            logger.error(f"Failed to mark IOC as processed: {e}")
            return False
    
    def save_to_warehouse(self, ioc_data: Dict[str, Any]) -> Optional[str]:
        """Save AI-processed IOC to Data Warehouse."""
        # Add timestamp
        ioc_data["processed_at"] = datetime.utcnow().isoformat() + "Z"
        if "created_at" not in ioc_data:
            ioc_data["created_at"] = ioc_data["processed_at"]
        
        try:
            doc_id = self._build_warehouse_doc_id(ioc_data)
            if ES_CLIENT_AVAILABLE and self.client:
                result = self.client.index(
                    index=self.warehouse_index,
                    body=ioc_data,
                    id=doc_id
                )
                return result.get("_id")
            else:
                resp = httpx.put(
                    f"{self.url}/{self.warehouse_index}/_doc/{quote(doc_id, safe='')}",
                    json=ioc_data,
                    timeout=10
                )
                if resp.status_code in (200, 201):
                    return resp.json().get("_id")
                return None
        except Exception as e:
            logger.error(f"Failed to save to warehouse: {e}")
            return None

    def save_to_processed(self, ioc_data: Dict[str, Any]) -> Optional[str]:
        """Save AI-processed IOC to Processed layer (validation/backup stage)."""
        ioc_data["processed_at"] = datetime.utcnow().isoformat() + "Z"
        if "created_at" not in ioc_data:
            ioc_data["created_at"] = ioc_data["processed_at"]
        ioc_data["validation_status"] = ioc_data.get("validation_status", "validated")

        try:
            doc_id = self._build_processed_doc_id(ioc_data)
            if ES_CLIENT_AVAILABLE and self.client:
                result = self.client.index(
                    index=self.processed_index,
                    body=ioc_data,
                    id=doc_id
                )
                return result.get("_id")
            else:
                resp = httpx.put(
                    f"{self.url}/{self.processed_index}/_doc/{quote(doc_id, safe='')}",
                    json=ioc_data,
                    timeout=10
                )
                if resp.status_code in (200, 201):
                    return resp.json().get("_id")
                return None
        except Exception as e:
            logger.error(f"Failed to save to processed layer: {e}")
            return None
    
    def bulk_index_datalake(self, documents: List[Dict]) -> Dict[str, int]:
        """Bulk index documents to Data Lake."""
        success = 0
        failed = 0
        
        for doc in documents:
            doc["ai_processed"] = False
            doc["created_at"] = datetime.utcnow().isoformat() + "Z"
            
            try:
                ioc_id = self._build_datalake_doc_id(doc)
                if ES_CLIENT_AVAILABLE and self.client:
                    self.client.index(
                        index=self.datalake_index,
                        body=doc,
                        id=ioc_id
                    )
                    success += 1
                else:
                    resp = httpx.put(
                        f"{self.url}/{self.datalake_index}/_doc/{quote(ioc_id, safe='')}",
                        json=doc,
                        timeout=10
                    )
                    if resp.status_code in (200, 201):
                        success += 1
                    else:
                        failed += 1
            except Exception as e:
                logger.error(f"Failed to index document: {e}")
                failed += 1
        
        return {"success": success, "failed": failed}
    
    def search_warehouse(
        self,
        query: str = "*",
        ioc_type: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> Dict[str, Any]:
        """Search the Data Warehouse for IOCs."""
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
            "query": {
                "bool": {
                    "must": must_clauses if must_clauses else [{"match_all": {}}]
                }
            },
            "sort": [{"ai_risk_score": "desc"}, {"processed_at": "desc"}],
            "from": offset,
            "size": limit
        }
        
        try:
            if ES_CLIENT_AVAILABLE and self.client:
                result = self.client.search(index=self.warehouse_index, body=search_body)
            else:
                resp = httpx.post(
                    f"{self.url}/{self.warehouse_index}/_search",
                    json=search_body,
                    timeout=30
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
        """Get statistics from Data Warehouse."""
        aggs_body = {
            "size": 0,
            "aggs": {
                "by_severity": {
                    "terms": {"field": "ai_severity"}
                },
                "by_type": {
                    "terms": {"field": "ioc_type"}
                },
                "avg_score": {
                    "avg": {"field": "ai_risk_score"}
                },
                "by_threat_type": {
                    "terms": {"field": "ai_threat_types", "size": 20}
                }
            }
        }
        
        try:
            if ES_CLIENT_AVAILABLE and self.client:
                result = self.client.search(index=self.warehouse_index, body=aggs_body)
            else:
                resp = httpx.post(
                    f"{self.url}/{self.warehouse_index}/_search",
                    json=aggs_body,
                    timeout=30
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
