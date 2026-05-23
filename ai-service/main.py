"""
AI Service API

FastAPI server for threat classification and risk scoring.
"""

from typing import Any, Dict, List, Optional, Tuple
import asyncio
import logging
import threading

import time
import os

from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field

from config import HOST, PORT, DEBUG, API_KEYS, REQUIRE_AUTH
from models.classifier import (
    classify_threat,
    extract_threat_actors,
    extract_mitre_techniques
)
from models.scorer import calculate_risk_score
from models.validation import REJECTED
from services.dashboard_compat_router import router as dashboard_compat_router
from services.dashboard_router import router as dashboard_router
from services.external_sharing_router import router as external_sharing_router
from utils.pipeline_documents import build_enriched_ioc_document
from utils.sanitizer import sanitize_text
from models.campaign_clusterer import cluster_iocs
from utils.cors import build_cors_origins

# Configure logging
logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

PIPELINE_SCHEDULER_ENABLED = os.getenv("PIPELINE_SCHEDULER_ENABLED", "false").lower() == "true"
PIPELINE_SCHEDULER_INTERVAL_SECONDS = int(os.getenv("PIPELINE_SCHEDULER_INTERVAL_SECONDS", "3600"))
PIPELINE_SCHEDULER_INITIAL_DELAY_SECONDS = int(os.getenv("PIPELINE_SCHEDULER_INITIAL_DELAY_SECONDS", "60"))
PIPELINE_SCHEDULER_LIMIT = int(os.getenv("PIPELINE_SCHEDULER_LIMIT", "100"))
_pipeline_lock = threading.Lock()
_pipeline_scheduler_task: Optional[asyncio.Task] = None

# Create FastAPI app
app = FastAPI(
    title="Thailand Cyber Threat Intelligence - AI Service",
    description="NLP Classification and Risk Scoring for IOCs",
    version="1.0.0"
)

# CORS middleware
cors_origins = build_cors_origins(os.getenv("AI_SERVICE_CORS_ORIGINS", "*"))
allow_credentials = "*" not in cors_origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins or ["*"],
    allow_credentials=allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(dashboard_compat_router)
app.include_router(dashboard_router)
app.include_router(external_sharing_router)

# ============================================
# AUTHENTICATION
# ============================================
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(api_key: str = Security(api_key_header)):
    """
    Verify API key for protected endpoints.
    If REQUIRE_AUTH is False, authentication is bypassed (for development).
    """
    if not REQUIRE_AUTH:
        return None  # Auth disabled

    if not API_KEYS:
        logger.error("Authentication is enabled but AI_SERVICE_API_KEYS is empty")
        raise HTTPException(
            status_code=500,
            detail="Server authentication misconfigured."
        )
    
    if api_key is None:
        raise HTTPException(
            status_code=401,
            detail="Missing API Key. Include 'X-API-Key' header.",
            headers={"WWW-Authenticate": "ApiKey"}
        )
    
    import hmac
    if not any(hmac.compare_digest(api_key, k) for k in API_KEYS):
        logger.warning("Invalid API key attempt")
        raise HTTPException(
            status_code=403,
            detail="Invalid API Key.",
            headers={"WWW-Authenticate": "ApiKey"}
        )
    
    return api_key


# Request/Response Models
class ClassifyRequest(BaseModel):
    text: str = Field(..., description="Text to classify (title + description)", max_length=10000)
    threshold: float = Field(0.3, description="Confidence threshold", ge=0.0, le=1.0)


class ClassifyResponse(BaseModel):
    threat_types: List[str]
    confidence: float
    all_labels: List[str]
    all_scores: List[float]
    threat_actors: List[str]
    mitre_techniques: List[str]


class ScoreRequest(BaseModel):
    ioc_value: str = Field(..., description="IOC value (IP, domain, hash, etc.)", max_length=2048)
    ioc_type: str = Field(..., description="Type of IOC", max_length=64)
    description: str = Field("", description="Threat description", max_length=50000)
    sources: List[str] = Field(default_factory=list, description="Data sources", max_length=50)
    country_code: Optional[str] = Field(None, description="Country code", max_length=4)
    domain_age_days: Optional[int] = Field(None, description="Domain age in days", ge=0)
    ioc_age_days: Optional[int] = Field(None, description="IOC age in days", ge=0)


class ScoreResponse(BaseModel):
    risk_score: int
    operational_risk_score: Optional[int] = None
    credibility_score: Optional[int] = None
    impact_score: Optional[int] = None
    severity: str
    score_model_version: Optional[str] = None
    score_config_version: Optional[str] = None
    breakdown: dict
    top_factors: List[dict]


class EnrichRequest(BaseModel):
    ioc_value: str = Field(..., max_length=2048)
    ioc_type: str = Field(..., max_length=64)
    description: str = Field("", max_length=50000)
    title: str = Field("", max_length=500)
    sources: List[str] = Field(default_factory=list, max_length=50)
    country_code: Optional[str] = Field(None, max_length=4)
    domain_age_days: Optional[int] = Field(None, ge=0)
    ioc_age_days: Optional[int] = Field(None, ge=0)


class EnrichResponse(BaseModel):
    ioc_value: str
    ioc_type: str
    # Classification results
    ai_threat_types: List[str]
    ai_threat_actors: List[str]
    ai_mitre_techniques: List[str]
    ai_classification_confidence: float
    # Scoring results
    ai_risk_score: int
    ai_operational_risk_score: Optional[int] = None
    ai_credibility_score: Optional[int] = None
    ai_impact_score: Optional[int] = None
    ai_severity: str
    ai_score_model_version: Optional[str] = None
    ai_score_config_version: Optional[str] = None
    ai_score_breakdown: dict
    ai_top_factors: List[dict]
    # Metadata
    processing_time_ms: int


class BatchEnrichRequest(BaseModel):
    items: List[EnrichRequest] = Field(..., max_length=100)


class BatchEnrichResponse(BaseModel):
    results: List[EnrichResponse]
    total_processing_time_ms: int


class HealthResponse(BaseModel):
    status: str
    version: str
    classifier_loaded: bool


class TranslateRequest(BaseModel):
    text: str = Field(..., description="Text to translate", max_length=10000)
    target_lang: str = Field("th", description="Target language code (th, en, ja, zh)", pattern="^(th|en|ja|zh)$")
    context: str = Field("cybersecurity threat intelligence", description="Domain context for better translation", max_length=200)


class TranslateResponse(BaseModel):
    original: str
    translated: str
    target_lang: str
    cached: bool = False


# Endpoints
@app.get("/", response_model=HealthResponse)
@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    from models.classifier import models_loaded
    
    return {
        "status": "healthy",
        "version": "1.0.0",
        "classifier_loaded": models_loaded()
    }


@app.post("/classify", response_model=ClassifyResponse)
async def classify_endpoint(request: ClassifyRequest, api_key: str = Depends(verify_api_key)):
    """Classify threat description into categories. Requires API Key."""
    try:
        start = time.time()

        sanitized_text = sanitize_text(request.text)["text"]
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, lambda: classify_threat(sanitized_text, threshold=request.threshold))
        actors = await loop.run_in_executor(None, lambda: extract_threat_actors(sanitized_text))
        mitre = await loop.run_in_executor(None, lambda: extract_mitre_techniques(sanitized_text))

        
        elapsed = int((time.time() - start) * 1000)
        logger.info(f"Classification completed in {elapsed}ms")
        
        return {
            "threat_types": result["threat_types"],
            "confidence": result["confidence"],
            "all_labels": result["labels"],
            "all_scores": result["scores"],
            "threat_actors": actors,
            "mitre_techniques": mitre
        }
        
    except Exception as e:
        logger.error(f"Classification error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal processing error")


@app.post("/score", response_model=ScoreResponse)
async def score_endpoint(request: ScoreRequest, api_key: str = Depends(verify_api_key)):
    """Calculate risk score for an IOC. Requires API Key."""
    try:
        start = time.time()

        sanitized_description = sanitize_text(request.description)["text"]
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, lambda: calculate_risk_score(

            ioc_value=request.ioc_value,
            ioc_type=request.ioc_type,
            description=sanitized_description,
            sources=request.sources,
            country_code=request.country_code,
            domain_age_days=request.domain_age_days,
            ioc_age_days=request.ioc_age_days
        ))

        
        elapsed = int((time.time() - start) * 1000)
        logger.info(f"Scoring completed in {elapsed}ms")
        
        return result
        
    except Exception as e:
        logger.error(f"Scoring error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal processing error")


@app.post("/enrich", response_model=EnrichResponse)
async def enrich_endpoint(request: EnrichRequest, api_key: str = Depends(verify_api_key)):
    """
    Full enrichment: classify + score in one call.
    This is the main endpoint for Dashboard integration.
    Requires API Key.
    """
    try:
        start = time.time()

        # Combine title and description for better classification
        full_text = sanitize_text(f"{request.title} {request.description}".strip())["text"]
        
        # 1. Classify threat
        loop = asyncio.get_running_loop()
        classification = await loop.run_in_executor(None, lambda: classify_threat(full_text))
        actors = await loop.run_in_executor(None, lambda: extract_threat_actors(full_text))
        mitre = await loop.run_in_executor(None, lambda: extract_mitre_techniques(full_text))
        
        # 2. Build full classification dict for scorer
        full_classification = {
            "threat_types": classification["threat_types"],
            "threat_actors": actors,
            "mitre_techniques": mitre,
            "confidence": classification["confidence"]
        }
        
        # 3. Calculate risk score (with full classification data)
        score_result = calculate_risk_score(
            ioc_value=request.ioc_value,
            ioc_type=request.ioc_type,
            description=full_text,
            sources=request.sources,
            country_code=request.country_code,
            domain_age_days=request.domain_age_days,
            ioc_age_days=request.ioc_age_days,
            threat_classification=full_classification
        )
        
        elapsed = int((time.time() - start) * 1000)
        logger.info(
            f"Enrichment completed in {elapsed}ms for {request.ioc_value} | "
            f"Score: {score_result['risk_score']} ({score_result['severity']}) | "
            f"Types: {classification['threat_types']} | Actors: {actors}"
        )
        
        return {
            "ioc_value": request.ioc_value,
            "ioc_type": request.ioc_type,
            # Classification
            "ai_threat_types": classification["threat_types"],
            "ai_threat_actors": actors,
            "ai_mitre_techniques": mitre,
            "ai_classification_confidence": classification["confidence"],
            # Scoring
            "ai_risk_score": score_result["risk_score"],
            "ai_operational_risk_score": score_result.get("operational_risk_score"),
            "ai_credibility_score": score_result.get("credibility_score"),
            "ai_impact_score": score_result.get("impact_score"),
            "ai_severity": score_result["severity"],
            "ai_score_model_version": score_result.get("score_model_version"),
            "ai_score_config_version": score_result.get("score_config_version"),
            "ai_score_breakdown": score_result["breakdown"],
            "ai_top_factors": score_result["top_factors"],
            # Metadata
            "processing_time_ms": elapsed
        }
        
    except Exception as e:
        logger.error(f"Enrichment error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal processing error")


@app.post("/enrich/batch", response_model=BatchEnrichResponse)
async def batch_enrich_endpoint(request: BatchEnrichRequest, api_key: str = Depends(verify_api_key)):
    """
    Batch enrichment for multiple IOCs. Requires API Key.
    """
    start = time.time()
    results = []
    
    for item in request.items:
        try:
            result = await enrich_endpoint(item, api_key)
            results.append(result)
        except Exception as e:
            logger.error(f"Batch item error for {item.ioc_value}: {e}")
            # Return partial result on error
            results.append({
                "ioc_value": item.ioc_value,
                "ioc_type": item.ioc_type,
                "ai_threat_types": [],
                "ai_threat_actors": [],
                "ai_mitre_techniques": [],
                "ai_classification_confidence": 0.0,
                "ai_risk_score": 0,
                "ai_operational_risk_score": None,
                "ai_credibility_score": None,
                "ai_impact_score": None,
                "ai_severity": "unknown",
                "ai_score_model_version": None,
                "ai_score_config_version": None,
                "ai_score_breakdown": {},
                "ai_top_factors": [],
                "processing_time_ms": 0,
            })
    
    total_elapsed = int((time.time() - start) * 1000)
    logger.info(f"Batch enrichment completed: {len(results)} items in {total_elapsed}ms")
    
    return {
        "results": results,
        "total_processing_time_ms": total_elapsed
    }


# ============================================
# TRANSLATION ENDPOINTS
# ============================================

@app.post("/translate", response_model=TranslateResponse)
async def translate_endpoint(request: TranslateRequest, api_key: str = Depends(verify_api_key)):
    """
    Translate text using OpenAI GPT with cybersecurity context.
    Optimized for threat intelligence terminology.
    Requires API Key.
    """
    try:
        import hashlib
        from utils.translator import translate_content, _translation_cache

        # Check if already cached — use deterministic hash, not Python's hash()
        text_hash = hashlib.sha256(request.text.encode()).hexdigest()[:32]
        cache_key = f"{request.target_lang}:{text_hash}"
        cached = cache_key in _translation_cache
        
        translated = translate_content(
            text=request.text,
            target_lang=request.target_lang,
            context=request.context
        )
        
        logger.info(f"Translation completed: {len(request.text)} chars → {request.target_lang} (cached={cached})")
        
        return {
            "original": request.text,
            "translated": translated,
            "target_lang": request.target_lang,
            "cached": cached
        }
        
    except Exception as e:
        logger.error(f"Translation error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal processing error")




# ============================================
# AI PIPELINE ENDPOINTS (Data Lake → AI → Data Warehouse)
# ============================================

class PipelineRunRequest(BaseModel):
    limit: int = Field(default=100, description="Maximum IOCs to process per run")


class PipelineRunResponse(BaseModel):
    processed: int
    rejected: int
    failed: int
    normalized: int = 0
    quarantined: int = 0
    skipped_duplicate: int = 0
    ml_classified: int = 0
    rule_classified: int = 0
    ml_skipped: int = 0
    evidence_enriched: int = 0
    vt_evidence_count: int = 0
    misp_risk_score_count: int = 0
    correlation_evidence_count: int = 0
    clustered_count: int = 0
    avg_ms_per_ioc: float = 0.0
    observations_updated: int
    processing_time_ms: int
    message: str


class ElasticsearchStatusResponse(BaseModel):
    status: str
    datalake_index: str
    warehouse_index: str
    datalake_count: int
    warehouse_count: int
    processed_index: Optional[str] = None
    processed_state_count: Optional[int] = None
    quarantine_index: Optional[str] = None
    quarantine_count: Optional[int] = None
    scheduler_enabled: bool = False
    scheduler_interval_seconds: int = 0


def _run_pipeline_once_sync(limit: int) -> Dict[str, Any]:
    if not _pipeline_lock.acquire(blocking=False):
        return {
            "processed": 0,
            "rejected": 0,
            "failed": 0,
            "normalized": 0,
            "quarantined": 0,
            "skipped_duplicate": 0,
            "ml_classified": 0,
            "rule_classified": 0,
            "ml_skipped": 0,
            "evidence_enriched": 0,
            "vt_evidence_count": 0,
            "misp_risk_score_count": 0,
            "correlation_evidence_count": 0,
            "avg_ms_per_ioc": 0.0,
            "observations_updated": 0,
            "processing_time_ms": 0,
            "message": "Pipeline skipped: another run is already in progress"
        }

    try:
        from elastic_client import DATALAKE_READONLY, ElasticClient, get_elastic_client

        start = time.time()
        es_client = get_elastic_client()
        es_client.create_processed_index()
        es_client.create_quarantine_index()

        # Get unprocessed IOCs from Data Lake. For read-only sources, this is
        # filtered by the local processed-state index on the warehouse cluster.
        unprocessed = es_client.get_unprocessed_iocs(limit=limit)

        if not unprocessed:
            return {
                "processed": 0,
                "rejected": 0,
                "failed": 0,
                "normalized": 0,
                "quarantined": 0,
                "skipped_duplicate": 0,
                "ml_classified": 0,
                "rule_classified": 0,
                "ml_skipped": 0,
                "evidence_enriched": 0,
                "vt_evidence_count": 0,
                "misp_risk_score_count": 0,
                "correlation_evidence_count": 0,
                "avg_ms_per_ioc": 0.0,
                "observations_updated": 0,
                "processing_time_ms": 0,
                "message": "No unprocessed IOCs found in Data Lake"
            }

        normalized = 0
        quarantined = 0
        skipped_duplicate = 0

        # 1:1 observation mode — each datalake observation becomes its own
        # warehouse row. Key the "group" by the datalake doc id (or a
        # synthetic per-row id) so build_enriched_ioc_document sees one doc
        # at a time and we keep all per-observation timestamps, sources,
        # descriptions distinct in the warehouse.
        grouped_iocs: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
        for index, ioc in enumerate(unprocessed):
            if ioc.get("adapter_status") == "quarantined":
                if es_client.save_quarantine(ioc, reason=ioc.get("quarantine_reason")):
                    quarantined += 1
                else:
                    skipped_duplicate += 1
                continue

            ioc_type = ElasticClient.normalize_ioc_type(ioc.get("ioc_type"))
            ioc_value = ElasticClient.normalize_ioc_value(ioc.get("ioc_value"))
            if not ioc_value:
                if es_client.save_quarantine(ioc, reason="missing_ioc_value"):
                    quarantined += 1
                continue
            obs_key = str(ioc.get("_id") or f"{ioc_type}:{ioc_value}:{index}")
            grouped_iocs[(ioc_type, obs_key)] = [ioc]
            normalized += 1

        # 1:1 observation mode skips the pre-merge step — every datalake
        # observation is its own warehouse row, so there's no existing doc
        # to merge sources with. Keep the loop structure but turn the
        # existing-doc lookup into a no-op so the rest of the pipeline
        # unchanged.
        warehouse_doc_ids: Dict[Tuple[str, str], str] = {}
        existing_warehouse: Dict[str, Dict[str, Any]] = {}
        id_to_key: Dict[str, Tuple[str, str]] = {}

        for key, ioc_docs_for_key in grouped_iocs.items():
            doc_id = warehouse_doc_ids.get(key)
            existing = existing_warehouse.get(doc_id) if doc_id else None
            if existing:
                existing_source_objs = existing.get("source_objects") or []
                if not existing_source_objs:
                    raw_names = existing.get("sources") or []
                    if isinstance(raw_names, list):
                        existing_source_objs = [
                            {"name": n, "confidence": 0, "type": "unknown"}
                            for n in raw_names
                            if isinstance(n, str) and n.strip()
                        ]
                if isinstance(existing_source_objs, list):
                    new_source_names = {
                        str(d.get("source_name", "")).strip()
                        for d in ioc_docs_for_key
                        if d.get("source_name")
                    }
                    for src_obj in existing_source_objs:
                        src_name = str(src_obj.get("name", "")).strip()
                        if src_name and src_name not in new_source_names:
                            ioc_docs_for_key.append({
                                "source_name": src_name,
                                "confidence": src_obj.get("confidence", 0),
                                "source_type": src_obj.get("type", "unknown"),
                                "ioc_value": ioc_docs_for_key[0].get("ioc_value"),
                                "ioc_type": ioc_docs_for_key[0].get("ioc_type"),
                                "description": "",
                                "severity": "",
                                "threat_type": [],
                                "tags": [],
                                "event_time": existing.get("first_seen"),
                                "collect_time": existing.get("last_seen"),
                                "_synthetic_from_warehouse": True,
                            })

        processed = 0
        rejected = 0
        failed = 0
        processed_observations = 0
        ml_classified = 0
        rule_classified = 0
        ml_skipped = 0
        evidence_enriched = 0
        vt_evidence_count = 0
        misp_risk_score_count = 0
        correlation_evidence_count = 0
        warehouse_items: List[Dict[str, Any]] = []
        processed_state_items: List[Dict[str, Any]] = []
        datalake_doc_ids_to_mark: List[str] = []

        for (_, _), ioc_docs in grouped_iocs.items():
            try:
                build_result = build_enriched_ioc_document(ioc_docs)
                pipeline_doc = build_result["document"]
                classification_mode = pipeline_doc.get("classification_mode")
                if classification_mode == "ml":
                    ml_classified += 1
                elif classification_mode == "source_rule":
                    rule_classified += 1
                else:
                    ml_skipped += 1
                if pipeline_doc.get("source_evidence"):
                    evidence_enriched += 1
                if (pipeline_doc.get("virustotal_malicious") or 0) > 0 or (pipeline_doc.get("virustotal_suspicious") or 0) > 0:
                    vt_evidence_count += 1
                if pipeline_doc.get("source_risk_score") is not None:
                    misp_risk_score_count += 1
                if (pipeline_doc.get("related_doc_count") or 0) > 0:
                    correlation_evidence_count += 1
                validation_status = pipeline_doc["validation_status"]
                ioc_value = pipeline_doc["ioc_value"]

                # 1:1 doc_id — fingerprint by source + event_time + ref so
                # each datalake observation gets its own warehouse row.
                warehouse_doc_id = ElasticClient._build_datalake_doc_id(pipeline_doc)
                warehouse_items.append({
                    "doc_id": warehouse_doc_id,
                    "document": dict(pipeline_doc),
                })
                state_status = "rejected" if validation_status == REJECTED else "processed"
                for doc in ioc_docs:
                    doc_id = doc.get("_id")
                    if doc_id:
                        datalake_doc_ids_to_mark.append(str(doc_id))
                    processed_state_items.append({
                        "doc": doc,
                        "status": state_status,
                        "warehouse_doc_id": warehouse_doc_id,
                    })

                if pipeline_doc["warehouse_eligible"]:
                    processed += 1
                elif validation_status == REJECTED:
                    rejected += 1
                processed_observations += len(ioc_docs)

            except Exception as e:
                logger.error(f"Pipeline error for {ioc_docs[0].get('ioc_value')}: {e}")
                for doc in ioc_docs:
                    es_client.mark_source_state(doc, "failed", error=str(e))
                failed += 1

        failed_warehouse_doc_ids: set[str] = set()
        if warehouse_items:
            warehouse_result = es_client.bulk_save_to_warehouse(warehouse_items)
            failed_warehouse_doc_ids = set(warehouse_result.get("failed_ids") or [])
            failed += int(warehouse_result.get("failed", 0) or 0)

        if processed_state_items:
            state_items_to_write = [
                item for item in processed_state_items
                if item.get("warehouse_doc_id") not in failed_warehouse_doc_ids
            ]
            state_result = es_client.bulk_mark_source_states(state_items_to_write)
            failed += int(state_result.get("failed", 0) or 0)

        if not DATALAKE_READONLY:
            for doc_id in datalake_doc_ids_to_mark:
                if not es_client.mark_as_processed(doc_id):
                    failed += 1

        # --- Campaign Clustering (incremental) ---
        # Disabled during 1:1 backfill: the bulk-update call races against the
        # bulk-index call in the same iteration (update sees the doc before the
        # index refresh applies → document_missing_exception per doc, ~10K
        # wasted ops per batch). Re-enable / re-cluster as a separate
        # post-ingest job once the warehouse is hydrated.
        clustered_count = 0
        if False and warehouse_items:
            try:
                batch_docs = [
                    item["document"] for item in warehouse_items
                    if item.get("doc_id") not in failed_warehouse_doc_ids
                ]
                cluster_results = cluster_iocs(batch_docs)
                cluster_lookup = {r["ioc_value"]: r for r in cluster_results}
                # Collect all cluster updates first, then write them in a
                # single bulk request. Per-doc _update calls used to dominate
                # iteration time — ~95% of every batch gets clustered, which
                # meant ~1900 round-trips × 50 ms ≈ 95 s wasted per iteration.
                cluster_updates: List[Tuple[str, Dict[str, Any]]] = []
                for item in warehouse_items:
                    doc = item["document"]
                    cr = cluster_lookup.get(doc.get("ioc_value"))
                    if cr and cr["cluster_label"] >= 0:
                        cluster_updates.append((
                            item["doc_id"],
                            {
                                "cluster_label": cr["cluster_label"],
                                "cluster_probability": round(cr["cluster_probability"], 4),
                            },
                        ))
                if cluster_updates:
                    result = es_client.bulk_update_warehouse_documents(cluster_updates)
                    clustered_count = int(result.get("success", 0) or 0)
            except Exception as _cluster_exc:
                logger.warning(f"Incremental clustering failed (non-fatal): {_cluster_exc}")

        elapsed = int((time.time() - start) * 1000)
        classified_iocs = ml_classified + rule_classified + ml_skipped
        avg_ms_per_ioc = round(elapsed / classified_iocs, 2) if classified_iocs else 0.0

        return {
            "processed": processed,
            "rejected": rejected,
            "failed": failed,
            "normalized": normalized,
            "quarantined": quarantined,
            "skipped_duplicate": skipped_duplicate,
            "ml_classified": ml_classified,
            "rule_classified": rule_classified,
            "ml_skipped": ml_skipped,
            "evidence_enriched": evidence_enriched,
            "vt_evidence_count": vt_evidence_count,
            "misp_risk_score_count": misp_risk_score_count,
            "correlation_evidence_count": correlation_evidence_count,
            "clustered_count": clustered_count,
            "avg_ms_per_ioc": avg_ms_per_ioc,
            "observations_updated": processed_observations,
            "processing_time_ms": elapsed,
            "message": (
                f"Pipeline completed: {processed} auto-validated to warehouse, "
                f"{rejected} rejected, "
                f"{processed_observations} observations updated, "
                f"ML={ml_classified}, rule={rule_classified}, skipped={ml_skipped}, "
                f"evidence={evidence_enriched}, vt={vt_evidence_count}, "
                f"source_risk={misp_risk_score_count}, correlations={correlation_evidence_count}, "
                f"clustered={clustered_count}, "
                f"{quarantined} quarantined, {failed} failed"
            )
        }
    finally:
        _pipeline_lock.release()


async def _run_pipeline_once(limit: int) -> Dict[str, Any]:
    return await asyncio.to_thread(_run_pipeline_once_sync, limit)


async def _pipeline_scheduler_loop() -> None:
    logger.info(
        "Pipeline scheduler enabled: interval=%ss initial_delay=%ss limit=%s",
        PIPELINE_SCHEDULER_INTERVAL_SECONDS,
        PIPELINE_SCHEDULER_INITIAL_DELAY_SECONDS,
        PIPELINE_SCHEDULER_LIMIT,
    )
    if PIPELINE_SCHEDULER_INITIAL_DELAY_SECONDS > 0:
        await asyncio.sleep(PIPELINE_SCHEDULER_INITIAL_DELAY_SECONDS)

    while True:
        try:
            result = await _run_pipeline_once(PIPELINE_SCHEDULER_LIMIT)
            logger.info("Scheduled pipeline result: %s", result)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error("Scheduled pipeline failed: %s", e, exc_info=True)

        await asyncio.sleep(PIPELINE_SCHEDULER_INTERVAL_SECONDS)


def _start_pipeline_scheduler() -> None:
    global _pipeline_scheduler_task
    if not PIPELINE_SCHEDULER_ENABLED:
        return
    if _pipeline_scheduler_task and not _pipeline_scheduler_task.done():
        return
    _pipeline_scheduler_task = asyncio.create_task(_pipeline_scheduler_loop())


@app.post("/pipeline/run", response_model=PipelineRunResponse)
async def run_pipeline(
    request: PipelineRunRequest = PipelineRunRequest(),
    api_key: str = Depends(verify_api_key)
):
    """
    Run AI Pipeline: Read from Data Lake → Process with AI → Write to Data Warehouse.
    
    This is the main on-demand pipeline endpoint that:
    1. Queries unprocessed IOCs from the configured Data Lake
    2. Runs classification and scoring on each
    3. Saves enriched results to the configured Data Warehouse
    4. Marks source IOCs as processed or records processed-state for read-only sources
    """
    return await _run_pipeline_once(request.limit)



@app.get("/pipeline/status", response_model=ElasticsearchStatusResponse)
async def pipeline_status(api_key: str = Depends(verify_api_key)):
    """Get Elasticsearch and pipeline status."""
    from elastic_client import get_elastic_client, DATALAKE_INDEX, WAREHOUSE_INDEX, PROCESSED_INDEX, QUARANTINE_INDEX
    
    es_client = get_elastic_client()
    health = es_client.health_check()
    
    # Get document counts
    datalake_count = es_client.count_documents(DATALAKE_INDEX)
    warehouse_count = es_client.count_documents(WAREHOUSE_INDEX)
    processed_state_count = es_client.count_documents(PROCESSED_INDEX)
    quarantine_count = es_client.count_documents(QUARANTINE_INDEX)
    
    return {
        "status": health.get("status", "unknown"),
        "datalake_index": DATALAKE_INDEX,
        "warehouse_index": WAREHOUSE_INDEX,
        "datalake_count": datalake_count,
        "warehouse_count": warehouse_count,
        "processed_index": PROCESSED_INDEX,
        "processed_state_count": processed_state_count,
        "quarantine_index": QUARANTINE_INDEX,
        "quarantine_count": quarantine_count,
        "scheduler_enabled": PIPELINE_SCHEDULER_ENABLED,
        "scheduler_interval_seconds": PIPELINE_SCHEDULER_INTERVAL_SECONDS
    }


@app.post("/elasticsearch/setup")
async def setup_elasticsearch(api_key: str = Depends(verify_api_key)):
    """Create Elasticsearch indexes for Data Lake and Data Warehouse."""
    from elastic_client import get_elastic_client
    
    es_client = get_elastic_client()
    results = es_client.create_indexes()
    
    return {
        "success": all(results.values()),
        "indexes": results
    }


@app.on_event("startup")
async def startup_event():
    """Pre-load models on startup."""
    _start_pipeline_scheduler()

    if os.getenv("AI_SERVICE_SKIP_STARTUP_PRELOAD", "").lower() == "true":
        logger.info("Skipping startup preload and Elasticsearch initialization")
        return

    logger.info("AI Service starting up...")
    logger.info(f"Loading classifier model (this may take 1-2 minutes on first run)...")
    
    # Pre-load classifier by making a dummy call
    try:
        classify_threat("test initialization")
        logger.info("Classifier loaded successfully!")
    except Exception as e:
        logger.warning(f"Failed to pre-load classifier: {e}")
    
    # Initialize Elasticsearch indexes
    try:
        from elastic_client import get_elastic_client
        es_client = get_elastic_client()
        health = es_client.health_check()
        auto_create_indexes = os.getenv("AI_SERVICE_AUTO_CREATE_INDEXES", "").lower() == "true"
        if health.get("status") in ("green", "degraded"):
            logger.info("Elasticsearch connected successfully!")
            if auto_create_indexes or es_client.url.startswith("http://localhost"):
                es_client.create_indexes()
                logger.info("Elasticsearch indexes ready!")
            else:
                logger.info("Skipping index auto-create for remote Elasticsearch")
        else:
            logger.warning(f"Elasticsearch not available: {health}")
    except Exception as e:
        logger.warning(f"Could not connect to Elasticsearch: {e}")


@app.on_event("shutdown")
async def shutdown_event():
    """Stop background tasks gracefully."""
    global _pipeline_scheduler_task
    if _pipeline_scheduler_task and not _pipeline_scheduler_task.done():
        _pipeline_scheduler_task.cancel()
        try:
            await _pipeline_scheduler_task
        except asyncio.CancelledError:
            pass


if __name__ == "__main__":
    import uvicorn
    
    logger.info(f"Starting AI Service on {HOST}:{PORT}")
    uvicorn.run(app, host=HOST, port=PORT, reload=DEBUG)
