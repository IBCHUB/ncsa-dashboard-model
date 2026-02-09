"""
AI Service API

FastAPI server for threat classification and risk scoring.
"""

from typing import Any, Dict, List, Optional, Tuple
import logging
import time
from datetime import datetime, timezone
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

# Configure logging
logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Thailand Cyber Threat Intelligence - AI Service",
    description="NLP Classification and Risk Scoring for IOCs",
    version="1.0.0"
)

# CORS middleware (allow Next.js dashboard)
cors_origins = [
    origin.strip() for origin in os.getenv(
        "AI_SERVICE_CORS_ORIGINS",
        "http://localhost:3000,http://localhost:3001"
    ).split(",")
    if origin.strip()
]
allow_credentials = "*" not in cors_origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins or ["http://localhost:3000"],
    allow_credentials=allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
    
    if api_key not in API_KEYS:
        logger.warning(f"Invalid API key attempt: {api_key[:8]}...")
        raise HTTPException(
            status_code=403,
            detail="Invalid API Key.",
            headers={"WWW-Authenticate": "ApiKey"}
        )
    
    return api_key


# Request/Response Models
class ClassifyRequest(BaseModel):
    text: str = Field(..., description="Text to classify (title + description)")
    threshold: float = Field(0.3, description="Confidence threshold")


class ClassifyResponse(BaseModel):
    threat_types: List[str]
    confidence: float
    all_labels: List[str]
    all_scores: List[float]
    threat_actors: List[str]
    mitre_techniques: List[str]


class ScoreRequest(BaseModel):
    ioc_value: str = Field(..., description="IOC value (IP, domain, hash, etc.)")
    ioc_type: str = Field(..., description="Type of IOC")
    description: str = Field("", description="Threat description")
    sources: List[str] = Field(default_factory=list, description="Data sources")
    country_code: Optional[str] = Field(None, description="Country code")
    domain_age_days: Optional[int] = Field(None, description="Domain age in days")
    ioc_age_days: Optional[int] = Field(None, description="IOC age in days")


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
    ioc_value: str
    ioc_type: str
    description: str = ""
    title: str = ""
    sources: List[str] = Field(default_factory=list)
    country_code: Optional[str] = None
    domain_age_days: Optional[int] = None
    ioc_age_days: Optional[int] = None


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
    items: List[EnrichRequest]


class BatchEnrichResponse(BaseModel):
    results: List[EnrichResponse]
    total_processing_time_ms: int


class HealthResponse(BaseModel):
    status: str
    version: str
    classifier_loaded: bool


class TranslateRequest(BaseModel):
    text: str = Field(..., description="Text to translate")
    target_lang: str = Field("th", description="Target language code (th, en, ja, zh)")
    context: str = Field("cybersecurity threat intelligence", description="Domain context for better translation")


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
    from models.classifier import _classifier
    
    return {
        "status": "healthy",
        "version": "1.0.0",
        "classifier_loaded": _classifier is not None
    }


@app.post("/classify", response_model=ClassifyResponse)
async def classify_endpoint(request: ClassifyRequest, api_key: str = Depends(verify_api_key)):
    """Classify threat description into categories. Requires API Key."""
    try:
        start = time.time()
        
        result = classify_threat(request.text, threshold=request.threshold)
        actors = extract_threat_actors(request.text)
        mitre = extract_mitre_techniques(request.text)
        
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
        logger.error(f"Classification error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/score", response_model=ScoreResponse)
async def score_endpoint(request: ScoreRequest, api_key: str = Depends(verify_api_key)):
    """Calculate risk score for an IOC. Requires API Key."""
    try:
        start = time.time()
        
        result = calculate_risk_score(
            ioc_value=request.ioc_value,
            ioc_type=request.ioc_type,
            description=request.description,
            sources=request.sources,
            country_code=request.country_code,
            domain_age_days=request.domain_age_days,
            ioc_age_days=request.ioc_age_days
        )
        
        elapsed = int((time.time() - start) * 1000)
        logger.info(f"Scoring completed in {elapsed}ms")
        
        return result
        
    except Exception as e:
        logger.error(f"Scoring error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


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
        full_text = f"{request.title} {request.description}".strip()
        
        # 1. Classify threat
        classification = classify_threat(full_text)
        actors = extract_threat_actors(full_text)
        mitre = extract_mitre_techniques(full_text)
        
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
        logger.error(f"Enrichment error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


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
                "ai_classification_confidence": 0,
                "ai_risk_score": 0,
                "ai_operational_risk_score": 0,
                "ai_credibility_score": 0,
                "ai_impact_score": 0,
                "ai_severity": "unknown",
                "ai_score_model_version": None,
                "ai_score_config_version": None,
                "ai_score_breakdown": {},
                "ai_top_factors": [],
                "processing_time_ms": 0,
                "error": str(e)
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
        from utils.translator import translate_content, _translation_cache
        
        # Check if already cached
        cache_key = f"{request.target_lang}:{hash(request.text)}"
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
        logger.error(f"Translation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# HELPDESK INTEGRATION ENDPOINTS
# ============================================

class CreateTicketRequest(BaseModel):
    ioc_value: str = Field(..., description="IOC value (IP, domain, hash)")
    ioc_type: str = Field(..., description="Type of IOC")
    description: str = Field(..., description="Threat description")
    risk_score: int = Field(..., description="AI risk score (0-100)")
    severity: str = Field(..., description="Severity level")
    threat_types: List[str] = Field(default_factory=list)
    threat_actors: List[str] = Field(default_factory=list)


class CreateTicketResponse(BaseModel):
    success: bool
    ticket_id: Optional[str]
    message: str
    mock: bool = False


@app.post("/helpdesk/ticket", response_model=CreateTicketResponse)
async def create_helpdesk_ticket(
    request: CreateTicketRequest,
    api_key: str = Depends(verify_api_key)
):
    """
    Create a ticket in THCert HelpDesk system.
    
    This endpoint allows the Dashboard to escalate threats to the HelpDesk.
    In mock mode, tickets are logged but not sent to the real API.
    """
    try:
        from integrations.helpdesk import create_incident_ticket
        
        result = create_incident_ticket(
            ioc_value=request.ioc_value,
            ioc_type=request.ioc_type,
            description=request.description,
            risk_score=request.risk_score,
            severity=request.severity,
            threat_types=request.threat_types,
            threat_actors=request.threat_actors
        )
        
        logger.info(f"HelpDesk ticket created: {result.ticket_id} (mock={result.mock})")
        
        return {
            "success": result.success,
            "ticket_id": result.ticket_id,
            "message": result.message,
            "mock": result.mock
        }
        
    except Exception as e:
        logger.error(f"HelpDesk ticket creation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# AI PIPELINE ENDPOINTS (Data Lake → AI → Data Warehouse)
# ============================================

class PipelineRunRequest(BaseModel):
    limit: int = Field(default=100, description="Maximum IOCs to process per run")


class PipelineRunResponse(BaseModel):
    processed: int
    failed: int
    processing_time_ms: int
    message: str


class ElasticsearchStatusResponse(BaseModel):
    status: str
    datalake_index: str
    processed_index: str
    warehouse_index: str
    datalake_count: int
    processed_count: int
    warehouse_count: int


@app.post("/pipeline/run", response_model=PipelineRunResponse)
async def run_pipeline(
    request: PipelineRunRequest = PipelineRunRequest(),
    api_key: str = Depends(verify_api_key)
):
    """
    Run AI Pipeline: Read from Data Lake → Process with AI → Write to Data Warehouse.
    
    This is the main on-demand pipeline endpoint that:
    1. Queries unprocessed IOCs from tcti-datalake
    2. Runs classification and scoring on each
    3. Saves enriched results to tcti-warehouse
    4. Marks source IOCs as processed
    """
    from elastic_client import get_elastic_client
    
    start = time.time()
    es_client = get_elastic_client()
    
    # Get unprocessed IOCs from Data Lake
    unprocessed = es_client.get_unprocessed_iocs(limit=request.limit)
    
    if not unprocessed:
        return {
            "processed": 0,
            "failed": 0,
            "processing_time_ms": 0,
            "message": "No unprocessed IOCs found in Data Lake"
        }
    
    def parse_dt(value: Any) -> Optional[datetime]:
        if not value:
            return None
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        try:
            text = str(value).strip()
            if not text:
                return None
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            parsed = datetime.fromisoformat(text)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except Exception:
            return None

    def to_iso_z(value: Optional[datetime]) -> Optional[str]:
        if value is None:
            return None
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    def pick_highest_severity(values: List[str]) -> str:
        severity_rank = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1,
            "clean": 0
        }
        best = "low"
        best_rank = -1
        for raw in values:
            sev = str(raw or "").strip().lower()
            rank = severity_rank.get(sev, -1)
            if rank > best_rank:
                best = sev
                best_rank = rank
        return best if best_rank >= 0 else "low"

    # Group by IOC key to preserve all source-level observations (MOM requirement)
    grouped_iocs: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for ioc in unprocessed:
        ioc_type = str(ioc.get("ioc_type", "unknown")).strip().lower()
        ioc_value = str(ioc.get("ioc_value", "")).strip()
        if not ioc_value:
            continue
        key = (ioc_type, ioc_value.lower())
        grouped_iocs.setdefault(key, []).append(ioc)

    processed = 0
    failed = 0
    processed_observations = 0

    for (_, _), ioc_docs in grouped_iocs.items():
        try:
            primary = ioc_docs[0]
            ioc_value = primary.get("ioc_value", "")
            ioc_type = primary.get("ioc_type", "unknown")

            source_names = []
            source_types = []
            descriptions = []
            tags = set()
            references = []
            threat_types_raw = []
            severity_values = []
            geo_countries = []
            first_seen_candidates: List[datetime] = []
            last_seen_candidates: List[datetime] = []

            for doc in ioc_docs:
                source_name = str(doc.get("source_name", "")).strip()
                if source_name and source_name not in source_names:
                    source_names.append(source_name)

                source_type = str(doc.get("source_type", "")).strip()
                if source_type and source_type not in source_types:
                    source_types.append(source_type)

                description = str(doc.get("description", "")).strip()
                if description and description not in descriptions:
                    descriptions.append(description)

                for tag in doc.get("tags", []) or []:
                    if tag:
                        tags.add(str(tag))

                reference = str(doc.get("reference", "")).strip()
                if reference and reference not in references:
                    references.append(reference)

                for threat in doc.get("threat_type", []) or []:
                    if threat:
                        threat_types_raw.append(str(threat))

                severity_values.append(str(doc.get("severity", "")).strip().lower())

                geo_country = str(doc.get("geo_country", "")).strip()
                if geo_country:
                    geo_countries.append(geo_country)

                event_dt = parse_dt(doc.get("event_time"))
                collect_dt = parse_dt(doc.get("collect_time"))
                if event_dt:
                    first_seen_candidates.append(event_dt)
                    last_seen_candidates.append(event_dt)
                if collect_dt:
                    first_seen_candidates.append(collect_dt)
                    last_seen_candidates.append(collect_dt)

            merged_description = "\n".join(descriptions) if descriptions else ""
            sources = source_names or ["unknown"]

            first_seen_dt = min(first_seen_candidates) if first_seen_candidates else None
            last_seen_dt = max(last_seen_candidates) if last_seen_candidates else None
            first_seen = to_iso_z(first_seen_dt) or primary.get("event_time")
            last_seen = to_iso_z(last_seen_dt) or primary.get("collect_time")

            ioc_age_days = None
            if first_seen_dt:
                ioc_age_days = max(
                    0,
                    (datetime.now(timezone.utc) - first_seen_dt.astimezone(timezone.utc)).days
                )
            
            # Run classification
            classification = classify_threat(merged_description)
            threat_actors = extract_threat_actors(merged_description)
            mitre_techniques = extract_mitre_techniques(merged_description)
            
            # Run scoring
            score_result = calculate_risk_score(
                ioc_value=ioc_value,
                ioc_type=ioc_type,
                description=merged_description,
                sources=sources,
                ioc_age_days=ioc_age_days,
                threat_classification={
                    "threat_types": classification["threat_types"],
                    "threat_actors": threat_actors,
                    "mitre_techniques": mitre_techniques,
                    "confidence": classification["confidence"]
                }
            )
            
            # Build warehouse document
            warehouse_doc = {
                "ioc_value": ioc_value,
                "ioc_type": ioc_type,
                "source_name": ", ".join(sources),
                "source_type": "multi" if len(source_types) > 1 else (source_types[0] if source_types else "unknown"),
                "sources": sources,
                "source_types": source_types,
                "source_count": len(sources),
                "description": merged_description,
                "threat_type": sorted(set(threat_types_raw)),
                "severity": pick_highest_severity(severity_values),
                "tags": sorted(tags),
                "reference": "\n".join(references),
                "collect_time": last_seen,
                "event_time": first_seen,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "ioc_age_days": ioc_age_days,
                "geo_country": geo_countries[0] if geo_countries else primary.get("geo_country"),
                # AI Enrichment
                "ai_risk_score": score_result.get("risk_score", 0),
                "ai_severity": score_result.get("severity", "low"),
                "ai_severity_th": score_result.get("severity_th", "ต่ำ"),
                "ai_threat_types": classification["threat_types"],
                "ai_threat_actors": threat_actors,
                "ai_mitre_techniques": mitre_techniques,
                "ai_classification_confidence": classification["confidence"],
                "ai_score_breakdown": score_result.get("breakdown", {}),
                "ai_top_factors": score_result.get("top_factors", []),
                "score_model_version": score_result.get("score_model_version"),
                "score_config_version": score_result.get("score_config_version"),
                "credibility_score": score_result.get("credibility_score", 0),
                "impact_score": score_result.get("impact_score", 0)
            }
            
            processed_doc = dict(warehouse_doc)
            processed_doc["validation_status"] = "validated"

            # Save to processed layer first (for validation/backup)
            processed_id = es_client.save_to_processed(processed_doc)
            if not processed_id:
                failed += 1
                continue

            # Save to warehouse
            saved_id = es_client.save_to_warehouse(warehouse_doc)
            
            if saved_id:
                # Mark all contributing observations as processed
                mark_failed = False
                for doc in ioc_docs:
                    doc_id = doc.get("_id")
                    if doc_id and not es_client.mark_as_processed(doc_id):
                        mark_failed = True
                        logger.warning(
                            "Failed marking datalake doc as processed: %s (%s)",
                            doc_id,
                            ioc_value
                        )
                if mark_failed:
                    failed += 1
                    continue
                processed += 1
                processed_observations += len(ioc_docs)
            else:
                failed += 1
                
        except Exception as e:
            logger.error(f"Pipeline error for {ioc_docs[0].get('ioc_value')}: {e}")
            failed += 1
    
    elapsed = int((time.time() - start) * 1000)
    
    return {
        "processed": processed,
        "failed": failed,
        "processing_time_ms": elapsed,
        "message": (
            f"Pipeline completed: {processed} aggregated IOCs processed, "
            f"{processed_observations} observations updated, {failed} failed"
        )
    }


@app.get("/pipeline/status", response_model=ElasticsearchStatusResponse)
async def pipeline_status(api_key: str = Depends(verify_api_key)):
    """Get Elasticsearch and pipeline status."""
    from elastic_client import get_elastic_client, DATALAKE_INDEX, PROCESSED_INDEX, WAREHOUSE_INDEX
    
    es_client = get_elastic_client()
    health = es_client.health_check()
    
    # Get document counts
    datalake_count = 0
    processed_count = 0
    warehouse_count = 0
    
    try:
        import httpx
        resp = httpx.get(f"{es_client.url}/{DATALAKE_INDEX}/_count", timeout=10)
        if resp.status_code == 200:
            datalake_count = resp.json().get("count", 0)

        resp = httpx.get(f"{es_client.url}/{PROCESSED_INDEX}/_count", timeout=10)
        if resp.status_code == 200:
            processed_count = resp.json().get("count", 0)
        
        resp = httpx.get(f"{es_client.url}/{WAREHOUSE_INDEX}/_count", timeout=10)
        if resp.status_code == 200:
            warehouse_count = resp.json().get("count", 0)
    except:
        pass
    
    return {
        "status": health.get("status", "unknown"),
        "datalake_index": DATALAKE_INDEX,
        "processed_index": PROCESSED_INDEX,
        "warehouse_index": WAREHOUSE_INDEX,
        "datalake_count": datalake_count,
        "processed_count": processed_count,
        "warehouse_count": warehouse_count
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
        if health.get("status") in ("green", "yellow"):
            logger.info("Elasticsearch connected successfully!")
            es_client.create_indexes()
            logger.info("Elasticsearch indexes ready!")
        else:
            logger.warning(f"Elasticsearch not available: {health}")
    except Exception as e:
        logger.warning(f"Could not connect to Elasticsearch: {e}")


if __name__ == "__main__":
    import uvicorn
    
    logger.info(f"Starting AI Service on {HOST}:{PORT}")
    uvicorn.run(app, host=HOST, port=PORT, reload=DEBUG)
