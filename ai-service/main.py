"""
AI Service API

FastAPI server for threat classification and risk scoring.
"""

from typing import Dict, List, Optional, Tuple
import logging
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
from utils.pipeline_documents import build_enriched_ioc_document
from utils.sanitizer import sanitize_text

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

# CORS middleware
cors_origin_setting = os.getenv("AI_SERVICE_CORS_ORIGINS", "*").strip()
if cors_origin_setting == "*" or not cors_origin_setting:
    cors_origins = ["*"]
else:
    cors_origins = [
        origin.strip()
        for origin in cors_origin_setting.split(",")
        if origin.strip()
    ]
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
        result = classify_threat(sanitized_text, threshold=request.threshold)
        actors = extract_threat_actors(sanitized_text)
        mitre = extract_mitre_techniques(sanitized_text)
        
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

        sanitized_description = sanitize_text(request.description)["text"]
        result = calculate_risk_score(
            ioc_value=request.ioc_value,
            ioc_type=request.ioc_type,
            description=sanitized_description,
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
        full_text = sanitize_text(f"{request.title} {request.description}".strip())["text"]
        
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
# AI PIPELINE ENDPOINTS (Data Lake → AI → Data Warehouse)
# ============================================

class PipelineRunRequest(BaseModel):
    limit: int = Field(default=100, description="Maximum IOCs to process per run")


class PipelineRunResponse(BaseModel):
    processed: int
    rejected: int
    failed: int
    observations_updated: int
    processing_time_ms: int
    message: str


class ElasticsearchStatusResponse(BaseModel):
    status: str
    datalake_index: str
    warehouse_index: str
    datalake_count: int
    warehouse_count: int



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
            "rejected": 0,
            "failed": 0,
            "observations_updated": 0,
            "processing_time_ms": 0,
            "message": "No unprocessed IOCs found in Data Lake"
        }

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
    rejected = 0
    failed = 0
    processed_observations = 0

    for (_, _), ioc_docs in grouped_iocs.items():
        try:
            build_result = build_enriched_ioc_document(ioc_docs)
            pipeline_doc = build_result["document"]
            validation_status = pipeline_doc["validation_status"]
            ioc_value = pipeline_doc["ioc_value"]

            saved_id = es_client.save_to_warehouse(dict(pipeline_doc))
            if not saved_id:
                logger.warning("Failed to save to warehouse for %s", ioc_value)
                failed += 1
                continue

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

            if pipeline_doc["warehouse_eligible"]:
                processed += 1
            elif validation_status == REJECTED:
                rejected += 1
            processed_observations += len(ioc_docs)
                
        except Exception as e:
            logger.error(f"Pipeline error for {ioc_docs[0].get('ioc_value')}: {e}")
            failed += 1
    
    elapsed = int((time.time() - start) * 1000)
    
    return {
        "processed": processed,
        "rejected": rejected,
        "failed": failed,
        "observations_updated": processed_observations,
        "processing_time_ms": elapsed,
        "message": (
            f"Pipeline completed: {processed} auto-validated to warehouse, "
            f"{rejected} rejected, "
            f"{processed_observations} observations updated, {failed} failed"
        )
    }



@app.get("/pipeline/status", response_model=ElasticsearchStatusResponse)
async def pipeline_status(api_key: str = Depends(verify_api_key)):
    """Get Elasticsearch and pipeline status."""
    from elastic_client import get_elastic_client, DATALAKE_INDEX, WAREHOUSE_INDEX
    
    es_client = get_elastic_client()
    health = es_client.health_check()
    
    # Get document counts
    datalake_count = es_client.count_documents(DATALAKE_INDEX)
    warehouse_count = es_client.count_documents(WAREHOUSE_INDEX)
    
    return {
        "status": health.get("status", "unknown"),
        "datalake_index": DATALAKE_INDEX,
        "warehouse_index": WAREHOUSE_INDEX,
        "datalake_count": datalake_count,
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


if __name__ == "__main__":
    import uvicorn
    
    logger.info(f"Starting AI Service on {HOST}:{PORT}")
    uvicorn.run(app, host=HOST, port=PORT, reload=DEBUG)
