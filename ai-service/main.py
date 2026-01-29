"""
AI Service API

FastAPI server for threat classification and risk scoring.
"""

from typing import List, Optional
import logging
import time

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
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001", "*"],
    allow_credentials=True,
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


class ScoreResponse(BaseModel):
    risk_score: int
    severity: str
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
    ai_severity: str
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
            domain_age_days=request.domain_age_days
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
            "ai_severity": score_result["severity"],
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
                "ai_severity": "unknown",
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
    
    processed = 0
    failed = 0
    
    for ioc in unprocessed:
        try:
            ioc_value = ioc.get("ioc_value", "")
            ioc_type = ioc.get("ioc_type", "unknown")
            description = ioc.get("description", "")
            sources = [ioc.get("source_name", "unknown")]
            
            # Run classification
            classification = classify_threat(description)
            threat_actors = extract_threat_actors(description)
            mitre_techniques = extract_mitre_techniques(description)
            
            # Run scoring
            score_result = calculate_risk_score(
                ioc_value=ioc_value,
                ioc_type=ioc_type,
                description=description,
                sources=sources,
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
                "source_name": ioc.get("source_name"),
                "source_type": ioc.get("source_type"),
                "sources": sources,
                "description": description,
                "threat_type": ioc.get("threat_type", []),
                "severity": ioc.get("severity"),
                "tags": ioc.get("tags", []),
                "reference": ioc.get("reference"),
                "collect_time": ioc.get("collect_time"),
                "event_time": ioc.get("event_time"),
                "first_seen": ioc.get("event_time"),
                "last_seen": ioc.get("collect_time"),
                "geo_country": ioc.get("geo_country"),
                # AI Enrichment
                "ai_risk_score": score_result.get("total_score", 0),
                "ai_severity": score_result.get("severity", "low"),
                "ai_severity_th": score_result.get("severity_th", "ต่ำ"),
                "ai_threat_types": classification["threat_types"],
                "ai_threat_actors": threat_actors,
                "ai_mitre_techniques": mitre_techniques,
                "ai_classification_confidence": classification["confidence"],
                "ai_score_breakdown": score_result.get("breakdown", {}),
                "ai_top_factors": score_result.get("top_factors", [])
            }
            
            # Save to warehouse
            saved_id = es_client.save_to_warehouse(warehouse_doc)
            
            if saved_id:
                # Mark as processed in Data Lake
                es_client.mark_as_processed(ioc.get("_id"))
                processed += 1
            else:
                failed += 1
                
        except Exception as e:
            logger.error(f"Pipeline error for {ioc.get('ioc_value')}: {e}")
            failed += 1
    
    elapsed = int((time.time() - start) * 1000)
    
    return {
        "processed": processed,
        "failed": failed,
        "processing_time_ms": elapsed,
        "message": f"Pipeline completed: {processed} processed, {failed} failed"
    }


@app.get("/pipeline/status", response_model=ElasticsearchStatusResponse)
async def pipeline_status(api_key: str = Depends(verify_api_key)):
    """Get Elasticsearch and pipeline status."""
    from elastic_client import get_elastic_client, DATALAKE_INDEX, WAREHOUSE_INDEX
    
    es_client = get_elastic_client()
    health = es_client.health_check()
    
    # Get document counts
    datalake_count = 0
    warehouse_count = 0
    
    try:
        import httpx
        resp = httpx.get(f"{es_client.url}/{DATALAKE_INDEX}/_count", timeout=10)
        if resp.status_code == 200:
            datalake_count = resp.json().get("count", 0)
        
        resp = httpx.get(f"{es_client.url}/{WAREHOUSE_INDEX}/_count", timeout=10)
        if resp.status_code == 200:
            warehouse_count = resp.json().get("count", 0)
    except:
        pass
    
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


