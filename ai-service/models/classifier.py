"""
NLP Threat Classifier using Hybrid Pipeline (English + Multilingual)

1. Language Detection: lingua-language-detector
2. English Model: DeBERTa-v3-large
3. Multilingual Model: BGE-M3

Configurable via `ai-service/config.py`.
"""

from typing import List, Dict, Optional
import logging
import torch
from transformers import pipeline
from lingua import Language, LanguageDetectorBuilder

from config import (
    MODEL_EN,
    MODEL_MULTI,
    DEVICE,
    THREAT_LABELS,
    LABEL_MAPPING,
    MITRE_TACTICS,
    SECTOR_LABELS,
    SECTOR_LABEL_MAPPING,
    SECTOR_CONFIDENCE_THRESHOLD,
    MAX_CLASSIFIER_INPUT_CHARS,
)

logger = logging.getLogger(__name__)

# Global instances (lazy loaded)
_detector = None
_en_classifier = None
_multi_classifier = None


def models_loaded() -> bool:
    """Return whether either runtime classifier has been initialized."""
    return _en_classifier is not None or _multi_classifier is not None


def get_detector():
    """Get or create Language Detector (singleton)"""
    global _detector
    if _detector is None:
        logger.info("Loading Language Detector (Lingua)...")
        # Load all languages as requested
        _detector = LanguageDetectorBuilder.from_all_languages().build()
        logger.info("Language Detector loaded.")
    return _detector


def get_en_classifier():
    """Get or create English Classifier (singleton)"""
    global _en_classifier
    if _en_classifier is None:
        logger.info(f"Loading English Classifier: {MODEL_EN}")
        _en_classifier = pipeline(
            "zero-shot-classification",
            model=MODEL_EN,
            device=0 if DEVICE == "cuda" and torch.cuda.is_available() else -1
        )
    return _en_classifier


def get_multi_classifier():
    """Get or create Multilingual Classifier (singleton)"""
    global _multi_classifier
    if _multi_classifier is None:
        logger.info(f"Loading Multilingual Classifier: {MODEL_MULTI}")
        _multi_classifier = pipeline(
            "zero-shot-classification",
            model=MODEL_MULTI,
            device=0 if DEVICE == "cuda" and torch.cuda.is_available() else -1
        )
    return _multi_classifier


def classify_threat(
    text: str,
    candidate_labels: Optional[List[str]] = None,
    multi_label: bool = True,
    threshold: float = 0.3
) -> Dict:
    """
    Classify threat description using Hybrid Pipeline.
    
    1. Detect Language
    2. Route to appropriate model (EN vs Multi)
    3. Return standardized results (mapped to Title Case)
    """
    if not text or len(text.strip()) < 5:
        return {
            "labels": [],
            "scores": [],
            "threat_types": [],
            "confidence": 0.0,
            "language": "unknown",
            "sector_classifications": [],
        }

    text = text.strip()
    if MAX_CLASSIFIER_INPUT_CHARS > 0 and len(text) > MAX_CLASSIFIER_INPUT_CHARS:
        logger.info(
            "Truncating classifier input from %s to %s chars",
            len(text),
            MAX_CLASSIFIER_INPUT_CHARS,
        )
        text = text[:MAX_CLASSIFIER_INPUT_CHARS]

    # Use configured labels if not provided
    threat_labels = candidate_labels or THREAT_LABELS

    # When using default labels, add sector labels for combined inference
    include_sectors = candidate_labels is None
    all_labels = threat_labels + SECTOR_LABELS if include_sectors else threat_labels

    try:
        # 1. Language Detection
        detector = get_detector()
        detected_lang = detector.detect_language_of(text)

        # 2. Model Selection
        if detected_lang == Language.ENGLISH:
            classifier = get_en_classifier()
            lang_code = "en"
        else:
            classifier = get_multi_classifier()
            lang_code = str(detected_lang.iso_code_639_1).lower().split('.')[-1]

        # 3. Single inference pass (threat + sector labels together)
        result = classifier(
            text,
            candidate_labels=all_labels,
            multi_label=multi_label
        )

        # 4. Partition results into threat vs sector
        threat_mapped = []
        threat_scores_all = []
        filtered_labels = []
        filtered_scores = []
        sector_classifications = []

        for label, score in zip(result["labels"], result["scores"]):
            if include_sectors and label in SECTOR_LABEL_MAPPING:
                # Sector label → collect separately
                if score >= SECTOR_CONFIDENCE_THRESHOLD:
                    sector_classifications.append({
                        "sector": SECTOR_LABEL_MAPPING[label],
                        "confidence": round(score, 3),
                        "label": label,
                    })
            else:
                # Threat label → existing logic
                mapped_label = LABEL_MAPPING.get(label, label.title())
                threat_mapped.append(mapped_label)
                threat_scores_all.append(round(score, 3))
                if score >= threshold:
                    filtered_labels.append(mapped_label)
                    filtered_scores.append(round(score, 3))

        # Sort sectors by confidence descending
        sector_classifications.sort(key=lambda s: s["confidence"], reverse=True)

        top_confidence = filtered_scores[0] if filtered_scores else 0.0

        return {
            "labels": threat_mapped,
            "scores": threat_scores_all,
            "threat_types": filtered_labels,
            "threat_details": [
                {"type": l, "confidence": s}
                for l, s in zip(filtered_labels, filtered_scores)
            ],
            "confidence": round(top_confidence, 3),
            "language": lang_code,
            "model_used": "english" if detected_lang == Language.ENGLISH else "multilingual",
            "sector_classifications": sector_classifications,
        }

    except Exception as e:
        logger.error(f"Classification error: {e}")
        return {
            "labels": [],
            "scores": [],
            "threat_types": [],
            "confidence": 0.0,
            "error": "Classification failed. See server logs for details.",
            "sector_classifications": [],
        }


def _load_threat_actors_config() -> dict:
    """Load threat actors from external JSON config (cached)."""
    import json
    from pathlib import Path
    
    # Resolve path relative to this file
    config_path = Path(__file__).parent.parent / "config" / "threat_actors.json"
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        logger.warning(f"Threat actors config not found: {config_path}")
        return {"threat_actors": []}
    except Exception as e:
        logger.error(f"Error loading threat actors config: {e}")
        return {"threat_actors": []}


_threat_actors_cache = None


def get_threat_actors_config() -> list:
    """Get threat actors config with caching."""
    global _threat_actors_cache
    if _threat_actors_cache is None:
        config = _load_threat_actors_config()
        _threat_actors_cache = config.get("threat_actors", [])
    return _threat_actors_cache


def extract_threat_actors(text: str) -> List[str]:
    """Extract known threat actor names from text."""
    if not text:
        return []
    
    actors_config = get_threat_actors_config()
    found_actors = []
    text_lower = text.lower()
    
    for actor in actors_config:
        name = actor.get("name", "")
        aliases = actor.get("aliases", [])
        
        if name.lower() in text_lower:
            if name not in found_actors:
                found_actors.append(name)
            continue
        
        for alias in aliases:
            if alias.lower() in text_lower:
                if name not in found_actors:
                    found_actors.append(name)
                break
    
    return found_actors


def extract_mitre_techniques(text: str) -> List[str]:
    """Extract MITRE ATT&CK references from text."""
    import re
    if not text:
        return []

    found: List[str] = []
    text_lower = text.lower()

    # Match patterns like T1059, T1059.001
    pattern = r'\bT\d{4}(?:\.\d{3})?\b'
    matches = re.findall(pattern, text, re.IGNORECASE)
    for match in matches:
        upper = match.upper()
        if upper not in found:
            found.append(upper)

    # Match tactic names from config
    for tactic_name, tactic_info in MITRE_TACTICS.items():
        tactic_lower = tactic_name.lower()
        tactic_id = tactic_info.get("id", "")
        if tactic_lower in text_lower or tactic_id.lower() in text_lower:
            label = f"{tactic_id} ({tactic_name})" if tactic_id else tactic_name
            if label not in found:
                found.append(label)

    return found


if __name__ == "__main__":
    # Simple test
    logging.basicConfig(level=logging.INFO)
    
    test_texts = [
        "Ransomware attack encrypts files and demands Bitcoin payment",
        "มีการตรวจพบมัลแวร์ดูดข้อมูลลูกค้าธนาคาร",
        "New zero-day exploit found in iOS"
    ]
    
    for text in test_texts:
        print(f"\nText: {text}")
        res = classify_threat(text)
        print(f"Lang: {res.get('language')} | Model: {res.get('model_used')}")
        print(f"Types: {res['threat_types']}")
