"""
NLP Threat Classifier using Zero-shot Classification

Uses facebook/bart-large-mnli for classifying threat descriptions
into predefined categories without requiring training data.
"""

from typing import List, Dict, Optional, Tuple
import logging

from transformers import pipeline
import torch

from config import THREAT_CATEGORIES, DEVICE, CLASSIFIER_MODEL

logger = logging.getLogger(__name__)

# Global classifier instance (lazy loaded)
_classifier = None


def get_classifier():
    """Get or create the zero-shot classifier (singleton pattern)"""
    global _classifier
    
    if _classifier is None:
        logger.info(f"Loading classifier model: {CLASSIFIER_MODEL}")
        logger.info(f"Using device: {DEVICE}")
        
        _classifier = pipeline(
            "zero-shot-classification",
            model=CLASSIFIER_MODEL,
            device=0 if DEVICE == "cuda" and torch.cuda.is_available() else -1
        )
        
        logger.info("Classifier loaded successfully")
    
    return _classifier


def classify_threat(
    text: str,
    candidate_labels: Optional[List[str]] = None,
    multi_label: bool = True,
    threshold: float = 0.3
) -> Dict:
    """
    Classify threat description into categories.
    
    Args:
        text: The description/title to classify
        candidate_labels: Categories to classify into (default: THREAT_CATEGORIES)
        multi_label: Allow multiple labels (default: True)
        threshold: Minimum confidence threshold (default: 0.3)
    
    Returns:
        Dict with labels and scores
    """
    if not text or len(text.strip()) < 10:
        return {
            "labels": [],
            "scores": [],
            "threat_types": [],
            "confidence": 0.0
        }
    
    labels = candidate_labels or THREAT_CATEGORIES
    classifier = get_classifier()
    
    try:
        result = classifier(
            text,
            candidate_labels=labels,
            multi_label=multi_label
        )
        
        # Filter by threshold
        filtered_labels = []
        filtered_scores = []
        
        for label, score in zip(result["labels"], result["scores"]):
            if score >= threshold:
                filtered_labels.append(label)
                filtered_scores.append(round(score, 3))
        
        # Get top confidence
        top_confidence = filtered_scores[0] if filtered_scores else 0.0
        
        return {
            "labels": result["labels"],  # All labels sorted by score
            "scores": [round(s, 3) for s in result["scores"]],
            "threat_types": filtered_labels,  # Only above threshold
            "confidence": round(top_confidence, 3)
        }
        
    except Exception as e:
        logger.error(f"Classification error: {e}")
        return {
            "labels": [],
            "scores": [],
            "threat_types": [],
            "confidence": 0.0,
            "error": str(e)
        }


def classify_batch(
    texts: List[str],
    threshold: float = 0.3,
    batch_size: int = 16
) -> List[Dict]:
    """
    Classify multiple texts in batch using true parallel processing.
    
    Args:
        texts: List of descriptions to classify
        threshold: Minimum confidence threshold
        batch_size: Number of texts to process in parallel (default: 16)
    
    Returns:
        List of classification results
    """
    if not texts:
        return []
    
    # Filter out empty/short texts and track their indices
    valid_texts = []
    valid_indices = []
    results = [None] * len(texts)
    
    empty_result = {
        "labels": [],
        "scores": [],
        "threat_types": [],
        "confidence": 0.0
    }
    
    for i, text in enumerate(texts):
        if text and len(text.strip()) >= 10:
            valid_texts.append(text)
            valid_indices.append(i)
        else:
            results[i] = empty_result.copy()
    
    if not valid_texts:
        return results
    
    # Get classifier and run batch inference
    classifier = get_classifier()
    labels = THREAT_CATEGORIES
    
    try:
        # Use pipeline's native batch processing
        batch_results = classifier(
            valid_texts,
            candidate_labels=labels,
            multi_label=True,
            batch_size=batch_size
        )
        
        # Handle single result (pipeline returns dict instead of list for single input)
        if isinstance(batch_results, dict):
            batch_results = [batch_results]
        
        # Process results and apply threshold
        for idx, result in zip(valid_indices, batch_results):
            filtered_labels = []
            filtered_scores = []
            
            for label, score in zip(result["labels"], result["scores"]):
                if score >= threshold:
                    filtered_labels.append(label)
                    filtered_scores.append(round(score, 3))
            
            top_confidence = filtered_scores[0] if filtered_scores else 0.0
            
            results[idx] = {
                "labels": result["labels"],
                "scores": [round(s, 3) for s in result["scores"]],
                "threat_types": filtered_labels,
                "confidence": round(top_confidence, 3)
            }
        
        logger.info(f"Batch classified {len(valid_texts)} texts successfully")
        return results
        
    except Exception as e:
        logger.error(f"Batch classification error: {e}")
        # Fallback to sequential processing
        logger.info("Falling back to sequential processing...")
        for i, text in zip(valid_indices, valid_texts):
            results[i] = classify_threat(text, threshold=threshold)
        return results


def _load_threat_actors_config() -> dict:
    """Load threat actors from external JSON config (cached)."""
    import json
    from pathlib import Path
    
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


# Cache loaded config
_threat_actors_cache = None


def get_threat_actors_config() -> list:
    """Get threat actors config with caching."""
    global _threat_actors_cache
    
    if _threat_actors_cache is None:
        config = _load_threat_actors_config()
        _threat_actors_cache = config.get("threat_actors", [])
    
    return _threat_actors_cache


def extract_threat_actors(text: str) -> List[str]:
    """
    Extract known threat actor names from text.
    
    Loads actors from config/threat_actors.json for dynamic updates.
    Matches both primary names and aliases.
    """
    if not text:
        return []
    
    actors_config = get_threat_actors_config()
    found_actors = []
    text_lower = text.lower()
    
    for actor in actors_config:
        name = actor.get("name", "")
        aliases = actor.get("aliases", [])
        
        # Check primary name
        if name.lower() in text_lower:
            if name not in found_actors:
                found_actors.append(name)
            continue
        
        # Check aliases
        for alias in aliases:
            if alias.lower() in text_lower:
                if name not in found_actors:
                    found_actors.append(name)
                break
    
    return found_actors


def extract_mitre_techniques(text: str) -> List[str]:
    """
    Extract MITRE ATT&CK technique IDs from text.
    """
    import re
    
    # Match patterns like T1059, T1059.001
    pattern = r'\bT\d{4}(?:\.\d{3})?\b'
    matches = re.findall(pattern, text, re.IGNORECASE)
    
    return [m.upper() for m in matches]


# For testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    test_texts = [
        "Ransomware attack encrypts files and demands Bitcoin payment",
        "Phishing campaign targets Thai government employees",
        "New zero-day vulnerability in Microsoft Exchange Server"
    ]
    
    for text in test_texts:
        print(f"\nText: {text[:50]}...")
        result = classify_threat(text)
        print(f"Threat Types: {result['threat_types']}")
        print(f"Confidence: {result['confidence']}")
