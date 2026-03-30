"""
AI-powered Translation Module using Hugging Face (Local Offline)

Provides local translation for cybersecurity threat intelligence content.
Optimized for English to Thai using Helsinki-NLP/opus-mt-en-th.
"""

import hashlib
import os
import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)

# Device setup
DEVICE = os.getenv("DEVICE", "cpu")
_device_id = -1
if DEVICE == "cuda":
    try:
        import torch
        if torch.cuda.is_available():
            _device_id = 0
        else:
            DEVICE = "cpu"
    except ImportError:
        DEVICE = "cpu"

# Translation settings
DEFAULT_MODEL = "Helsinki-NLP/opus-mt-en-th"
MAX_TEXT_LENGTH = 1000  # Max characters per translation request (local models usually have lower context)

# Cache to avoid re-translating same content (capped to prevent unbounded memory growth)
_CACHE_MAX_SIZE = 1000
_translation_cache: dict[str, str] = {}

# Lazy loaded pipeline
_translator_pipeline = None
_model_failed = False

def get_translator():
    """Get Hugging Face pipeline, lazy initialization."""
    global _translator_pipeline, _model_failed
    if _translator_pipeline is not None:
        return _translator_pipeline
    
    if _model_failed:
        # Don't keep trying if it failed the first time (saves time per request)
        return None
        
    try:
        from transformers import pipeline
        logger.info(f"Loading translation model {DEFAULT_MODEL} on device {DEVICE}...")
        _translator_pipeline = pipeline("translation", model=DEFAULT_MODEL, device=_device_id)
        logger.info("Translation model loaded successfully")
        return _translator_pipeline
    except ImportError:
        logger.error("transformers package not installed")
        _model_failed = True
        return None
    except Exception as e:
        logger.error(f"Failed to initialize translation pipeline: {e}")
        _model_failed = True
        return None


def is_mostly_thai(text: str) -> bool:
    """Heuristic to check if text is already mostly Thai."""
    thai_chars = len(re.findall(r'[\u0E00-\u0E7F]', text))
    if len(text) == 0:
        return False
    return (thai_chars / len(text)) > 0.3


def translate_content(
    text: str,
    target_lang: str = "th",
    context: str = "cybersecurity threat intelligence"
) -> str:
    """
    Translate text using local Hugging Face model with cybersecurity context in mind.
    
    Args:
        text: Text to translate
        target_lang: Target language code ('th' for Thai). Only 'th' is supported.
        context: Deprecated context arg for local model backward compatibility.
        
    Returns:
        Translated text, or original text if translation fails
    """
    # Skip empty or very short text
    if not text or len(text.strip()) < 5:
        return text
    
    # We only have en-th model downloaded. Skip non-Thai target.
    if target_lang != "th":
        return text
        
    # If it's already Thai, we shouldn't pass it to opus-mt-en-th
    if is_mostly_thai(text):
        return text
    
    # Truncate very long text (work on a local copy to avoid mutating the caller's string key)
    # Most local translation models expect < 512 tokens.
    if len(text) > MAX_TEXT_LENGTH:
        text = text[:MAX_TEXT_LENGTH] + "..."

    # Check cache first (deterministic SHA-256 key, safe across workers/restarts)
    cache_key = f"{target_lang}:{hashlib.sha256(text.encode()).hexdigest()[:32]}"
    if cache_key in _translation_cache:
        return _translation_cache[cache_key]
    
    translator = get_translator()
    if translator is None:
        return text
    
    try:
        # Using the pipeline directly on string text
        # Clean up some formatting that confuses local models:
        clean_text = text.replace("\n", " ").strip()
        
        result = translator(clean_text, max_length=512, truncation=True)
        translated = result[0]["translation_text"].strip()
        
        # Basic post-processing heuristics to fix common translation artefacts
        if len(translated) == 0 or len(translated) > len(text) * 3:
            # Model hallucinated
            return text
            
        # Cache the result (evict oldest entry if at capacity)
        if len(_translation_cache) >= _CACHE_MAX_SIZE:
            _translation_cache.pop(next(iter(_translation_cache)))
        _translation_cache[cache_key] = translated
        
        logger.debug(f"Translated text ({len(text)} chars) to {target_lang}")
        return translated
        
    except Exception as e:
        logger.error(f"Translation failed: {e}")
        return text
