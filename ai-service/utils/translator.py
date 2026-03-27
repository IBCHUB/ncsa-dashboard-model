"""
AI-powered Translation Module using OpenAI GPT

Provides context-aware translation for cybersecurity threat intelligence content.
Optimized for technical terms and Thai language output.
"""

import hashlib
import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# OpenAI API Key - can be set via environment variable or .env file
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

# Translation settings
DEFAULT_MODEL = "gpt-4o-mini"  # Cost-effective model for translation
MAX_TEXT_LENGTH = 4000  # Max characters per translation request


def get_openai_client():
    """Get OpenAI client, lazy initialization."""
    try:
        from openai import OpenAI
        api_key = OPENAI_API_KEY
        if not api_key:
            logger.warning("OPENAI_API_KEY not set, translation will return original text")
            return None
        return OpenAI(api_key=api_key)
    except ImportError:
        logger.error("openai package not installed")
        return None
    except Exception as e:
        logger.error(f"Failed to initialize OpenAI client: {e}")
        return None


# Cache to avoid re-translating same content (capped to prevent unbounded memory growth)
_CACHE_MAX_SIZE = 1000
_translation_cache: dict[str, str] = {}


def translate_content(
    text: str,
    target_lang: str = "th",
    context: str = "cybersecurity threat intelligence"
) -> str:
    """
    Translate text using OpenAI GPT with cybersecurity context.
    
    Args:
        text: Text to translate
        target_lang: Target language code ('th' for Thai, 'en' for English)
        context: Domain context for better translation
        
    Returns:
        Translated text, or original text if translation fails
    """
    # Skip empty or very short text
    if not text or len(text.strip()) < 5:
        return text
    
    # Truncate very long text (work on a local copy to avoid mutating the caller's string key)
    if len(text) > MAX_TEXT_LENGTH:
        text = text[:MAX_TEXT_LENGTH] + "..."

    # Check cache first (deterministic SHA-256 key, safe across workers/restarts)
    cache_key = f"{target_lang}:{hashlib.sha256(text.encode()).hexdigest()[:32]}"
    if cache_key in _translation_cache:
        return _translation_cache[cache_key]
    
    # Get OpenAI client
    client = get_openai_client()
    if client is None:
        return text
    
    # Language mapping
    lang_names = {
        "th": "Thai (ภาษาไทย)",
        "en": "English",
        "ja": "Japanese",
        "zh": "Chinese (Simplified)"
    }
    target_lang_name = lang_names.get(target_lang, target_lang)
    
    # System prompt for cybersecurity translation
    system_prompt = f"""You are a professional translator specializing in {context}.
Translate the given text to {target_lang_name}.

Important guidelines:
1. Keep technical terms accurate (e.g., "lateral movement" → "การแพร่กระจายในเครือข่าย")
2. Preserve meaning of security concepts (APT, C2, ransomware, etc.)
3. Use formal but readable language
4. Keep acronyms as-is when commonly used (e.g., IOC, APT, CVE)
5. If the text is already in the target language, return it as-is
6. Return ONLY the translated text, no explanations"""
    
    try:
        response = client.chat.completions.create(
            model=DEFAULT_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": text}
            ],
            temperature=0.3,  # Low temperature for consistent translation
            max_tokens=2000
        )
        
        translated = response.choices[0].message.content.strip()
        
        # Cache the result (evict oldest entry if at capacity)
        if len(_translation_cache) >= _CACHE_MAX_SIZE:
            _translation_cache.pop(next(iter(_translation_cache)))
        _translation_cache[cache_key] = translated
        
        logger.debug(f"Translated text ({len(text)} chars) to {target_lang}")
        return translated
        
    except Exception as e:
        logger.error(f"Translation failed: {e}")
        return text


