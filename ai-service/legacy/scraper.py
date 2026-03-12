"""
URL Content Scraper for IOC Enrichment

Fetches title, meta description, and main content from URLs
to enrich IOCs that have empty descriptions.
"""

import requests
from bs4 import BeautifulSoup
from typing import Dict, Optional
from urllib.parse import urlparse
import logging
import time
from functools import lru_cache

logger = logging.getLogger(__name__)

# Configuration
REQUEST_TIMEOUT = 5  # seconds
MIN_DESCRIPTION_LENGTH = 20
MAX_DESCRIPTION_LENGTH = 500
RATE_LIMIT_DELAY = 0.5  # seconds between requests to same domain

# Track last request time per domain
_last_request_time: Dict[str, float] = {}

# User agent to avoid blocks
HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; TCTI-Bot/1.0; +https://tcti.example.com)",
    "Accept": "text/html,application/xhtml+xml",
    "Accept-Language": "en-US,en;q=0.9,th;q=0.8"
}


def _get_domain(url: str) -> str:
    """Extract domain from URL for rate limiting."""
    try:
        parsed = urlparse(url)
        return parsed.netloc
    except Exception:
        return ""


def _respect_rate_limit(domain: str) -> None:
    """Wait if we've recently hit this domain."""
    global _last_request_time
    
    if domain in _last_request_time:
        elapsed = time.time() - _last_request_time[domain]
        if elapsed < RATE_LIMIT_DELAY:
            time.sleep(RATE_LIMIT_DELAY - elapsed)
    
    _last_request_time[domain] = time.time()


def _clean_text(text: str) -> str:
    """Clean and normalize extracted text."""
    if not text:
        return ""
    
    # Remove excessive whitespace
    text = " ".join(text.split())
    
    # Truncate if too long
    if len(text) > MAX_DESCRIPTION_LENGTH:
        text = text[:MAX_DESCRIPTION_LENGTH].rsplit(" ", 1)[0] + "..."
    
    return text.strip()


@lru_cache(maxsize=1000)
def scrape_content(url: str) -> Dict[str, Optional[str]]:
    """
    Scrape content from a URL for IOC enrichment.
    
    Args:
        url: The URL to scrape
        
    Returns:
        Dict with:
            - title: Page title
            - description: Meta description or first paragraph
            - success: Whether scraping succeeded
            - error: Error message if failed
    """
    result = {
        "title": None,
        "description": None,
        "success": False,
        "error": None,
        "scraped": True
    }
    
    if not url or not url.startswith(("http://", "https://")):
        result["error"] = "Invalid URL"
        return result
    
    domain = _get_domain(url)
    
    try:
        # Respect rate limiting
        _respect_rate_limit(domain)
        
        # Fetch the page
        response = requests.get(
            url,
            headers=HEADERS,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True
        )
        response.raise_for_status()
        
        # Parse HTML
        soup = BeautifulSoup(response.text, "html.parser")
        
        # Extract title
        title_tag = soup.find("title")
        if title_tag:
            result["title"] = _clean_text(title_tag.get_text())
        
        # Try to get meta description
        meta_desc = soup.find("meta", attrs={"name": "description"})
        if meta_desc and meta_desc.get("content"):
            result["description"] = _clean_text(meta_desc["content"])
        
        # Fallback: try og:description
        if not result["description"]:
            og_desc = soup.find("meta", attrs={"property": "og:description"})
            if og_desc and og_desc.get("content"):
                result["description"] = _clean_text(og_desc["content"])
        
        # Fallback: try first H1 + first paragraph
        if not result["description"]:
            h1 = soup.find("h1")
            first_p = soup.find("p")
            
            parts = []
            if h1:
                parts.append(_clean_text(h1.get_text()))
            if first_p:
                parts.append(_clean_text(first_p.get_text()))
            
            if parts:
                result["description"] = " - ".join(parts)
        
        # If we got something useful, mark success
        if result["description"] and len(result["description"]) >= MIN_DESCRIPTION_LENGTH:
            result["success"] = True
            logger.info(f"Scraped content from {domain}: {len(result['description'])} chars")
        else:
            result["error"] = "No meaningful content found"
            
    except requests.exceptions.Timeout:
        result["error"] = "Request timed out"
        logger.warning(f"Timeout scraping {url}")
        
    except requests.exceptions.HTTPError as e:
        result["error"] = f"HTTP error: {e.response.status_code}"
        logger.warning(f"HTTP error {e.response.status_code} for {url}")
        
    except requests.exceptions.RequestException as e:
        result["error"] = f"Request failed: {str(e)}"
        logger.warning(f"Request failed for {url}: {e}")
        
    except Exception as e:
        result["error"] = f"Parse error: {str(e)}"
        logger.error(f"Error parsing {url}: {e}")
    
    return result


def enrich_description(
    existing_description: Optional[str],
    source_url: Optional[str]
) -> Dict[str, Optional[str]]:
    """
    Enrich IOC description if needed.
    
    Args:
        existing_description: Current description (may be empty)
        source_url: URL to scrape if description is empty
        
    Returns:
        Dict with:
            - description: Enriched or original description
            - scraped: Whether we scraped new content
            - scrape_error: Any error during scraping
    """
    result = {
        "description": existing_description or "",
        "scraped": False,
        "scrape_error": None
    }
    
    # Check if we already have a good description
    if existing_description and len(existing_description.strip()) >= MIN_DESCRIPTION_LENGTH:
        return result
    
    # Need to scrape
    if source_url:
        scraped = scrape_content(source_url)
        
        if scraped["success"] and scraped["description"]:
            # Build enriched description
            parts = []
            if scraped["title"]:
                parts.append(scraped["title"])
            parts.append(scraped["description"])
            
            result["description"] = " - ".join(parts)
            result["scraped"] = True
            
        elif scraped["error"]:
            result["scrape_error"] = scraped["error"]
    
    return result


# For testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    test_urls = [
        "https://thehackernews.com/2024/01/critical-vulnerability.html",
        "https://www.bleepingcomputer.com/news/security/ransomware-attack.html",
        "https://invalid-url-that-does-not-exist.com"
    ]
    
    for url in test_urls:
        print(f"\nURL: {url[:50]}...")
        result = scrape_content(url)
        print(f"Success: {result['success']}")
        print(f"Title: {result['title'][:50] if result['title'] else 'N/A'}...")
        print(f"Description: {result['description'][:100] if result['description'] else 'N/A'}...")
        if result['error']:
            print(f"Error: {result['error']}")
