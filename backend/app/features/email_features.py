import re
from backend.app.utils.url_utils import _normalize_url

def extract_urls(text: str) -> list[str]:
    """
    Extracts URLs from text. 
    If HTML is detected, focuses on href attributes.
    Excludes non-clickable metadata like W3C DTDs.
    """
    # 1. Try to find href matches first (standard for HTML emails)
    href_pattern = r'href=["\'](https?://[^"\']+)["\']'
    href_matches = re.findall(href_pattern, text, re.IGNORECASE)
    
    # 2. Fallback to generic URL extraction for plain text parts
    # but ensure we don't pick up DOCTYPE system IDs
    generic_pattern = r'(https?://[^\s"<>()]+)'
    generic_matches = re.findall(generic_pattern, text)
    
    # Merge and prioritize href matches, but include generic matches for completeness
    raw_urls = href_matches + generic_matches
    
    # 3. Filter out unwanted technical patterns
    blocked_patterns = {
        'w3.org/TR/', 
        'schema.org', 
        'w3.org/1999/xhtml',
        '.dtd'
    }
    
    cleaned_urls = []
    trailing_punct = '.,);]}'
    
    for url in raw_urls:
        # Skip technical boilerplate
        if any(p in url for p in blocked_patterns):
            continue
            
        # Strip trailing punctuation
        while url and url[-1] in trailing_punct:
            url = url[:-1]
            
        if url and url not in cleaned_urls:
            cleaned_urls.append(url)
            
    # Normalize and deduplicate
    normalized_urls = set()
    for url in cleaned_urls:
        try:
            normalized_urls.add(_normalize_url(url))
        except Exception:
            normalized_urls.add(url)
            
    return sorted(list(normalized_urls))
