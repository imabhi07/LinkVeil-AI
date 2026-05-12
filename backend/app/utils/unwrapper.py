
import aiohttp
import asyncio
import logging
import re
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Common shorteners that require network-based unwrapping
SHORTENER_DOMAINS = {
    "t.co", "wa.me", "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "buff.ly",
    "is.gd", "rebrand.ly", "t.me", "lnkd.in", "db.tt", "qr.ae", "git.io"
}

# Mobile User-Agent to bypass some basic bot-detection
MOBILE_UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1"

async def resolve_shortener(url: str, timeout: float = 5.0) -> Optional[str]:
    """
    Follows redirects for known shorteners to find the destination URL.
    Uses a mobile UA to bypass bot-detection on some platforms.
    """
    domain = urlparse(url).netloc.lower()
    # Remove 'www.' if present for matching
    if domain.startswith("www."):
        domain = domain[4:]
        
    if domain not in SHORTENER_DOMAINS:
        return None

    logger.info(f"Unwrapping shortener: {url} (domain: {domain})")
    
    headers = {
        "User-Agent": MOBILE_UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }
    
    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            # We only need the headers to find the Location
            async with session.head(url, allow_redirects=True, timeout=timeout) as response:
                if response.status == 200:
                    final_url = str(response.url)
                    if final_url != url:
                        logger.info(f"Resolved {url} -> {final_url}")
                        return final_url
                elif response.status in (301, 302, 303, 307, 308):
                    # Sometimes HEAD doesn't follow redirects automatically if it's a weird status
                    # though aiohttp handles it. Check Location manually if needed.
                    loc = response.headers.get("Location")
                    if loc:
                        return loc
    except Exception as e:
        logger.warning(f"Failed to resolve shortener {url}: {e}")
        
    return None
