"""
threat_intel_service.py
-----------------------
Threat feed integration for known phishing URLs.
Short-circuits the engine if a match is found.
"""

import aiohttp
import asyncio
import logging
import time

logger = logging.getLogger(__name__)

class ThreatIntelService:
    FEEDS = {
        "openphish": "https://openphish.com/feed.txt",
        "urlhaus": "https://urlhaus.abuse.ch/downloads/text_recent/",
        # PhishTank usually needs an API key or specific user-agent/headers
        # and returns JSON. We'll start with these two first.
    }

    def __init__(self):
        self._feed_cache = {}  # feed_name -> set of URLs
        self._last_refresh = 0
        self.REFRESH_INTERVAL = 3600  # 1 hour
        self._lock = asyncio.Lock()

    async def refresh_feeds(self):
        """Fetch and update threat feeds."""
        async with self._lock:
            now = time.time()
            if now - self._last_refresh < self.REFRESH_INTERVAL:
                return

            logger.info("Refreshing threat intel feeds...")
            async with aiohttp.ClientSession() as session:
                for name, url in self.FEEDS.items():
                    try:
                        async with session.get(url, timeout=30) as resp:
                            if resp.status == 200:
                                text = await resp.text()
                                # Simple line-based text feeds
                                urls = {line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")}
                                self._feed_cache[name] = urls
                                logger.info(f"Loaded {len(urls)} entries from {name}")
                            else:
                                logger.warning(f"Failed to fetch {name} feed: HTTP {resp.status}")
                    except Exception as e:
                        logger.error(f"Error fetching {name} feed: {e}")
            
            self._last_refresh = now

    async def check(self, url: str) -> dict:
        """
        Check if URL exists in any threat feed.
        Returns {
            "is_known_malicious": bool,
            "source": str | None,
            "confidence": float
        }
        """
        # If cache is empty, try to refresh once
        if not self._feed_cache:
            await self.refresh_feeds()

        # Check against cache
        for name, urls in self._feed_cache.items():
            if url in urls:
                logger.info(f"Threat intel hit! {url} found in {name}")
                return {
                    "is_known_malicious": True,
                    "source": name,
                    "confidence": 1.0
                }
            
            # Also check with/without trailing slash and protocol variants
            normalized = url.rstrip("/")
            with_slash = normalized + "/"
            without_proto = url.split("://")[-1].rstrip("/")
            http_variant = "http://" + without_proto
            https_variant = "https://" + without_proto
            
            variants = {normalized, with_slash, http_variant, https_variant,
                        http_variant + "/", https_variant + "/"}
            
            # Set intersection is O(1) per variant
            if variants & urls:
                matched = (variants & urls).pop()
                logger.info(f"Threat intel hit! {url} matched {matched} in {name}")
                return {
                    "is_known_malicious": True,
                    "source": name,
                    "confidence": 0.95
                }

        return {
            "is_known_malicious": False,
            "source": None,
            "confidence": 0.0
        }

    async def background_refresh(self):
        """Infinite loop to refresh feeds periodically."""
        while True:
            try:
                await self.refresh_feeds()
            except Exception as e:
                logger.error(f"Background refresh failed: {e}")
            # Refresh every 6 hours (matches INTEL_REFRESH_INTERVAL in .env.example)
            await asyncio.sleep(21600)

# Singleton
threat_intel_service = ThreatIntelService()
