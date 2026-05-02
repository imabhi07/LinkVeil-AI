"""
whois_service.py
----------------
Domain registration info and age scoring service.
"""

import whois
import logging
from datetime import datetime, timezone
from typing import Optional, Tuple
import asyncio

logger = logging.getLogger(__name__)

class WhoisService:
    def __init__(self):
        # In-memory cache: domain -> (timestamp, result_dict)
        self._cache = {}
        self.CACHE_TTL = 86400  # 24 hours

    async def lookup(self, domain: str) -> dict:
        """
        Returns {
            "domain_age_days": int | None,
            "has_privacy": bool,
            "registrar": str | None,
            "creation_date": str | None,
            "is_new_domain": bool
        }
        """
        # 1. Check cache
        now = datetime.now(timezone.utc).timestamp()
        if domain in self._cache:
            ts, result = self._cache[domain]
            if now - ts < self.CACHE_TTL:
                logger.info(f"WHOIS cache hit for {domain}")
                return result

        try:
            # 2. Perform WHOIS lookup
            # Wrap blocking call in a thread to keep event loop free
            w = await asyncio.to_thread(whois.whois, domain)
            
            creation_date = w.creation_date
            # creation_date can be a single datetime or a list
            if isinstance(creation_date, list):
                # Filter out None values and check if list is not empty
                valid_dates = [d for d in creation_date if d is not None]
                creation_date = min(valid_dates) if valid_dates else None
            
            age_days = None
            is_new = False
            if creation_date:
                # Remove timezone if present to compare with now()
                if creation_date.tzinfo is not None:
                    creation_date = creation_date.astimezone(timezone.utc).replace(tzinfo=None)
                
                delta = datetime.now() - creation_date
                age_days = delta.days
                if age_days < 30:
                    is_new = True

            # Detect privacy shield (common keywords)
            registrar = str(w.registrar) if w.registrar else "Unknown"
            privacy_keywords = ["privacy", "proxy", "protected", "guard", "masked"]
            has_privacy = any(kw in registrar.lower() for kw in privacy_keywords)

            result = {
                "domain_age_days": age_days,
                "has_privacy": has_privacy,
                "registrar": registrar,
                "creation_date": creation_date.isoformat() if creation_date else None,
                "is_new_domain": is_new
            }

            # 3. Cache and return
            self._cache[domain] = (now, result)
            return result

        except Exception as e:
            logger.error(f"WHOIS lookup failed for {domain}: {e}")
            return {
                "domain_age_days": None,
                "has_privacy": False,
                "registrar": None,
                "creation_date": None,
                "is_new_domain": False
            }

# Singleton
whois_service = WhoisService()
