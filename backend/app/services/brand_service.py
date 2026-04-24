"""
brand_service.py
----------------
Deterministic brand impersonation classifier.
Detects when a known brand name is used in a domain or path that does not 
belong to the legitimate brand owner.
"""

import tldextract
import re
import logging

logger = logging.getLogger(__name__)

# brand_token -> legitimate_root_domain
BRAND_TOKENS = {
    "paypal": "paypal.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "twitter": "twitter.com",
    "linkedin": "linkedin.com",
    "adobe": "adobe.com",
    "ebay": "ebay.com",
    "walmart": "walmart.com",
    "chase": "chase.com",
    "bankofamerica": "bankofamerica.com",
    "wellsfargo": "wellsfargo.com",
    "citibank": "citi.com",
    "americanexpress": "americanexpress.com",
    "coinbase": "coinbase.com",
    "binance": "binance.com",
    "metamask": "metamask.io",
    "blockchain": "blockchain.com",
    "dropbox": "dropbox.com",
    "docusign": "docusign.com",
    "protonmail": "proton.me",
    "outlook": "outlook.com",
    "office365": "office.com",
    "sharepoint": "sharepoint.com",
}

def detect_brand_mismatch(url: str) -> dict:
    """
    Returns {
        "brand_detected": str | None,
        "legitimate_domain": str | None,
        "is_mismatch": bool,
        "confidence": float,
        "reason": str | None
    }
    """
    try:
        url_lower = url.lower()
        extracted = tldextract.extract(url_lower)
        root_domain = f"{extracted.domain}.{extracted.suffix}"
        
        # Check hostname (subdomain + domain)
        full_host = f"{extracted.subdomain}.{extracted.domain}" if extracted.subdomain else extracted.domain
        
        # Check path
        path = url_lower.split("/", 3)[-1] if "/" in url_lower.split("://")[-1] else ""

        for token, legit_domain in BRAND_TOKENS.items():
            # 1. Check if token is in hostname with word boundaries
            # Using regex \b to avoid over-matching (e.g. 'apple' in 'pineapple')
            if re.search(rf'\b{re.escape(token)}\b', full_host):
                # If it's in the hostname, but the root domain is NOT the legit one, it's a mismatch
                if root_domain != legit_domain:
                    return {
                        "brand_detected": token.capitalize(),
                        "legitimate_domain": legit_domain,
                        "is_mismatch": True,
                        "confidence": 0.9,
                        "reason": f"Brand '{token}' found in untrusted domain '{root_domain}'"
                    }
            
            # 2. Check if token is in path (e.g. example.com/login-paypal)
            if re.search(rf'\b{re.escape(token)}\b', path):
                 if root_domain != legit_domain:
                    return {
                        "brand_detected": token.capitalize(),
                        "legitimate_domain": legit_domain,
                        "is_mismatch": True,
                        "confidence": 0.8,
                        "reason": f"Brand '{token}' found in path of untrusted domain '{root_domain}'"
                    }

        return {
            "brand_detected": None,
            "legitimate_domain": None,
            "is_mismatch": False,
            "confidence": 0.0,
            "reason": None
        }

    except Exception as e:
        logger.error(f"Error in brand_service.detect_brand_mismatch: {e}")
        return {
            "brand_detected": None,
            "legitimate_domain": None,
            "is_mismatch": False,
            "confidence": 0.0,
            "reason": str(e)
        }
