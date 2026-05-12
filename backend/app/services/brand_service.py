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
    "paypal": ["paypal.com"],
    "google": ["google.com", "google.co", "google.co.in", "google.co.uk", "google.de", "google.fr", "google.co.jp", "google.com.br", "google.com.au"],
    "microsoft": ["microsoft.com", "microsoftonline.com", "office.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.co.jp", "amazon.es", "amazon.it", "amazon.com.br", "amazon.com.au"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
    "twitter": ["twitter.com", "x.com"],
    "linkedin": ["linkedin.com"],
    "adobe": ["adobe.com"],
    "ebay": ["ebay.com", "ebay.co.uk", "ebay.de", "ebay.com.au"],
    "walmart": ["walmart.com"],
    "chase": ["chase.com"],
    "bankofamerica": ["bankofamerica.com"],
    "wellsfargo": ["wellsfargo.com"],
    "citibank": ["citi.com"],
    "americanexpress": ["americanexpress.com"],
    "coinbase": ["coinbase.com"],
    "binance": ["binance.com"],
    "metamask": ["metamask.io"],
    "blockchain": ["blockchain.com"],
    "dropbox": ["dropbox.com"],
    "docusign": ["docusign.com"],
    "protonmail": ["proton.me", "protonmail.com"],
    "outlook": ["outlook.com"],
    "office365": ["office.com"],
    "sharepoint": ["sharepoint.com"],
    "airbnb": ["airbnb.com"],
    "netflix": ["netflix.com"],
    "spotify": ["spotify.com"],
    "disneyplus": ["disneyplus.com"],
    
    "slack": ["slack.com"],
    "zoom": ["zoom.us"],
    "canva": ["canva.com"],
    "atlassian": ["atlassian.com"],
    "jira": ["jira.com"],
    "trello": ["trello.com"],
    "bitbucket": ["bitbucket.org"],
    "vercel": ["vercel.com", "vercel.app"],
    "netlify": ["netlify.com", "netlify.app"],
    "digitalocean": ["digitalocean.com"],
    "heroku": ["heroku.com"],
    "cloudflare": ["cloudflare.com"],
    "github": ["github.com", "github.io"],
    "gitlab": ["gitlab.com"],
    "discord": ["discord.com", "discord.gg"],
    "notion": ["notion.so"],
    "figma": ["figma.com"],
    "intercom": ["intercom.com"],
    "stripe": ["stripe.com"],
    "razorpay": ["razorpay.com"],
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

        for token, legit_domains in BRAND_TOKENS.items():
            # 1. Check if token is in hostname with word boundaries
            if re.search(rf'\b{re.escape(token)}\b', full_host):
                # Quick check: if the registrable base domain IS the brand, it's legit
                if extracted.domain == token:
                    continue
                # If it's in the hostname, but the root domain is NOT among the legit ones, it's a mismatch
                if root_domain not in legit_domains:
                    return {
                        "brand_detected": token.capitalize(),
                        "legitimate_domain": legit_domains[0],
                        "is_mismatch": True,
                        "confidence": 0.9,
                        "reason": f"Brand '{token}' found in untrusted domain '{root_domain}'"
                    }
            
            # 2. Check if token is in path (e.g. example.com/login-paypal)
            if re.search(rf'\b{re.escape(token)}\b', path):
                 # Quick check: if the registrable base domain IS the brand, it's legit
                 if extracted.domain == token:
                    continue
                 if root_domain not in legit_domains:
                    return {
                        "brand_detected": token.capitalize(),
                        "legitimate_domain": legit_domains[0],
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
        
def get_legit_domains(brand_name: str) -> list[str]:
    """Returns the official domains for a brand name (case-insensitive)."""
    if not brand_name:
        return []
    return BRAND_TOKENS.get(brand_name.lower(), [])
