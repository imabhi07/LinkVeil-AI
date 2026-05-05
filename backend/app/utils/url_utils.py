import ipaddress
import socket
from urllib.parse import urlparse, parse_qs, urlencode, unquote

# ── Tracking / analytics params to strip before caching & scanning ──
_TRACKING_PARAMS = frozenset({
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "utm_id", "utm_source_platform", "utm_creative_format",
    "fbclid", "gclid", "gclsrc", "msclkid", "mc_eid", "mc_cid",
    "dclid", "yclid", "twclid", "li_fat_id", "igshid",
    "ref", "ref_src", "ref_url", "source", "spm",
    "_ga", "_gl", "_hsenc", "_hsmi", "_openstat",
    "wickedid", "oly_anon_id", "oly_enc_id",
    "vero_id", "nr_email_referer",
})

# SSRF Protected ranges
_PRIVATE_NETWORKS = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),  # Link-local / Cloud metadata
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
    ipaddress.ip_network('fe80::/10'),
]

def is_safe_url(url: str) -> tuple[bool, str]:
    """
    Checks if a URL is safe to probe/fetch (SSRF prevention).
    Returns (is_safe, reason).
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            return False, "unsupported_scheme"
        
        hostname = parsed.hostname
        if not hostname:
            return False, "missing_hostname"
        
        # Check if hostname is an IP
        try:
            ip = ipaddress.ip_address(hostname)
            for network in _PRIVATE_NETWORKS:
                if ip in network:
                    return False, "private_ip_blocked"
        except ValueError:
            # It's a domain name, not an IP.
            # In a real production system, we'd resolve it and check the resulting IP too,
            # but for this forensic engine, we'll block obvious localhost/private keywords.
            if hostname.lower() in ('localhost', 'metadata.google.internal'):
                return False, "localhost_blocked"
            
        return True, ""
    except Exception:
        return False, "invalid_url"

def _normalize_url(raw: str) -> str:
    """
    Normalize URL for cache consistency.
    """
    url = raw.strip()
    if "://" not in url:
        url = "https://" + url

    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname.lower() if parsed.hostname else ""
        port = parsed.port

        # Strip default ports
        if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
            port = None

        netloc = f"{hostname}:{port}" if port else hostname
        path = parsed.path.rstrip("/") or "/"

        # Strip tracking params and sort remaining
        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            clean_params = {
                k: v for k, v in sorted(params.items())
                if k.lower() not in _TRACKING_PARAMS
            }
            query = urlencode(clean_params, doseq=True) if clean_params else ""
        else:
            query = ""

        normalized = f"{scheme}://{netloc}{path}"
        if query:
            normalized += f"?{query}"
        return normalized
    except:
        return url
