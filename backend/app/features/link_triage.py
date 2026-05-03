import re
import socket
import base64
import ipaddress
import binascii
import concurrent.futures
import os
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode, unquote

def strip_pii(url: str) -> str:
    """
    Scrub email addresses and long tokens from URL query parameters.
    """
    if not url: return url
    try:
        parsed = urlparse(url)
        if not parsed.query:
            return url
            
        params = parse_qs(parsed.query)
        scrubbed_params = {}
        
        # Email regex
        email_regex = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
        
        for k, vals in params.items():
            new_vals = []
            for v in vals:
                # 1. Scrub emails
                v = re.sub(email_regex, '[PII_REMOVED]', v)
                # 2. Scrub long random-looking tokens (likely PII/Session)
                if len(v) > 40 and re.match(r'^[a-zA-Z0-9\-_=]+$', v):
                    v = '[TOKEN_REMOVED]'
                new_vals.append(v)
            scrubbed_params[k] = new_vals
            
        # Reconstruct
        new_query = urlencode(scrubbed_params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))
    except Exception:
        return url

def is_safe_url(url: str, dns_timeout: float = 3.0) -> bool:
    """
    SSRF hardening: only allow http/https, reject private IP ranges and localhost.
    Now with full DNS resolution and IP range checks.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            return False
            
        hostname = parsed.hostname
        if not hostname:
            return False
            
        # 1. Basic length and character check
        if len(url) > 2048:
            return False
            
        # 2. DNS Resolution and IP checking with timeout
        try:
            # We use a ThreadPoolExecutor to enforce a timeout on the blocking getaddrinfo call
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(socket.getaddrinfo, hostname, None)
                addr_info = future.result(timeout=dns_timeout)
                
            for res in addr_info:
                ip_str = res[4][0]
                ip_addr = ipaddress.ip_address(ip_str)
                
                # Reject if ANY resolved IP is in a restricted range
                if (ip_addr.is_private or 
                    ip_addr.is_loopback or 
                    ip_addr.is_link_local or 
                    ip_addr.is_unspecified or 
                    ip_addr.is_multicast):
                    return False
        except (socket.gaierror, socket.timeout, concurrent.futures.TimeoutError):
            # If we can't resolve it or it times out, we don't trust it
            return False
            
        return True
    except Exception:
        return False

def unwrap_once(url: str) -> tuple[str | None, str | None]:
    """
    Tries to find a destination URL within query parameters.
    Returns: (unwrapped_url, source_param_name) or (None, None)
    """
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Common redirect/target parameters
        target_params = ['url', 'dest', 'destination', 'link', 'redirect', 'target', 'u', 'uri', 'next', 'goto', 'continue', 'r']
        
        for p in target_params:
            if p in params:
                val = params[p][0]
                
                # Check for Base64 (common in some wrappers)
                if len(val) > 10 and (val.endswith('==') or re.match(r'^[a-zA-Z0-9+/]+={0,2}$', val)):
                    try:
                        decoded = base64.b64decode(val).decode('utf-8')
                        if is_safe_url(decoded):
                            return decoded, p
                    except (binascii.Error, UnicodeDecodeError, ValueError):
                        continue
                
                # Try standard unquote
                candidate = unquote(val)
                if is_safe_url(candidate):
                    return candidate, p
                    
        return None, None
    except Exception:
        return None, None

SOCIAL_DOMAINS = {
    "facebook.com", "instagram.com", "linkedin.com", "twitter.com", "x.com", 
    "threads.net", "youtube.com"
}
KNOWN_SAFE_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "infosys.com", "gmail.com", "outlook.com"
}

def classify_url(url: str, unwrapped_info: tuple[str | None, str | None] = (None, None)) -> tuple[str, str]:
    """
    Classifies a URL into categories: static_asset, tracking_wrapper, unsubscribe, content, known_safe, other.
    Returns: (category, reason)
    """
    try:
        # Check for Tracking Wrapper FIRST (can be passed in to avoid redundant work)
        unwrapped, param = unwrapped_info
        if not unwrapped:
            unwrapped, param = unwrap_once(url)
            
        if unwrapped:
            return "tracking_wrapper", f"Found destination in '{param}' parameter"

        parsed = urlparse(url)
        path = parsed.path.lower()
        query = parsed.query.lower()
        domain = parsed.netloc.lower()
        # Strip 'www.' for cleaner matching
        clean_domain = domain.replace("www.", "")
        
        # 1. Content (HIGHEST PRIORITY - even on safe domains)
        content_keywords = {"login", "verify", "account", "security", "update", "reset", 
                             "password", "payment", "billing", "signin", "auth", "profile", "complete"}
        if any(kw in path or kw in query for kw in content_keywords):
            return "content", "Highly sensitive keyword detected in URL path/query"

        # 2. Social Media (Strict Skip)
        if any(clean_domain.endswith(d) for d in SOCIAL_DOMAINS):
            return "known_safe", f"Verified social platform: {clean_domain}"

        # 3. Known Safe Major Domains (Optimization for non-content pages)
        if any(clean_domain.endswith(d) for d in KNOWN_SAFE_DOMAINS):
            return "known_safe", f"Verified major platform or trusted domain: {clean_domain}"

        # 4. Static Assets
        static_extensions = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.ico', 
                             '.css', '.js', '.woff', '.woff2', '.ttf', '.eot'}
        if any(path.endswith(ext) for ext in static_extensions):
            return "static_asset", "File extension matches static asset patterns"
            
        # 3. Unsubscribe
        unsub_keywords = {"unsubscribe", "optout", "opt-out", "mail-pref"}
        if any(kw in path or kw in query for kw in unsub_keywords):
            return "unsubscribe", "URL contains unsubscribe or opt-out keywords"
            
        # 4. Tracking / Analytics (General patterns if not a wrapper)
        tracking_keywords = {"pixel", "beacon", "track", "analytics", "click-thru", "open-rate"}
        if any(kw in path or kw in query or kw in domain for kw in tracking_keywords):
            return "tracking_wrapper", "URL matches known tracking or analytics patterns"
            
            
        # Default for "pages" (no extension or .html/.php etc)
        page_extensions = {'.html', '.htm', '.php', '.asp', '.aspx'}
        _, ext = os.path.splitext(path)
        if ext in page_extensions or not ext:
            return "content", "Standard web page pattern"
            
        return "other", "Unclassified link"
    except Exception:
        return "other", "Error during classification"

def dedupe_urls(urls: list[str]) -> list[str]:
    """
    Dedupes URLs by normalizing them and checking (domain, path).
    Query params are ignored for deduping to avoid UTM duplicates.
    """
    seen = set()
    unique = []
    
    for url in urls:
        try:
            parsed = urlparse(url)
            # Normalization: lower case domain, strip trailing slash from path
            normalized_netloc = parsed.netloc.lower()
            normalized_path = parsed.path.rstrip('/')
            
            dedupe_key = (normalized_netloc, normalized_path)
            
            if dedupe_key not in seen:
                seen.add(dedupe_key)
                unique.append(url)
        except Exception:
            if url not in unique:
                unique.append(url)
                
    return unique

def triage_urls(urls: list[str], max_scan: int = 8, from_email: str = None) -> dict:
    """
    Categorizes and picks the top N URLs to scan.
    Implements: Two-Pass Triage + SSRF-Safe Unwrapping + PII Scrubbing.
    """
    # Pass 1: Normalize, Classify, Unwrap, Scrub
    processed = []
    unwrap_events = []
    pii_scrubbed_count = 0
    
    unique_keys = set()
    
    for raw_url in urls:
        # PII Scrubbing (all links get scrubbed for storage/display)
        sanitized_raw = strip_pii(raw_url)
        if sanitized_raw != raw_url:
            pii_scrubbed_count += 1
            
        # Unwrapping (Check this before classification to avoid redundancy)
        unwrapped, param = unwrap_once(raw_url)
        
        # Classification (Pass unwrapped info to avoid second lookup)
        cat, reason = classify_url(raw_url, unwrapped_info=(unwrapped, param))
        final_scan_url = raw_url
        sanitized_final_url = sanitized_raw
        
        if unwrapped:
            final_scan_url = unwrapped
            sanitized_final_url = strip_pii(unwrapped)
            unwrap_events.append({
                "found_url": sanitized_raw,
                "destination_url": sanitized_final_url,
                "status": "success",
                "reason": f"Unwrapped from '{param}'"
            })
        
        # Deduping by (sanitized_final_url)
        if sanitized_final_url in unique_keys:
            continue
        unique_keys.add(sanitized_final_url)
        
        processed.append({
            "raw_url": sanitized_raw, # Sanitized found url
            "scan_url": sanitized_final_url, # Sanitized destination url
            "type": cat,
            "reason": reason,
            "is_unwrapped": unwrapped is not None
        })
        
    # Stats
    stats = {
        "total_extracted": len(urls),
        "total_unique": len(processed),
        "pii_scrubbed_count": pii_scrubbed_count,
        "wrappers_unwrapped": len(unwrap_events),
        "static_asset": len([p for p in processed if p["type"] == "static_asset"]),
        "tracking_wrapper": len([p for p in processed if p["type"] == "tracking_wrapper"]),
        "unsubscribe": len([p for p in processed if p["type"] == "unsubscribe"]),
        "content": len([p for p in processed if p["type"] == "content"]),
        "known_safe": len([p for p in processed if p["type"] == "known_safe"]),
        "other": len([p for p in processed if p["type"] == "other"])
    }
    
    # Pass 2: Priority Scoring
    def priority_score(item):
        score = 0
        if item["type"] == "content": score += 100
        if item["type"] == "other": score += 50
        
        # Keyword Boost
        keywords = ["login", "verify", "secure", "account", "password", "payment", "billing"]
        if any(kw in item["scan_url"].lower() for kw in keywords):
            score += 200
            
        # Tracking wrappers (even if unwrapped) are slightly suspicious
        if item["is_unwrapped"]: score += 10
        
        return score

    sorted_links = sorted(processed, key=priority_score, reverse=True)
    
    # Filter out statics/tracking/known_safe from full scan unless space permits
    to_scan_candidates = [p for p in sorted_links if p["type"] not in ("static_asset", "known_safe")]
    to_scan = to_scan_candidates[:max_scan]
    
    # Final cleanup for response
    scan_urls = [p["scan_url"] for p in to_scan]
    scanned_set = set(scan_urls)
    
    skipped = [
        {"url": p["raw_url"], "type": p["type"], "reason": p["reason"]}
        for p in sorted_links if p["scan_url"] not in scanned_set
    ]
    
    # Deep Dive Selection
    deep_dive_candidate = to_scan[0]["scan_url"] if to_scan else None

    return {
        "to_scan": scan_urls,
        "skipped": skipped,
        "stats": stats,
        "deep_dive_candidate": deep_dive_candidate,
        "unwrap_events": unwrap_events,
        "processed_links": to_scan # Return full objects for UI mapping later if needed
    }
