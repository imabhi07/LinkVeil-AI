"""
xgb_features.py
----------------
Hand-crafted URL feature extractor for the XGBoost phishing classifier.
All features are numeric so sklearn/XGBoost can consume them directly.
"""

import re
import math
from urllib.parse import urlparse


# Common phishing keywords
PHISH_KEYWORDS = [
    "login", "signin", "verify", "update", "secure", "account", "banking",
    "confirm", "ebayisapi", "webscr", "paypal", "password", "credential",
    "alert", "suspended", "support", "helpdesk", "click", "free",
]


def _entropy(s: str) -> float:
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def extract_features(url: str) -> list:
    """
    Extract a fixed-length numeric feature vector from a URL.
    Returns a list of 30 floats.
    """
    url = str(url).strip()

    # --- Parsed components ---
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
    except Exception:
        parsed = urlparse("http://invalid")

    scheme   = parsed.scheme or ""
    netloc   = parsed.netloc or ""
    path     = parsed.path or ""
    query    = parsed.query or ""
    fragment = parsed.fragment or ""

    # Strip port from hostname
    hostname = netloc.split(":")[0] if netloc else ""
    subdomain_parts = hostname.split(".")

    full_url = url

    # ----- Feature list (30 features) -----
    features = []

    # 1. Total URL length
    features.append(len(full_url))

    # 2. Hostname length
    features.append(len(hostname))

    # 3. Path length
    features.append(len(path))

    # 4. Query length
    features.append(len(query))

    # 5. Number of dots in URL
    features.append(full_url.count("."))

    # 6. Number of hyphens in URL
    features.append(full_url.count("-"))

    # 7. Number of underscores in URL
    features.append(full_url.count("_"))

    # 8. Number of slashes in URL
    features.append(full_url.count("/"))

    # 9. Number of "@" symbols (credential phishing indicator)
    features.append(full_url.count("@"))

    # 10. Number of "?" characters
    features.append(full_url.count("?"))

    # 11. Number of "=" characters
    features.append(full_url.count("="))

    # 12. Number of "&" characters
    features.append(full_url.count("&"))

    # 13. Number of digits in URL
    features.append(sum(c.isdigit() for c in full_url))

    # 14. Ratio of digits to total URL length
    features.append(sum(c.isdigit() for c in full_url) / max(len(full_url), 1))

    # 15. Is HTTPS? (1 = yes, 0 = no)
    features.append(1 if scheme == "https" else 0)

    # 16. IP address in hostname? (e.g., 192.168.1.1)
    ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    features.append(1 if ip_pattern.match(hostname) else 0)

    # 17. Number of subdomains
    num_subdomains = max(0, len(subdomain_parts) - 2)
    features.append(num_subdomains)

    # 18. Has "www" prefix?
    features.append(1 if hostname.startswith("www.") else 0)

    # 19. Count of phishing keywords in URL
    url_lower = full_url.lower()
    features.append(sum(1 for kw in PHISH_KEYWORDS if kw in url_lower))

    # 20. Entropy of hostname (high entropy = random/DGA domain)
    features.append(_entropy(hostname))

    # 21. Entropy of full URL
    features.append(_entropy(full_url))

    # 22. Length of longest consecutive digit string in URL
    digit_runs = re.findall(r"\d+", full_url)
    features.append(max((len(r) for r in digit_runs), default=0))

    # 23. Ratio of uppercase letters in URL
    features.append(sum(c.isupper() for c in full_url) / max(len(full_url), 1))

    # 24. Has port number?
    features.append(1 if ":" in netloc and not netloc.endswith(":") else 0)

    # 25. Count of special characters (non-alphanumeric, non-standard)
    features.append(len(re.findall(r"[^a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]", full_url)))

    # 26. Number of path segments (depth)
    path_segments = [s for s in path.split("/") if s]
    features.append(len(path_segments))

    # 27. Has fragment (#)?
    features.append(1 if fragment else 0)

    # 28. TLD length (e.g., "com" = 3)
    tld = subdomain_parts[-1] if subdomain_parts else ""
    features.append(len(tld))

    # 29. "Shortening service" in hostname?
    shorteners = ["bit.ly", "tinyurl", "goo.gl", "ow.ly", "t.co", "buff.ly", "short.io"]
    features.append(1 if any(s in hostname for s in shorteners) else 0)

    # 30. URL contains "redirect" or "forward"?
    features.append(1 if "redirect" in url_lower or "forward" in url_lower else 0)

    return features


FEATURE_NAMES = [
    "url_length", "hostname_length", "path_length", "query_length",
    "count_dots", "count_hyphens", "count_underscores", "count_slashes",
    "count_at", "count_question", "count_equals", "count_ampersand",
    "count_digits", "ratio_digits",
    "is_https", "has_ip", "num_subdomains", "has_www",
    "phish_keyword_count", "entropy_hostname", "entropy_url",
    "longest_digit_run", "ratio_uppercase",
    "has_port", "special_char_count", "path_depth",
    "has_fragment", "tld_length", "is_shortener", "has_redirect",
]
