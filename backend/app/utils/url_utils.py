from urllib.parse import urlparse, parse_qs, urlencode

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


def _normalize_url(raw: str) -> str:
    """
    Normalize URL for cache consistency:
      - lowercase the scheme + hostname
      - strip trailing slashes
      - strip default ports (80/443)
      - remove tracking / analytics query params
      - sort remaining query params alphabetically
      - drop fragment
    """
    url = raw.strip()
    if "://" not in url:
        url = "https://" + url

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
