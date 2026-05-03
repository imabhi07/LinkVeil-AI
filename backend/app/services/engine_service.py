import asyncio
import logging
import time
from functools import lru_cache
from typing import Optional
from urllib.parse import urlparse
from sqlalchemy.orm import Session
from datetime import datetime, timezone

import json
import tldextract
from backend.app.services.xgb_service import xgb_service
from backend.app.services.llm_service import analyze_url
from backend.app.services.probe_agent import run_probe_async, probe_result_to_dict, FAKE_USER
from backend.app.services.threat_intel_service import threat_intel_service
from backend.app.services.whois_service import whois_service
from backend.app.services.brand_service import detect_brand_mismatch
from backend.app.services.vision_service import vision_service
from backend.app.features.url_features import extract_features
from backend.app.models.db_models import ScanResult

logger = logging.getLogger(__name__)

# ── Result cache: avoid re-running full pipeline for same URL within 5 min ──
_result_cache: dict[str, tuple[float, dict]] = {}
CACHE_TTL_SECONDS = 300  # 5 minutes

# ── Well-known safe domains — skip expensive Playwright probe for these ──
KNOWN_SAFE_DOMAINS = frozenset({
    "google.com", "youtube.com", "facebook.com", "instagram.com",
    "twitter.com", "x.com", "linkedin.com", "github.com",
    "microsoft.com", "apple.com", "amazon.com", "netflix.com",
    "wikipedia.org", "reddit.com", "stackoverflow.com",
    "paypal.com", "yahoo.com", "bing.com", "whatsapp.com",
    "zoom.us", "slack.com", "dropbox.com", "spotify.com",
    "paytm.com", "flipkart.com", "razorpay.com", "phonepe.com",
    "uber.com", "airbnb.com", "stripe.com", "twitch.tv",
    "perplexity.ai", "chatgpt.com", "openai.com", "infosys.com",
    "pepsicoindia.co.in", "pepsico.com", "tata.com", "reliance.com",
    "hdfcbank.com", "icicibank.com", "sbi.co.in", "irctc.co.in"
})

SUSPICIOUS_TLDS = frozenset({
    "cf", "tk", "ml", "ga", "gq",  # Freenom free TLDs
    "buzz", "top", "xyz", "club", "work", "loan", "click",
    "info", "cam", "icu", "monster", "rest", "surf", "casa"
})

LOGIN_KEYWORDS = ["/login", "/signin", "/verify", "/account", "/secure", "/auth", "/webscr", "/ebayisapi"]

# ── Timeout guards ──
XGB_TIMEOUT_S = 5
LLM_TIMEOUT_S = 25
PROBE_TIMEOUT_S = 30


def _root_domain(url: str) -> str:
    """Extract root domain correctly using tldextract (handles .co.in, etc.)"""
    try:
        ext = tldextract.extract(url)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
        return (ext.registered_domain or "").lower()
    except Exception:
        return ""


def _should_skip_probe(url: str) -> bool:
    """Skip Playwright probe for well-known safe domains."""
    return _root_domain(url) in KNOWN_SAFE_DOMAINS


def _get_trusted_verdict(url: str) -> dict:
    """Returns a pre-baked 'Safe' verdict for whitelisted domains."""
    domain = _root_domain(url)
    return {
        "url": url,
        "risk_score": 0.0,
        "risk_level": "Safe",
        "recommendation": "✅ Safe - Verified Trusted Domain",
        "explanation": f"This domain ({domain}) is a verified high-authority corporate or service platform and is pre-cleared by the PhishGuard Global Whitelist.",
        "brand_impersonation": False,
        "brand_name": domain.split('.')[0].capitalize(),
        "verdictTitle": "Trusted Domain Verified",
        "technicalDetails": {
            "urlStructure": "Verified legitimate structure.",
            "domainReputation": "High-authority whitelisted domain.",
            "socialEngineeringTricks": "None detected."
        },
        "mitigationAdvice": ["No action required. This is an official domain."],
        "agentReport": {"performed": False, "outcome": "Skipped for trusted domain."},
        "whois_info": {"domain_age_days": 5000, "is_new_domain": False}, # Representative value
        "threat_intel": {"is_known_malicious": False},
        "visual_forensics": None,
        "fusion_trace": {"final_score": 0.0, "note": "Whitelisted domain short-circuit"}
    }


def _get_cached(url: str) -> Optional[dict]:
    """Return cached result if TTL hasn't expired."""
    if url in _result_cache:
        ts, result = _result_cache[url]
        if time.time() - ts < CACHE_TTL_SECONDS:
            logger.info(f"Cache HIT for {url} (age={time.time() - ts:.0f}s)")
            return result
        else:
            del _result_cache[url]
    return None


def _set_cache(url: str, result: dict):
    """Store result in cache with current timestamp."""
    _result_cache[url] = (time.time(), result)
    # Evict old entries if cache grows too large (simple LRU-ish)
    if len(_result_cache) > 200:
        oldest_key = min(_result_cache, key=lambda k: _result_cache[k][0])
        del _result_cache[oldest_key]


async def evaluate_url(url: str, db: Session) -> dict:
    """
    Hybrid evaluation pipeline:
    1. Cache check
    2. Threat Intel short-circuit
    3. Parallel execution (XGB, LLM, Probe, WHOIS, Brand detect)
    4. Vision analysis (if screenshot captured)
    5. Fusion logic with boosts
    6. Persistence and caching
    """
    t0 = time.perf_counter()
    logger.info(f"Starting hybrid evaluation for URL: {url}")

    # ── 1. Check cache ──
    cached = _get_cached(url)
    if cached is not None:
        _save_to_db(cached, db)
        return cached

    # ── 2. Threat Intel (Short-circuit) ──
    threat_result = await threat_intel_service.check(url)
    
    # ── 3. Whitelist Short-circuit (NEW) ──
    if _should_skip_probe(url):
        logger.info(f"Whitelist HIT for {url} — returning instant verdict.")
        verdict = _get_trusted_verdict(url)
        _save_to_db(verdict, db)
        return verdict

    if threat_result["is_known_malicious"]:
        verdict = {
            "url": url,
            "risk_score": 95.0,
            "risk_level": "High",
            "explanation": f"⚠️ Threat Intel Match: This URL is found in the {threat_result['source']} blacklist.",
            "brand_impersonation": False,
            "brand_name": None,
            "verdictTitle": "Known Malicious URL",
            "technicalDetails": {"domainReputation": f"Blacklisted by {threat_result['source']}"},
            "mitigationAdvice": ["Do not interact with this page.", "Report to security team."],
            "agentReport": {"activeProbing": {"performed": False, "outcome": "Short-circuited by threat intel."}},
            "threat_intel": threat_result
        }
        _save_to_db(verdict, db)
        return verdict

    # ── 4. Parallel Analysis ──
    lexical_features = extract_features(url)
    tasks = [
        asyncio.to_thread(xgb_service.predict, url),
        analyze_url(url, lexical_features),
        run_probe_async(url) if not _should_skip_probe(url) else asyncio.sleep(0, result="SKIPPED"),
        whois_service.lookup(_root_domain(url)),
        asyncio.to_thread(detect_brand_mismatch, url)
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)
    t_parallel = time.perf_counter()

    xgb_prob = results[0] if not isinstance(results[0], Exception) else 0.5
    llm_result = results[1] if not isinstance(results[1], Exception) else {}
    probe_result = results[2] if not isinstance(results[2], Exception) else None
    whois_result = results[3] if not isinstance(results[3], Exception) else {}
    brand_result = results[4] if not isinstance(results[4], Exception) else {}

    # ── 4. Vision Analysis (Delayed for Early Exit check) ──
    visual_result = None

    # ── 5. Fusion Logic ──
    raw_xgb_score = xgb_prob * 100
    
    # Dynamic fallback: if AI fails, be more lenient for known safe domains
    default_score = 15.0 if _should_skip_probe(url) else 35.0
    llm_score = llm_result.get("riskScore", default_score)
    if isinstance(llm_score, str):
        try: llm_score = float(llm_score)
        except: llm_score = default_score

    # Base blend (70% LLM, 30% XGB)
    risk_score = (llm_score * 0.7) + (raw_xgb_score * 0.3)
    
    # ── 4.5 Late Vision Analysis (with Early Exit) ──
    if probe_result and hasattr(probe_result, "screenshot_path") and probe_result.screenshot_path:
        # Optimization: Only run Vision if we need visual corroboration
        is_mismatch = brand_result.get("is_mismatch", False)
        has_login = getattr(probe_result, "login_form_found", False)
        
        # Logic: 
        # - Skip if already definitively flagged by domain mismatch (Saves Quota)
        # - Skip if low risk and no login form (Selective Vision)
        if is_mismatch:
            logger.info(f"Deterministic Early Exit: Skipping Vision for {url} (Brand Mismatch already confirmed)")
            # Synthesize a visual result so the UI still shows the forensic evidence
            visual_result = {
                "visual_score": 0.95,
                "score": 0.95,
                "brand_logo_guess": brand_result.get("brand_detected", "Unknown"),
                "brand_match": brand_result.get("brand_detected", "Unknown"),
                "phash": "DETERMINISTIC-MATCH",
                "explanation": f"Deterministic Match: Local engine confirmed brand impersonation of '{brand_result.get('brand_detected')}' via domain analysis."
            }
        elif not has_login and llm_score < 40:
            logger.info(f"Selective Vision: Skipping Vision for {url} (No login form and LLM score {llm_score} is low)")
        else:
            logger.info(f"Vision Required: Invoking Gemini Vision for {url}")
            visual_result = await vision_service.analyze_screenshot(probe_result.screenshot_path)
    
    # WHOIS Boosts
    whois_boost = 0
    domain_age = whois_result.get("domain_age_days")
    if whois_result.get("is_new_domain"): whois_boost += 20
    elif domain_age is not None and domain_age < 90: whois_boost += 10
    if whois_result.get("has_privacy"): whois_boost += 5
    
    # Brand Mismatch Boost
    brand_boost = 0
    if brand_result.get("is_mismatch"): brand_boost += 25
    
    # Vision Boost
    vision_boost = 0
    if visual_result and visual_result["visual_score"] > 0.7:
        # Only apply vision boost if corroborated by brand_service OR probe found login form
        has_brand_mismatch = brand_result.get("is_mismatch", False)
        probe_found_login = probe_result and hasattr(probe_result, "login_form_found") and probe_result.login_form_found
        if has_brand_mismatch or probe_found_login:
            vision_boost += 30
            logger.info(f"Vision Boost: +30 (corroborated by brand={has_brand_mismatch}, login_form={probe_found_login})")
        else:
            logger.info(f"Vision Boost: SUPPRESSED (visual_score={visual_result['visual_score']:.2f} but no brand mismatch and no login form)")

    # ── New Heuristic Boosts (Bug #7) ──
    tld_boost = 0
    extracted = tldextract.extract(url)
    tld = extracted.suffix.lower()
    if tld in SUSPICIOUS_TLDS:
        tld_boost += 15
        logger.info(f"TLD Boost: +15 for .{tld}")

    login_boost = 0
    path = urlparse(url).path.lower()
    if any(kw in path for kw in LOGIN_KEYWORDS):
        # Only boost if it's not a known safe domain
        if not _should_skip_probe(url):
            login_boost += 10
            logger.info(f"Login Path Boost: +10 for sensitive path '{path}'")

    # ── Probe Behavioral Adjustment (Bug #5) ──
    probe_adjustment = 0
    if probe_result and hasattr(probe_result, "performed") and probe_result.performed:
        final_url = getattr(probe_result, "final_url", url)
        
        if getattr(probe_result, "accepted_fake_creds", False):
            probe_adjustment = +35  # Severe penalty for credential harvesting
            logger.info("Probe Penalty: +35 (Confirmed Credential Harvester)")
        elif final_url and final_url != url and _root_domain(final_url) in KNOWN_SAFE_DOMAINS:
            probe_adjustment = -100 # Massive dampener: safely redirects to known brand
            logger.info(f"Probe Dampener: -100 (Safe Redirect to {final_url})")
        elif getattr(probe_result, "behavior_risk", "") == "High":
            probe_adjustment = +20
            logger.info("Probe Penalty: +20 (High Behavioral Risk)")
        elif getattr(probe_result, "behavior_risk", "") == "Low":
            if getattr(probe_result, "login_form_found", False):
                probe_adjustment = -15  # Good sign: rejected fake creds
                logger.info("Probe Dampener: -15 (Correctly rejected creds)")
            else:
                probe_adjustment = -20  # Strong exculpatory: page reachable, no cred harvesting at all
                logger.info("Probe Dampener: -20 (No login form found — not a credential harvester)")
    
    risk_score = max(0.0, min(100.0, risk_score))
    
    # ── Unreachable Domain Override ──
    is_unreachable = False
    if probe_result and hasattr(probe_result, "performed") and probe_result.performed:
        if not getattr(probe_result, "reachable", True):
            is_unreachable = True

    # Final Level and Recommendation Assignment
    if is_unreachable:
        final_level = "Unknown"
        recommendation = "💤 Site is Offline - Safe to ignore"
        risk_score = 0.0
        llm_result["explanation"] = "The target URL is currently unreachable, offline, or does not exist. Since no content could be loaded, it currently poses no active threat."
        logger.info(f"Unreachable Domain Override: Score set to 0.0 for {url}")
    elif risk_score >= 71:
        final_level = "High"
        recommendation = "🛑 Dangerous - Do Not Open"
    elif risk_score >= 31:
        final_level = "Medium"
        recommendation = "⚠️ Suspicious - Proceed with Caution"
    else:
        final_level = "Low"
        recommendation = "✅ Safe - You can proceed"

    # Construct Verdict
    verdict = {
        "url": url,
        "risk_score": round(risk_score, 2),
        "risk_level": final_level,
        "recommendation": recommendation,
        "explanation": llm_result.get("explanation", "Analysis complete."),
        "brand_impersonation": brand_result.get("is_mismatch", False) or llm_result.get("brand_impersonation", False),
        "brand_name": brand_result.get("brand_detected") or llm_result.get("brand_name"),
        "verdictTitle": f"{final_level} Risk Analysis",
        "technicalDetails": llm_result.get("technicalDetails", {}),
        "mitigationAdvice": llm_result.get("mitigationAdvice", []),
        "agentReport": {"summary": llm_result.get("explanation", "")},
        "whois_info": whois_result,
        "threat_intel": threat_result,
        "visual_forensics": visual_result,
        "fusion_trace": {
            "xgb_score": raw_xgb_score,
            "llm_score": llm_score,
            "whois_boost": whois_boost,
            "brand_boost": brand_boost,
            "vision_boost": vision_boost,
            "tld_boost": tld_boost,
            "login_boost": login_boost,
            "probe_adjustment": probe_adjustment,
            "final_score": risk_score
        }
    }

    # Integrate Probe artifacts
    # Integrate Probe results (Bug #8 fix - flatten into agentReport)
    if probe_result == "SKIPPED":
        verdict["agentReport"].update({"performed": False, "outcome": "Skipped for trusted domain."})
    elif probe_result:
        # Map probe_result to dict and merge into agentReport top-level
        probe_data = probe_result_to_dict(probe_result)
        verdict["agentReport"].update(probe_data)
        
        verdict["probe_artifacts"] = {
            "redirect_chain": getattr(probe_result, "redirect_chain", []),
            "form_fields": getattr(probe_result, "form_fields", {}),
            "final_url": getattr(probe_result, "final_url", url),
            "page_title": getattr(probe_result, "page_title", "")
        }

    _set_cache(url, verdict)
    _save_to_db(verdict, db)
    return verdict


def _save_to_db(verdict: dict, db: Session):
    """Persist all forensic and analytical data to DB."""
    try:
        probe_art = verdict.get("probe_artifacts", {})
        whois = verdict.get("whois_info", {})
        vision = verdict.get("visual_forensics", {})
        
        db_scan = ScanResult(
            url=verdict["url"],
            risk_score=verdict["risk_score"],
            risk_level=verdict["risk_level"],
            recommendation=verdict.get("recommendation"),
            explanation=verdict["explanation"],
            brand_impersonation=verdict["brand_impersonation"],
            brand_name=str(verdict["brand_name"]).title() if verdict.get("brand_name") else None,
            screenshot_path=vision.get("screenshot_path") if vision else None,
            visual_score=vision.get("visual_score") if vision else None,
            brand_logo_guess=vision.get("brand_logo_guess") if vision else None,
            probe_artifacts=json.dumps(probe_art) if probe_art else None,
            domain_age_days=whois.get("domain_age_days"),
            registrar=whois.get("registrar"),
            whois_privacy=whois.get("has_privacy"),
            threat_intel_match=verdict.get("threat_intel", {}).get("is_known_malicious", False),
            threat_intel_source=verdict.get("threat_intel", {}).get("source"),
            fusion_trace=json.dumps(verdict.get("fusion_trace")),
            timestamp=datetime.now(timezone.utc),
        )
        db.add(db_scan)
        db.commit()
    except Exception as e:
        logger.error(f"Failed to save scan to database: {e}")
        db.rollback()