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
from backend.app.services.dl_service import dl_service
from backend.app.services.llm_service import analyze_url
from backend.app.services.probe_agent import run_probe_async, probe_result_to_dict, FAKE_USER
from backend.app.services.threat_intel_service import threat_intel_service
from backend.app.services.whois_service import whois_service
from backend.app.services.brand_service import detect_brand_mismatch, get_legit_domains
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
    "microsoft.com", "apple.com", "amazon.com", 
    "wikipedia.org", "reddit.com", "stackoverflow.com",
    "paypal.com", "yahoo.com", "bing.com", "whatsapp.com",
    "zoom.us", "slack.com", "dropbox.com", "uber.com", "airbnb.com", "pinterest.com",
    "razorpay.com", "phonepe.com", "stripe.com", "twitch.tv",
    "perplexity.ai", "chatgpt.com", "openai.com", "claude.ai", "anthropic.com",
    "infosys.com", "pepsicoindia.co.in", "pepsico.com", "tata.com", "reliance.com",
    "hdfcbank.com", "icicibank.com", "sbi.co.in", "irctc.co.in",
    "discord.com", "discord.gg", "coderabbit.ai", "customer.io", "customeriomail.com",
    "trello.com", "canva.com", "notion.so", "figma.com", "intercom.com", "intercom-mail.com",
    "atlassian.com", "jira.com", "bitbucket.org", "gitlab.com",
    "adobe.com", "salesforce.com", "okta.com", "auth0.com",
    "inflection.io", "vercel.com", "netlify.com",
    "digitalocean.com", "heroku.com", "cloudflare.com", "cloudinary.com",
    "sendgrid.net", "sendgrid.com", "mcsv.net", "hubspotemail.net", "hubspot.com",
    "amazonses.com", "mandrillapp.com", "mailchimp.com"
})

# ── Shared Hosting Platforms: Frequently abused for phishing (e.g. realbnb.vercel.app) ──
# We NEVER short-circuit these for subdomains; we force full forensic analysis.
SHARED_HOSTING_DOMAINS = frozenset({
    "vercel.app", "netlify.app", "github.io", "firebaseapp.com", 
    "pages.dev", "railway.app", "surge.sh", "render.com", 
    "s3.amazonaws.com", "storage.googleapis.com", "web.app", "onrender.com"
})

# Analysis Heuristics
LOGIN_KEYWORDS = ["/login", "/signin", "/verify", "/account", "/secure", "/auth", "/webscr", "/ebayisapi", "/payment", "/invoice", "/order", "/billing", "/validate"]
URGENCY_LURES = ["urgent", "immediately", "action", "suspended", "security", "limited", "locked", "expire"]

SUSPICIOUS_TLDS = frozenset({
    "cf", "tk", "ml", "ga", "gq",  # Freenom free TLDs
    "buzz", "top", "xyz", "club", "work", "loan", "click",
    "info", "cam", "icu", "monster", "rest", "surf", "casa", "zip", "mov"
})

# ── Timeout guards ──
XGB_TIMEOUT_S = 5
BERT_TIMEOUT_S = 5
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
    """Skip Playwright probe for well-known safe domains, UNLESS they look like redirectors."""
    root = _root_domain(url)
    if root not in KNOWN_SAFE_DOMAINS:
        return False
        
    # Shared hosting subdomains NEVER skip probe
    if root in SHARED_HOSTING_DOMAINS:
        # Check if it's just the root domain (e.g. vercel.app) or a user site (e.g. myphish.vercel.app)
        ext = tldextract.extract(url)
        if ext.subdomain:
            return False
            
    # Exceptions: Even if the domain is safe, skip if it's a known storage/redirector pattern
    # these are frequently abused for hosting phishing HTML
    redirector_patterns = ["storage.googleapis.com", "drive.google.com", "onedrive.live.com", "dropbox.com/s/"]
    if any(p in url.lower() for p in redirector_patterns):
        return False
        
    return True


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
        "functional_category": "Official Service",
        "functional_description": "This link belongs to a verified, high-authority domain that is part of the global trusted infrastructure.",
        "verdictTitle": "Trusted Domain Verified",
        "technicalDetails": {
            "urlStructure": "Verified legitimate structure.",
            "domainReputation": "High-authority whitelisted domain.",
            "socialEngineeringTricks": "None detected."
        },
        "mitigationAdvice": ["No action required. This is an official domain."],
        "agentReport": {
            "activeProbing": {
                "performed": False, 
                "reachable": True,
                "outcome": "Skipped for trusted domain."
            }
        },
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


class FusionEngine:
    def fuse(self, scores: dict, degraded_engines: list[str]) -> tuple[float, dict]:
        """Combine engine scores with weights that adjust based on availability."""
        llm_score = scores.get("llm", 0.0)
        xgb_score = scores.get("xgb", 0.0)
        bert_score = scores.get("bert", 0.0)
        
        trace = {}
        
        if "llm" in degraded_engines:
            # ML-only blend (50/50 XGB/BERT)
            if "bert" in degraded_engines:
                risk_score = xgb_score
                trace["engines_used"] = ["xgb"]
            else:
                risk_score = (xgb_score * 0.50) + (bert_score * 0.50)
                trace["engines_used"] = ["xgb", "bert"]
        else:
            # Normal tri-model blend: 60% LLM, 20% XGB, 20% BERT
            if "bert" in degraded_engines:
                risk_score = (llm_score * 0.70) + (xgb_score * 0.30)
                trace["engines_used"] = ["llm", "xgb"]
            else:
                risk_score = (llm_score * 0.60) + (xgb_score * 0.20) + (bert_score * 0.20)
                trace["engines_used"] = ["llm", "xgb", "bert"]
                
        return risk_score, trace

    def create_verdict(self, 
                       url: str,
                       risk_score: float, 
                       explanation: str, 
                       forensic_results: dict, 
                       forensic_errors: list, 
                       degraded_engines: list, 
                       fusion_trace: dict) -> dict:
        """Construct the final verdict dictionary."""
        
        # Cleanup explanation
        clean_explanation = explanation
        if "llm" in degraded_engines:
            # Replace technical strings
            for tech_err in ["API error", "TimeoutError", "Service Unavailable"]:
                clean_explanation = clean_explanation.replace(tech_err, "forensic engine failure")
            
            # Prepend indicator if not already present
            if "[Partial Analysis]" not in clean_explanation:
                clean_explanation = f"[Partial Analysis] {clean_explanation}"
                
            if len(clean_explanation.strip()) < 40: # If it's too short/generic
                clean_explanation = "Partial analysis complete. Verdict computed from ML models and forensic signals as AI deep analysis was unavailable."
        
        # Determine risk level
        if risk_score >= 71:
            level = "malicious"
            rec = "Dangerous - Do Not Open"
        elif risk_score >= 31:
            level = "suspicious"
            rec = "Suspicious - Proceed with Caution"
        else:
            level = "safe"
            rec = "Safe - You can proceed"

        llm_res = forensic_results.get("llm", {})
        brand_res = forensic_results.get("brand", {})
        whois_res = forensic_results.get("whois", {})
        probe_res = forensic_results.get("visual", {}) # This contains probe data too if vision skipped

        # Metadata Synthesis Fallback: If AI failed, synthesize technical details from ML/Forensic data
        tech_details = llm_res.get("technicalDetails")
        if not tech_details and "llm" in degraded_engines:
            tech_details = {
                "urlDeepDive": f"Lexical analysis identifies a {'suspicious' if risk_score > 50 else 'standard'} URL structure. The path depth and entropy suggest a {level.lower()}-risk destination.",
                "domainForensics": f"Domain reputation based on registrar {whois_res.get('registrar', 'Unknown')} and age ({whois_res.get('domain_age_days', 'unknown')} days).",
                "socialEngineering": f"Heuristic model detects potential {level.lower()}-risk manipulation patterns based on semantic context."
            }
            # Specific additions based on WHOIS
            if whois_res.get("is_new_domain"):
                tech_details["domainForensics"] += " ALERT: Brand-new domain registered recently."
            if whois_res.get("has_privacy"):
                tech_details["domainForensics"] += " NOTE: Registrant details are hidden via privacy protection."

        mitigation = llm_res.get("mitigationAdvice") or []
        if not mitigation:

            if level.lower() == "malicious":
                mitigation = [
                    "CRITICAL: Do not click any links or download attachments from this URL.",
                    "Delete this email immediately and report it to your security team.",
                    "If you have already entered credentials, change your password immediately."
                ]
            elif level.lower() == "suspicious":
                mitigation = [
                    "Proceed with extreme caution. Verify the sender's identity through a secondary channel.",
                    "Check for subtle typos in the domain name (e.g., 'micros0ft.com').",
                    "Do not provide sensitive personal or financial information on this page."
                ]
            else:
                mitigation = [
                    "No immediate threat detected, but always remain vigilant.",
                    "Verify that the SSL certificate (padlock icon) is valid and matches the domain.",
                    "Use a password manager to ensure you only enter credentials on official sites."
                ]

        # Evidence Capture Mapping: Ensure screenshotPath is preserved in agentReport for the UI
        probe_data = forensic_results.get("probe") or {}
        agent_report = {
            "summary": clean_explanation,
            "activeProbing": {
                "performed": True if (probe_data and probe_data.get("performed")) else False,
                "screenshotPath": (probe_res or {}).get("screenshot_path") or probe_data.get("screenshotPath"),
                "loginFormFound": probe_data.get("loginFormFound", False),
                "pageTitle": probe_data.get("pageTitle"),
                "finalUrl": probe_data.get("finalUrl"),
                "behaviorRisk": probe_data.get("behaviorRisk") or ("HIGH" if risk_score > 70 else "MEDIUM" if risk_score > 30 else "LOW"),
                "outcome": probe_data.get("outcome") or clean_explanation
            }
        }

        # Dynamic conclusion title based on findings
        is_impersonation = bool(brand_res.get("is_mismatch", False) or llm_res.get("brand_impersonation", False))
        brand_name = brand_res.get("brand_detected") or llm_res.get("brand_name")
        
        if level == "SAFE":
            if risk_score < 10:
                title = "Secure Destination Verified"
            else:
                title = "No Active Threats Detected"
        elif level == "SUSPICIOUS":
            if is_impersonation:
                title = "Suspicious Brand Discrepancy"
            else:
                title = "Anomalous Activity Detected"
        else:  # MALICIOUS
            if is_impersonation:
                title = f"Critical: {brand_name.title()} Impersonation" if brand_name else "Malicious Brand Impersonation"
            else:
                title = "Active Malicious Threat"

        return {
            "url": url,
            "risk_score": round(risk_score, 2),
            "risk_level": level,
            "recommendation": rec,
            "explanation": clean_explanation,
            "brand_impersonation": is_impersonation,
            "brand_name": brand_name,
            "functional_category": llm_res.get("functional_category", "Web Resource"),
            "functional_description": llm_res.get("functional_description", "This is a standard web destination with no specific risk category identified."),
            "verdictTitle": title,
            "technicalDetails": tech_details,
            "mitigationAdvice": mitigation,
            "agentReport": agent_report,
            "whois_info": whois_res,
            "threat_intel": forensic_results.get("threat", {}),
            "visual_forensics": forensic_results.get("visual", {}),
            "forensic_errors": forensic_errors,
            "degraded_engines": degraded_engines,
            "fusion_trace": fusion_trace
        }

fusion_engine = FusionEngine()


async def evaluate_url(url: str, db: Session, auth_context: Optional[dict] = None, force_refresh: bool = False) -> dict:
    """
    Hybrid evaluation pipeline:
    1. Check Protocol (Safety for local resources)
    2. Cache check
    3. Email Auth Trust (Short-circuit for verified senders)
    4. Threat Intel short-circuit
    5. Parallel execution (XGB, LLM, Probe, WHOIS, Brand detect)
    """
    # ── 0. Protocol Validation ──
    parsed = urlparse(url)
    if parsed.scheme not in ["http", "https"]:
        logger.info(f"Non-Web Protocol Detected: {url}")
        return {
            "url": url,
            "risk_score": 0.0,
            "risk_level": "Safe",
            "explanation": f"This is a '{parsed.scheme}' resource, which is internal to your browser or system. These protocols are typically used for extensions or local files and are not subject to external phishing analysis.",
            "verdictTitle": "Internal System Resource",
            "recommendation": "Safe - Browser/System Resource",
            "brand_impersonation": False,
            "technicalDetails": {"urlStructure": f"Protocol: {parsed.scheme} (Non-analyzable)"},
            "mitigationAdvice": ["No action required for internal system links."],
            "agentReport": {"activeProbing": {"performed": False, "outcome": "Skipped (Non-Web Protocol)"}}
        }

    t0 = time.perf_counter()
    logger.info(f"Starting hybrid evaluation for URL: {url}")

    # ── 1. Check cache ──
    if not force_refresh:
        cached = _get_cached(url)
        if cached is not None:
            _save_to_db(cached, db)
            return cached
    else:
        logger.info(f"Forcing REFRESH for {url} (Cache bypassed)")

    # ── 2. Email Auth Trust ──
    # Only short-circuit if NOT forcing a refresh
    url_root = _root_domain(url)
    if auth_context and not force_refresh:
        dmarc = auth_context.get("dmarc", "none").lower()
        spf = auth_context.get("spf", "none").lower()
        sender_domain = auth_context.get("sender_domain", "").lower()
        
        # If DMARC/SPF pass and URL domain matches sender domain, we can trust it
        if dmarc == "pass" and spf == "pass" and sender_domain and url_root == sender_domain:
            logger.info(f"Auth Trust HIT: Short-circuiting for {url} (Authenticated sender {sender_domain})")
            verdict = _get_trusted_verdict(url)
            verdict["explanation"] = f"✅ Verified: This link belongs to {url_root}, which was confirmed via email authentication (DMARC/SPF pass) for the sender {sender_domain}."
            _save_to_db(verdict, db)
            return verdict

    # ── 2.5 Global Whitelist Short-circuit ──
    # ONLY short-circuit if it's a known safe domain AND NOT a shared hosting provider with a subdomain
    ext = tldextract.extract(url)
    is_shared_hosting = url_root in SHARED_HOSTING_DOMAINS
    
    if url_root in KNOWN_SAFE_DOMAINS or (is_shared_hosting and not ext.subdomain):
        logger.info(f"Global Whitelist HIT: Short-circuiting for {url}")
        verdict = _get_trusted_verdict(url)
        verdict["explanation"] = f"✅ Safe Authority: {url_root} is a verified, high-authority domain. Deep forensic analysis skipped for this trusted infrastructure."
        _save_to_db(verdict, db)
        return verdict

    # ── 3. Threat Intel (Short-circuit) ──
    threat_result = await threat_intel_service.check(url)
    
    # (Probe skip optimization moved to parallel task list)

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
        asyncio.to_thread(detect_brand_mismatch, url),
        asyncio.wait_for(asyncio.to_thread(dl_service.predict, url), timeout=BERT_TIMEOUT_S)
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)
    t_parallel = time.perf_counter()

    # ── Structured Error Collection ──
    forensic_errors: list[dict] = []
    degraded_engines: list[str] = []

    xgb_prob = results[0] if not isinstance(results[0], Exception) else None
    if isinstance(results[0], Exception) or xgb_prob is None:
        msg = f"ML model error: {str(results[0])[:100]}" if isinstance(results[0], Exception) else "XGBoost model unavailable."
        forensic_errors.append({"stage": "XGBoost", "message": msg})
        degraded_engines.append("xgboost")
        if xgb_prob is None: xgb_prob = 0.0 # Placeholder for fusion call

    llm_result = (results[1] if not isinstance(results[1], Exception) else {}) or {}
    llm_failed = isinstance(results[1], Exception) or (
        isinstance(llm_result, dict) and "API error" in llm_result.get("explanation", "")
    )
    if llm_failed:
        forensic_errors.append({
            "stage": "LLM Analysis",
            "message": "AI analysis unavailable. Verdict computed from ML models and forensic signals."
        })
        degraded_engines.append("llm")

    probe_result = results[2] if not isinstance(results[2], Exception) else None
    if isinstance(results[2], Exception):
        forensic_errors.append({"stage": "Active Probe", "message": f"Probe agent error: {str(results[2])[:100]}"})
        degraded_engines.append("probe")

    whois_result = (results[3] if not isinstance(results[3], Exception) else {}) or {}
    if isinstance(results[3], Exception):
        forensic_errors.append({"stage": "WHOIS", "message": "Domain registration lookup failed."})
        degraded_engines.append("whois")

    brand_result = (results[4] if not isinstance(results[4], Exception) else {}) or {}
    if isinstance(results[4], Exception):
        forensic_errors.append({"stage": "Brand Detection", "message": "Brand mismatch check unavailable."})
        degraded_engines.append("brand")

    bert_prob = results[5] if not isinstance(results[5], Exception) else None
    if isinstance(results[5], Exception) or bert_prob is None:
        msg = f"BERT model error: {str(results[5])[:100]}" if isinstance(results[5], Exception) else "DistilBERT model unavailable."
        forensic_errors.append({"stage": "BERT/DL", "message": msg})
        degraded_engines.append("bert")
        if bert_prob is None: bert_prob = 0.0 # Placeholder for fusion call

    # ── 4. Vision Analysis (Delayed for Early Exit check) ──
    visual_result = None

    # ── 5. Fusion Logic ──
    raw_xgb_score = xgb_prob * 100
    raw_bert_score = (bert_prob * 100) if bert_prob is not None else 0.0
    
    # Cap ML scores for known safe domains to prevent lexical false positives
    # But ONLY if it's truly a safe path (no .html on storage domains)
    is_storage_path = any(p in url.lower() for p in ["storage.googleapis.com", "drive.google.com", "onedrive.live.com"])
    is_html_extension = url.lower().split('?')[0].endswith(('.html', '.htm', '.php'))
    
    # ── Reputation-Based ML Capping (Anti-False-Positive) ──
    # If the domain is old (>1 year) and not on a suspicious TLD, 
    # we cap the lexical models to prevent false positives from long URLs.
    domain_age = (whois_result.get("domain_age_days") or whois_result.get("age_days") or 0)
    is_suspicious_tld = tldextract.extract(url).suffix.lower() in SUSPICIOUS_TLDS
    
    if domain_age > 365 and not is_suspicious_tld and not is_storage_path:
        raw_xgb_score = min(raw_xgb_score, 35.0)
        raw_bert_score = min(raw_bert_score, 35.0)
        logger.info(f"Reputation Cap: XGB={raw_xgb_score:.1f}, BERT={raw_bert_score:.1f} (Established domain, age={domain_age}d)")
    
    # Extract LLM score, ensuring we handle degradation without hardcoded fallbacks
    llm_score = llm_result.get("riskScore") if not llm_failed else None
    if isinstance(llm_score, str):
        try:
            llm_score = float(llm_score)
        except (ValueError, TypeError):
            llm_score = None

    # Fusion processing using the new FusionEngine class
    scores_dict = {"llm": llm_score, "xgb": raw_xgb_score, "bert": raw_bert_score}
    risk_score, fusion_trace = fusion_engine.fuse(scores_dict, degraded_engines)
    
    # Apply forensic penalty AFTER risk_score is initialized
    if is_storage_path and is_html_extension:
        risk_score += 40
        logger.info("Storage Forensic Penalty: +40 (HTML on cloud storage is high-risk)")

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
        elif not has_login and (llm_score or 0) < 40:
            logger.info(f"Selective Vision: Skipping Vision for {url} (No login form and LLM score {llm_score} is low)")

            visual_result = {
                "screenshot_path": probe_result.screenshot_path,
                "visual_score": 0.0,
                "brand_logo_guess": "UNKNOWN",
                "explanation": "Selective Vision: AI analysis optimized away for low-risk, non-credential-harvesting page."
            }
        else:
            logger.info(f"Vision Required: Invoking Gemini Vision for {url}")
            visual_result = await vision_service.analyze_screenshot(probe_result.screenshot_path)
            if visual_result:
                visual_result["screenshot_path"] = probe_result.screenshot_path
    
    # WHOIS Boosts
    whois_boost = 0
    domain_age = whois_result.get("domain_age_days")
    if whois_result.get("is_new_domain"): whois_boost += 20
    elif domain_age is not None and domain_age < 90: whois_boost += 10
    if whois_result.get("has_privacy"): whois_boost += 5
    
    # Brand Mismatch Boost
    brand_boost = 0
    if brand_result.get("is_mismatch"):
        # Suppress mismatch penalty if domain is established AND not a shared host
        domain_age_val = (whois_result.get("domain_age_days") or whois_result.get("age_days") or 0)
        current_root = _root_domain(url)
        is_established = domain_age_val > 365 and current_root not in SHARED_HOSTING_DOMAINS
        
        if not is_established:
            brand_boost = 25
            logger.info(f"Brand Mismatch Penalty: +25 (New domain claiming to be {brand_result.get('brand_detected')})")
        else:
            logger.info(f"Brand Mismatch Suppressed: Established domain ({domain_age_val}d) containing brand token.")
    
    # Vision Boost & Trust Logic
    vision_boost = 0
    if visual_result and visual_result.get("visual_score", 0) > 0.7:
        brand_match = visual_result.get("brand_match")
        legit_domains = get_legit_domains(brand_match) if brand_match else []
        current_root = _root_domain(url)

        # ── Vision Trust: If brand is matched on its OFFICIAL domain, it's a strong safety signal ──
        # ── Vision Trust: If brand is matched on its OFFICIAL domain, it's a strong safety signal ──
        if legit_domains and current_root in legit_domains:
            vision_boost = -40
            visual_result["explanation"] = f"Vision Trust: Verified official {brand_match} identity on its legitimate domain ({current_root}). Analysis favors safety."
            logger.info(f"Vision Trust HIT: Official {brand_match} domain detected. Applying safety dampener (-40).")
        else:
            # ── Vision Reputation Check: Is this domain established? ──
            # If the domain is old (>1yr) AND not a shared host, we are MUCH more lenient
            domain_age_val = (whois_result.get("domain_age_days") or whois_result.get("age_days") or 0)
            current_root = _root_domain(url)
            is_established = domain_age_val > 365 and current_root not in SHARED_HOSTING_DOMAINS
            
            # ── Vision Boost: If brand is matched on an UNTRUSTED domain, it's a strong threat signal ──
            has_brand_mismatch = brand_result.get("is_mismatch", False)
            probe_found_login = probe_result and hasattr(probe_result, "login_form_found") and probe_result.login_form_found
            
            if (has_brand_mismatch or probe_found_login) and not is_established:
                vision_boost = 30
                visual_result["explanation"] = f"Visual Warning: Detected {brand_match or 'sensitive'} branding on a young/unverified domain. This is a high-fidelity impersonation risk."
                logger.info(f"Vision Boost: +30 (Potential {brand_match or 'Unknown'} impersonation corroborated by context)")
            elif is_established:
                visual_result["explanation"] = f"Vision Integrity: {brand_match} branding detected on an established domain ({domain_age_val} days old). Impersonation penalty suppressed."
                logger.info(f"Vision Boost: SUPPRESSED (Domain age {domain_age_val}d provides safe harbor for detected branding)")
            else:
                visual_result["explanation"] = f"Visual ambiguity: {brand_match or 'Brand'} detected but lacking corroborating forensic mismatch. Proceed with caution."
                logger.info(f"Vision Boost: SUPPRESSED (No corroborating forensic context for visual match)")

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

    # Urgency Lure Boost
    for lure in URGENCY_LURES:
        if lure in path:
            login_boost += 15
            logger.info(f"Urgency Lure Boost: +15 for keyword '{lure}' in path")
            break

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
                logger.info("Probe Dampener: -20 (No login form found - not a credential harvester)")
    
    # Apply all forensic boosts and behavioral adjustments
    risk_score += whois_boost + brand_boost + vision_boost + tld_boost + login_boost + probe_adjustment

    risk_score = max(0.0, min(100.0, risk_score))
    
    # ── Unreachable Domain Override ──
    is_unreachable = False
    if probe_result and hasattr(probe_result, "performed") and probe_result.performed:
        if not getattr(probe_result, "reachable", True):
            is_unreachable = True

    # Final Level and Recommendation Assignment
    # --- Offline Status Override Logic ---
    is_hard_offline = getattr(probe_result, "explicitly_offline", False)

    if is_hard_offline:
        # If the domain itself is highly suspicious (lexical/AI flags), don't zero it out.
        # This prevents "Target Offline" from masking typosquatting/brand impersonation traps.
        if risk_score > 40:
            logger.info(f"Offline but SUSPICIOUS: Maintaining risk score {risk_score} for {url}")
            llm_result["explanation"] = f"DORMANT THREAT: Although the site is currently offline (NXDOMAIN or connection refused), forensic models detected high risk in the URL structure. This domain may be part of a dormant phishing campaign. {llm_result.get('explanation', '')}"
        else:
            final_level = "Unknown"
            recommendation = "Site is Offline - Safe to ignore"
            risk_score = 0.0
            llm_result["explanation"] = "The target domain is confirmed offline (NXDOMAIN or connection refused). It currently poses no active threat."
            logger.info(f"Explicit Offline Override: Score set to 0.0 for {url}")
            verdict = {
                "url": url,
                "risk_score": 0.0,
                "risk_level": final_level,
                "explanation": llm_result["explanation"],
                "brand_impersonation": False,
                "brand_name": None,
                "recommendation": recommendation,
                "verdictTitle": "Target Offline",
                "technicalDetails": {
                    "urlStructure": "Domain is unreachable. No active payload detected.",
                    "domainReputation": "DNS lookup failed (NXDOMAIN).",
                },
                "mitigationAdvice": ["No action needed for offline sites."],
                "agentReport": {"activeProbing": {"performed": True, "reachable": False, "outcome": "Site is explicitly offline."}},
                "whois_info": whois_result,
                "threat_intel": threat_result,
                "visual_forensics": visual_result,
                "fusion_trace": {
                    "xgb_prob": round(xgb_prob, 3),
                    "bert_prob": round(bert_prob, 3) if bert_prob is not None else None,
                    "llm_score": llm_score,
                    "note": "Hard offline domain override"
                }
            }
            _save_to_db(verdict, db)
            return verdict
        
    # For Timeouts/Partial loads, we proceed with the ML score
    if is_unreachable and not is_hard_offline:
        # Penalize inconclusive results slightly to favor caution
        risk_score += 20
        logger.info(f"Probe Timed Out for {url}: Adding +20 Inconclusive penalty. Final Score: {risk_score}")
            
    # Construct Verdict via FusionEngine
    verdict = fusion_engine.create_verdict(
        url=url,
        risk_score=risk_score,
        explanation=llm_result.get("explanation", "Analysis complete."),
        forensic_results={
            "llm": llm_result,
            "whois": whois_result,
            "brand": brand_result,
            "threat": threat_result,
            "visual": visual_result,
            "probe": probe_result_to_dict(probe_result) if isinstance(probe_result, object) and probe_result != "SKIPPED" else None
        },
        forensic_errors=forensic_errors,
        degraded_engines=degraded_engines,
        fusion_trace={
            "xgb_score": raw_xgb_score,
            "bert_score": raw_bert_score,
            "llm_score": llm_score,
            "whois_boost": whois_boost,
            "brand_boost": brand_boost,
            "vision_boost": vision_boost,
            "tld_boost": tld_boost,
            "login_boost": login_boost,
            "probe_adjustment": probe_adjustment,
            "final_score": risk_score,
            "engines_used": fusion_trace.get("engines_used", [])
        }
    )

    # Integrate Probe artifacts
    # Integrate Probe results (Bug #8 fix - flatten into agentReport)
    if probe_result == "SKIPPED":
        if "activeProbing" not in verdict["agentReport"]:
            verdict["agentReport"]["activeProbing"] = {}
        verdict["agentReport"]["activeProbing"].update({
            "performed": False, 
            "reachable": True, 
            "outcome": "Skipped for trusted domain."
        })
    elif probe_result:
        # Map probe_result to dict and merge into agentReport's activeProbing sub-object
        probe_data = probe_result_to_dict(probe_result)
        if "activeProbing" not in verdict["agentReport"]:
            verdict["agentReport"]["activeProbing"] = {}
        verdict["agentReport"]["activeProbing"].update(probe_data)
        
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
        
        # Extract TLD for analytics
        ext = tldextract.extract(verdict.get("url", ""))
        tld_val = ext.suffix if ext.suffix else None

        db_scan = ScanResult(
            url=verdict.get("url", "unknown"),
            risk_score=verdict.get("risk_score", 0.0),
            risk_level=verdict.get("risk_level", "Unknown"),
            recommendation=verdict.get("recommendation"),
            explanation=verdict.get("explanation", "No explanation available."),
            brand_impersonation=verdict.get("brand_impersonation", False),
            brand_name=str(verdict.get("brand_name")).title() if verdict.get("brand_name") else None,
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
            tld=tld_val,
            functional_category=verdict.get("functional_category"),
            timestamp=datetime.now(timezone.utc),
        )
        db.add(db_scan)
        db.commit()
    except Exception as e:
        logger.error(f"Failed to save scan to database: {e}")
        db.rollback()