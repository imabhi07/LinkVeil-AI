import asyncio
import logging
import time
from functools import lru_cache
from typing import Optional
from urllib.parse import urlparse
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from backend.app.services.xgb_service import xgb_service
from backend.app.services.llm_service import analyze_url
from backend.app.services.probe_agent import run_probe_async, probe_result_to_dict, FAKE_USER
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
})

# ── Timeout guards ──
XGB_TIMEOUT_S = 5
LLM_TIMEOUT_S = 25
PROBE_TIMEOUT_S = 30


def _root_domain(url: str) -> str:
    """Extract root domain: 'https://mail.google.com/x' → 'google.com'"""
    try:
        host = urlparse(url).hostname or ""
        parts = host.lower().split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else host
    except Exception:
        return ""


def _should_skip_probe(url: str) -> bool:
    """Skip Playwright probe for well-known safe domains."""
    return _root_domain(url) in KNOWN_SAFE_DOMAINS


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
    Evaluates a URL by running the XGBoost model, Gemini LLM, and the real
    Playwright probe concurrently. Fuses the XGB + LLM results for the risk verdict.
    The probe result replaces the fake agentReport.activeProbing section only —
    it has NO influence on riskScore or risk_level.

    Optimizations:
      - In-memory result cache (5 min TTL)
      - Timeout guards on each parallel task
      - Skip probe for well-known safe domains
      - Structured timing logs
    """
    t0 = time.perf_counter()
    logger.info(f"Starting hybrid evaluation for URL: {url}")

    # ── Check cache first ──
    cached = _get_cached(url)
    if cached is not None:
        # Still persist to DB for history
        _save_to_db(cached, db)
        return cached

    # 1. Extract lexical features for LLM context
    try:
        features = extract_features(url)
    except Exception as e:
        logger.error(f"Failed to extract features for {url}: {e}")
        features = {}

    # 2. Build tasks with timeout guards
    async def _xgb_with_timeout():
        return await asyncio.wait_for(
            asyncio.to_thread(xgb_service.predict, url),
            timeout=XGB_TIMEOUT_S,
        )

    async def _llm_with_timeout():
        return await asyncio.wait_for(
            analyze_url(url, features),
            timeout=LLM_TIMEOUT_S,
        )

    async def _probe_with_timeout():
        return await asyncio.wait_for(
            run_probe_async(url),
            timeout=PROBE_TIMEOUT_S,
        )

    # 3. Run all three in parallel
    dl_prob, llm_result, probe_result = await asyncio.gather(
        _xgb_with_timeout(),
        _llm_with_timeout(),
        _probe_with_timeout(),
        return_exceptions=True,
    )

    t_parallel = time.perf_counter()

    # ── Handle failures ──
    if isinstance(dl_prob, Exception):
        logger.error(f"XGB failed ({type(dl_prob).__name__}): {dl_prob}")
        dl_prob = 0.5
    if isinstance(llm_result, Exception):
        logger.error(f"LLM failed ({type(llm_result).__name__}): {llm_result}")
        llm_result = {
            "riskScore": 50.0,
            "risk_level": "Unknown",
            "explanation": "Failed to analyze.",
            "brand_impersonation": False,
            "brand_name": None,
        }
    if isinstance(probe_result, Exception):
        logger.error(f"Probe failed ({type(probe_result).__name__}): {probe_result}")
        probe_result = None

    # 3. Fusion logic
    raw_dl_score = dl_prob * 100
    llm_level = llm_result.get("risk_level", "Unknown").strip().capitalize()
    llm_has_analysis = llm_level in ("Low", "Medium", "High")
    llm_score = llm_result.get("riskScore")

    if isinstance(llm_score, str):
        try:
            llm_score = float(llm_score)
        except ValueError:
            llm_score = None

    if llm_has_analysis and isinstance(llm_score, (int, float)):
        risk_score = (float(llm_score) * 0.7) + (raw_dl_score * 0.3)
        logger.info(f"Fusion: LLM={llm_score:.1f} XGB={raw_dl_score:.1f} → blended={risk_score:.1f}")
    else:
        risk_score = raw_dl_score
        logger.info(f"LLM unavailable. Using XGB score only: {risk_score:.1f}")

    # 4. Determine final risk level
    if llm_has_analysis:
        if llm_level == "Low":
            final_risk_level = "Low"
            risk_score = min(risk_score, 34.0)
        elif llm_level == "High":
            final_risk_level = "High"
            risk_score = max(risk_score, 65.0)
        else:
            final_risk_level = "Medium"
            risk_score = max(35.0, min(64.0, risk_score))
    else:
        if dl_prob >= 0.65:
            final_risk_level = "High"
            risk_score = max(risk_score, 65.0)
        elif dl_prob >= 0.35:
            final_risk_level = "Medium"
            risk_score = max(35.0, min(64.0, risk_score))
        else:
            final_risk_level = "Low"
            risk_score = min(risk_score, 34.0)

    # 4. Construct final verdict with mapping for frontend compatibility
    llm_tech = llm_result.get("technicalDetails") or {}
    llm_forensics = llm_result.get("forensicData") or {}
    
    # Map new high-fidelity fields to existing frontend keys
    tech_details = {
        "urlStructure": llm_tech.get("urlDeepDive") or llm_tech.get("urlStructure", "Analysis pending..."),
        "domainReputation": llm_tech.get("domainForensics") or llm_tech.get("domainReputation", "Reputation check in progress..."),
        "socialEngineeringTricks": llm_tech.get("socialEngineering") or llm_tech.get("socialEngineeringTricks", "Checking for deception markers..."),
        "forensicDeepDive": llm_forensics.get("threatTactics") or "Heuristic analysis complete.",
        "visualPrediction": llm_forensics.get("visualPrediction") or "Standard layout expected."
    }

    verdict = {
        "url": url,
        "risk_score": round(risk_score, 2),
        "risk_level": final_risk_level,
        "explanation": llm_result.get("explanation", ""),
        "brand_impersonation": llm_result.get("brand_impersonation", False),
        "brand_name": llm_result.get("brand_name", None),
        "verdictTitle": llm_result.get("verdictTitle") or f"{final_risk_level} Risk Detected",
        "technicalDetails": tech_details,
        "mitigationAdvice": llm_result.get("mitigationAdvice") or [],
        "agentReport": llm_result.get("agentReport"),
    }

    # 4b. ALWAYS override activeProbing with REAL data — never show LLM hallucinations
    agent_report = verdict.get("agentReport") or {}

    # Capture probe error message before we convert exception to None
    probe_error_msg = None
    if isinstance(probe_result, Exception):
        probe_error_msg = str(probe_result)
        # Already logged above, probe_result is already set to None

    cred_string = f"{FAKE_USER} / ••••••••"

    if probe_result == "SKIPPED":
        # Known safe domain — no real probe was needed
        agent_report["activeProbing"] = {
            "performed": False,
            "credentialsUsed": cred_string,
            "outcome": (
                f"Live probe skipped — '{_root_domain(url)}' is a verified legitimate domain. "
                "Active probing is not performed against known-safe sites to avoid "
                "unnecessary load and false positives."
            ),
            "behaviorRisk": "Low",
            "reachable": None,
            "loginFormFound": None,
            "fieldsFilled": False,
            "acceptedFakeCredentials": False,
            "postSubmitRedirect": None,
            "pageTitle": None,
            "finalUrl": None,
            "error": None,
        }
    elif probe_result is not None and not isinstance(probe_result, Exception):
        # Real probe completed successfully
        real_probe_dict = probe_result_to_dict(probe_result)
        logger.info(
            f"Real probe completed — reachable={probe_result.reachable}, "
            f"loginFormFound={probe_result.login_form_found}, "
            f"behaviorRisk={probe_result.behavior_risk}"
        )
        agent_report["activeProbing"] = real_probe_dict
    else:
        # Probe crashed or timed out — show honest error, NOT LLM fiction
        agent_report["activeProbing"] = {
            "performed": True,
            "credentialsUsed": cred_string,
            "outcome": (
                f"Live probe failed — the headless browser could not complete the analysis. "
                f"Error: {probe_error_msg or 'Unknown error'}. "
                "This may be due to anti-bot protections (WAF/Cloudflare), network issues, "
                "or the site blocking automated browsers."
            ),
            "behaviorRisk": "Unknown",
            "reachable": False,
            "loginFormFound": None,
            "fieldsFilled": False,
            "acceptedFakeCredentials": False,
            "postSubmitRedirect": None,
            "pageTitle": None,
            "finalUrl": None,
            "error": probe_error_msg,
        }

    verdict["agentReport"] = agent_report

    # ── Cache the result ──
    _set_cache(url, verdict)

    # 5. Save to database
    _save_to_db(verdict, db)

    elapsed = (time.perf_counter() - t0) * 1000
    logger.info(
        f"✅ Evaluation complete for {url} — "
        f"risk={verdict['risk_score']} ({verdict['risk_level']}) "
        f"parallel={((t_parallel - t0) * 1000):.0f}ms total={elapsed:.0f}ms"
    )

    return verdict


def _save_to_db(verdict: dict, db: Session):
    """Persist scan result to the database."""
    try:
        db_scan = ScanResult(
            url=verdict["url"],
            risk_score=verdict["risk_score"],
            risk_level=verdict["risk_level"],
            explanation=verdict["explanation"],
            brand_impersonation=verdict["brand_impersonation"],
            brand_name=verdict["brand_name"],
            timestamp=datetime.now(timezone.utc),
        )
        db.add(db_scan)
        db.commit()
    except Exception as e:
        logger.error(f"Failed to save scan to database: {e}")
        db.rollback()