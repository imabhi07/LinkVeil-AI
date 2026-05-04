import logging
import asyncio
from urllib.parse import urlparse, parse_qs, urlencode
from fastapi import APIRouter, Depends, HTTPException, File, UploadFile
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.models.schemas import URLRequest, ScanResponse, EmailScanRequest, EmailScanResponse
from backend.app.services.engine_service import evaluate_url
from backend.app.utils.url_utils import _normalize_url, _TRACKING_PARAMS
from backend.app.features.email_features import extract_urls
from backend.app.services.email_service import analyze_email
from backend.app.services.email_parser import parse_email_from_string, parse_email_from_bytes
from backend.app.features.link_triage import triage_urls

MAX_SCAN_LINKS_PER_EMAIL = 4
SCAN_TIMEOUT = 30.0

logger = logging.getLogger(__name__)
router = APIRouter()

TRUSTED_DOMAINS = {
    "leetcode.com", "coderabbit.ai", "github.com", "google.com", 
    "microsoft.com", "apple.com", "amazon.com", "stripe.com", 
    "paypal.com", "linkedin.com", "discord.com", "slack.com", "infosys.com"
}

@router.post("/scan", response_model=ScanResponse)
async def scan_url(request: URLRequest, db: Session = Depends(get_db)):
    """
    Submits a URL to the LinkVeil XGBoost + LLM engines concurrently.
    Fuses the results via the rule engine and returns the final verdict.
    """
    url_str = _normalize_url(str(request.url))
    logger.info(f"Scan request for: {url_str}")

    try:
        verdict = await evaluate_url(url_str, db)
        return ScanResponse(**verdict)
    except Exception as e:
        logger.error(f"Engine failure for {url_str}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal engine failure: {str(e)}")

async def _execute_email_analysis(parsed_data: dict, db: Session):
    """Internal helper to run the forensics pipeline on a parsed email."""
    body = parsed_data.get("body", "")
    raw_content = parsed_data.get("raw_content", body)
    urls = extract_urls(raw_content)
    
    from_email = parsed_data.get("from_email")
    auth = parsed_data.get("auth_results", {})
    auth_pass = auth.get("spf") == "pass" or auth.get("dkim") == "pass"
    
    sender_domain = ""
    if from_email and "@" in from_email:
        sender_domain = from_email.split("@")[-1].lower()
    
    is_trusted = auth_pass and sender_domain in TRUSTED_DOMAINS

    email_analysis = analyze_email(
        subject=parsed_data.get("subject"),
        body=body,
        from_email=from_email,
        reply_to=parsed_data.get("reply_to"),
        from_name=parsed_data.get("from_name"),
        is_trusted=is_trusted
    )
    
    heuristic_score = email_analysis["heuristic_score"]
    reasons = email_analysis["reasons"]
    indicators = email_analysis["flags"]
    
    if not urls:
        risk_level = "Low"
        if heuristic_score >= 65:
            risk_level = "High"
        elif heuristic_score >= 35:
            risk_level = "Medium"
            
        return EmailScanResponse(
            email_risk_score=float(heuristic_score),
            email_risk_level=risk_level,
            reasons=reasons + ["No URLs found in email body."] if not reasons else reasons,
            suspicious_indicators=indicators,
            extracted_urls=[],
            link_results=[],
            parsed_email=parsed_data
        )

    # Triage links
    triage = triage_urls(urls, max_scan=MAX_SCAN_LINKS_PER_EMAIL, from_email=parsed_data.get("from_email"))
    to_scan = triage["to_scan"]
    skipped = triage["skipped"]
    stats = triage["stats"]
    deep_dive_target = triage["deep_dive_candidate"]
    unwrap_events = triage.get("unwrap_events", [])

    semaphore = asyncio.Semaphore(5)
    async def gated_evaluate(url):
        async with semaphore:
            try:
                # Wrap evaluate_url with a timeout to prevent hanging on external calls
                result = await asyncio.wait_for(evaluate_url(url, db), timeout=SCAN_TIMEOUT)
                return ScanResponse(**result)
            except asyncio.TimeoutError:
                logger.error(f"Scan timeout for URL {url} after {SCAN_TIMEOUT}s")
                return None
            except Exception as e:
                logger.error(f"Failed to scan URL {url} in email: {e}")
                return None

    tasks = [gated_evaluate(url) for url in to_scan]
    results = await asyncio.gather(*tasks)
    valid_results = [r for r in results if r is not None]
    
    # 404/Inconclusive Handling & Error Collection
    forensic_errors = []
    for r in valid_results:
        # Check for 404 Page Not Found
        if "404" in r.explanation or "Not Found" in r.explanation or "Page Not Found" in r.explanation:
            if r.risk_score < 70: # Only if not already definitively malicious
                r.risk_level = "INCONCLUSIVE"
                # Cap the contribution to avoid false medium
                r.risk_score = min(r.risk_score, 30)
                
        # Check for API errors
        if "API error" in r.explanation:
            msg = "External API timeout or rate limit hit."
            if not any(e["message"] == msg for e in forensic_errors):
                forensic_errors.append({"url": r.url, "stage": "AI Analysis", "message": msg})
    
    max_link_score = max((r.risk_score for r in valid_results), default=0.0)
    
    # Verdict Fusion: Single final verdict
    # Blend heuristic and link risk, but prioritize the definitive link results
    
    effective_heuristic = float(heuristic_score)
    if auth_pass and effective_heuristic < 25:
        # If auth passes and heuristics are already low, reduce them further
        effective_heuristic *= 0.5
        
    if max_link_score > 0:
        # Weighted average: 70% link, 30% heuristic
        final_score = (max_link_score * 0.7) + (effective_heuristic * 0.3)
    else:
        final_score = effective_heuristic
    
    if final_score >= 65:
        email_risk_level = "High"
    elif final_score >= 35:
        email_risk_level = "Medium"
    else:
        email_risk_level = "Low"
        
    # Inject Link Analysis into Forensic Logs
    if max_link_score >= 65:
        reasons.insert(0, f"Critical: Email contains high-risk deceptive links (Link Risk: {round(max_link_score, 1)}/100).")
    elif max_link_score >= 35:
        reasons.insert(0, f"Warning: Email contains suspicious or tracking links (Link Risk: {round(max_link_score, 1)}/100).")
        
    # Indicator & Reason Filtering: Tame noise if overall verdict is LOW or sender is Trusted
    final_indicators = indicators
    final_reasons = reasons
    
    if email_risk_level == "Low" or is_trusted:
        # 1. Filter Indicators
        filtered_indicators = {}
        for k, v in indicators.items():
            # Skip financial hook and urgency for trusted/low-risk newsletters
            if k in ("financial_hook", "urgency") and v and effective_heuristic < 15:
                continue 
            # Skip impersonation if trusted (already handled in email_service, but double safety)
            if k == "impersonation" and is_trusted:
                continue
            filtered_indicators[k] = v
        final_indicators = filtered_indicators
        
        # 2. Filter Reasons (Detection Logs)
        # We want to hide "Mentions financial" or "Credential requests" if the score is very low
        # and it's a trusted sender or generally safe email.
        filtered_reasons = []
        for r in reasons:
            if "financial" in r.lower() and effective_heuristic < 10:
                continue
            if "credentials" in r.lower() and is_trusted and effective_heuristic < 15:
                continue
            if "mimic" in r.lower() and is_trusted:
                continue
            filtered_reasons.append(r)
        if not filtered_reasons:
            filtered_reasons = ["No suspicious forensic indicators detected in email content."]
        final_reasons = filtered_reasons
        
    return EmailScanResponse(
        email_risk_score=round(final_score, 2),
        email_risk_level=email_risk_level,
        reasons=final_reasons,
        suspicious_indicators=final_indicators,
        extracted_urls=urls,
        link_results=valid_results,
        parsed_email=parsed_data,
        auth_results=auth,
        triage_stats=stats,
        skipped_urls=skipped,
        scanned_count=len(valid_results),
        total_extracted=len(urls),
        heuristic_score=float(heuristic_score),
        link_score=float(max_link_score),
        forensic_errors=forensic_errors,
        deep_dive_target=deep_dive_target,
        unwrap_events=unwrap_events
    )

@router.post("/scan/email", response_model=EmailScanResponse)
async def scan_email(request: EmailScanRequest, db: Session = Depends(get_db)):
    """
    Analyzes an email (manual fields or raw paste) for phishing indicators.
    """
    if request.raw_email:
        parsed_data = parse_email_from_string(request.raw_email)
    else:
        # Legacy/Manual mode
        parsed_data = {
            "from_name": request.from_name,
            "from_email": request.from_email,
            "reply_to": request.reply_to,
            "subject": request.subject,
            "body": request.body
        }
        
    return await _execute_email_analysis(parsed_data, db)

@router.post("/scan/eml", response_model=EmailScanResponse)
async def scan_eml(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """
    Uploads and analyzes a .eml file.
    """
    filename = file.filename or ""
    if not filename.lower().endswith('.eml'):
        raise HTTPException(status_code=400, detail="Only .eml files are supported")
        
    content = await file.read()
    parsed_data = parse_email_from_bytes(content)
    return await _execute_email_analysis(parsed_data, db)
