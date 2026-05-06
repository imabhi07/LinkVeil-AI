import logging
import asyncio
from fastapi import APIRouter, Depends, HTTPException, File, UploadFile
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.models.schemas import URLRequest, ScanResponse, EmailScanRequest, EmailScanResponse
from backend.app.services.engine_service import evaluate_url
from backend.app.utils.url_utils import _normalize_url
from backend.app.services.email_service import ForensicsBrain
from backend.app.services.email_parser import parse_email_from_string, parse_email_from_bytes
from backend.app.utils.forensics import generate_scan_id, get_iso_timestamp, ForensicErrorEnvelope, Sanitizer

SCAN_TIMEOUT = 60.0

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post("/scan", response_model=ScanResponse)
async def scan_url(request: URLRequest, db: Session = Depends(get_db)):
    """Legacy URL scan endpoint."""
    url_str = _normalize_url(str(request.url))
    try:
        verdict = await evaluate_url(url_str, db)
        return ScanResponse(**verdict)
    except Exception as e:
        logger.error(f"Engine failure for {url_str}: {e}")
        raise HTTPException(status_code=500, detail=f"Internal engine failure: {str(e)}")

async def _execute_email_analysis(parsed_data: dict, input_type: str, db: Session):
    """
    Forensics++ Pipeline:
    1. Email Heuristics (Intent)
    2. Link Analysis (Payload)
    3. Fusion & Evidence Generation
    """
    scan_id = generate_scan_id()
    scanned_at = get_iso_timestamp()
    forensic_errors = []
    
    # 1. Forensic Brain Analysis (Email Side)
    email_forensics = ForensicsBrain.calculate_email_risk(parsed_data)
    email_score = email_forensics["score"]
    
    # 2. Link Analysis
    urls_to_scan = parsed_data.get("links", [])
    link_results = []
    
    if urls_to_scan:
        semaphore = asyncio.Semaphore(5)
        async def gated_evaluate(url):
            async with semaphore:
                try:
                    result = await asyncio.wait_for(
                        evaluate_url(url, db, auth_context=parsed_data.get("auth")), 
                        timeout=SCAN_TIMEOUT
                    )
                    return ScanResponse(**result)
                except asyncio.TimeoutError:
                    forensic_errors.append(ForensicErrorEnvelope.wrap(f"LinkScan:{url[:30]}", Exception("Timeout"), True))
                    return None
                except Exception as e:
                    logger.error(f"LinkScan error for {url}: {e}")
                    forensic_errors.append(ForensicErrorEnvelope.wrap(f"LinkScan:{url[:30]}", e))
                    return None

        tasks = [gated_evaluate(url) for url in urls_to_scan]
        results = await asyncio.gather(*tasks)
        
        # Build link_results including placeholders for failures
        for i, r in enumerate(results):
            if r is not None:
                link_results.append(r)
            else:
                # Add a placeholder for the failed scan so it appears in the UI
                err_info = next((e for e in forensic_errors if f"LinkScan:{urls_to_scan[i][:30]}" in e["engine"]), {"message": "Forensic analysis timed out or failed"})
                link_results.append(ScanResponse(
                    url=urls_to_scan[i],
                    risk_score=0.0,
                    risk_level="INCONCLUSIVE",
                    explanation=f"Forensic Intelligence Alert: {err_info['message']}. This link remains inconclusive as deep analysis was interrupted.",
                    brand_impersonation=False,
                    forensic_errors=[err_info] if err_info else [{"engine": "LinkScan", "message": "Analysis Timeout"}]
                ))

    link_score = max((r.risk_score for r in link_results), default=0.0)
    
    # 3. Fusion & Verdict
    fusion = ForensicsBrain.fuse_verdict(email_score, link_score)
    confidence = ForensicsBrain.judge_confidence(parsed_data, link_results)
    
    # 4. Evidence Building (PII Sanitized)
    evidence = {
        "email_header_summary": f"From: {parsed_data['identity']['from']['email']} | Auth: SPF={parsed_data['auth']['spf']}, DKIM={parsed_data['auth']['dkim']}",
        "top_threat_reasons": email_forensics["reasons"][:3],
        "social_engineering_snippet": Sanitizer.scrub(parsed_data.get("clean_body", ""), 200)
    }

    return EmailScanResponse(
        scan_id=scan_id,
        scanned_at=scanned_at,
        input_type=input_type,
        email_risk_score=float(email_score),
        link_risk_score=float(link_score),
        final_risk_score=fusion["final_score"],
        verdict_label=fusion["verdict_label"],
        final_verdict_source=fusion["final_verdict_source"],
        analysis_quality="high" if confidence["level"] == "high" else "medium",
        confidence=confidence,
        score_identity=float(email_forensics.get("score_identity", 0)),
        score_linguistic=float(email_forensics.get("score_linguistic", 0)),
        score_breakdown={
            "email": email_forensics["signals"],
            "link": [
                {
                    "url": r.url,
                    "points": r.risk_score,
                    "reason": r.verdictTitle
                } for r in link_results if r.risk_score > 10
            ]
        },
        forensic_errors=forensic_errors,
        triage_stats=parsed_data["triage_stats"],
        identity=parsed_data["identity"],
        auth=parsed_data["auth"],
        html_findings=parsed_data["html_findings"],
        social_engineering=email_forensics["social_engineering"],
        evidence=evidence,
        attachments=parsed_data.get("attachments", []),
        link_results=link_results,
        extracted_urls=urls_to_scan,
        reasons=email_forensics["reasons"],
        unwrap_events=parsed_data.get("unwrap_events", [])
    )

@router.post("/scan/email", response_model=EmailScanResponse)
async def scan_email(request: EmailScanRequest, db: Session = Depends(get_db)):
    if request.raw_email:
        parsed_data = await parse_email_from_string(request.raw_email)

        input_type = "paste"
    else:
        # Construct identity for manual mode
        parsed_data = {
            "identity": {
                "from": {"email": request.from_email, "name": request.from_name, "domain": request.from_email.split('@')[-1] if request.from_email else ""},
                "reply_to": {"email": request.reply_to} if request.reply_to else None,
                "mismatches": []
            },
            "auth": {"spf": "none", "dkim": "none", "dmarc": "none"},
            "html_findings": {"hidden_html": [], "link_mismatches": []},
            "links": [],
            "triage_stats": {"total_found": 0, "analyzed": 0, "ignored": 0, "filtered": 0},
            "clean_body": request.body or "",
            "attachments": []
        }
        input_type = "manual"
        
    return await _execute_email_analysis(parsed_data, input_type, db)

@router.post("/scan/eml", response_model=EmailScanResponse)
async def scan_eml(file: UploadFile = File(...), db: Session = Depends(get_db)):
    filename = file.filename or ""
    if not filename.lower().endswith('.eml'):
        raise HTTPException(status_code=400, detail="Only .eml files are supported")
        
    content = await file.read()
    parsed_data = await parse_email_from_bytes(content)
    return await _execute_email_analysis(parsed_data, "eml", db)
