import logging
from urllib.parse import urlparse
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.models.schemas import URLRequest, ScanResponse
from backend.app.services.engine_service import evaluate_url

logger = logging.getLogger(__name__)
router = APIRouter()


def _normalize_url(raw: str) -> str:
    """
    Normalize URL for cache consistency:
      - lowercase the scheme + hostname
      - strip trailing slashes
      - strip default ports (80/443)
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
    query = parsed.query
    fragment = ""  # intentionally drop fragment — server never sees it

    normalized = f"{scheme}://{netloc}{path}"
    if query:
        normalized += f"?{query}"
    return normalized


@router.post("/scan", response_model=ScanResponse)
async def scan_url(request: URLRequest, db: Session = Depends(get_db)):
    """
    Submits a URL to the PhishGuard XGBoost + LLM engines concurrently.
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
