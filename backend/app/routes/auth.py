from fastapi import APIRouter, Response, Depends, HTTPException, Cookie
from typing import Optional
import secrets
import logging
import os
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.models.db_models import ForensicSession

logger = logging.getLogger(__name__)
router = APIRouter()

@router.get("/session")
async def initialize_session(response: Response, db: Session = Depends(get_db)):
    """
    Server-side session provisioning.
    Sets an httpOnly SameSite cookie for the session token and 
    returns a server-generated tenant identifier.
    """
    # 1. Provision a new tenant ID
    # Shared with the client for forensic scoping (X-Client-ID)
    tenant_id = secrets.token_hex(16)
    
    # 2. Generate and persist a secure session token
    session_token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(days=1)
    
    db_session = ForensicSession(
        session_token=session_token,
        tenant_id=tenant_id,
        expires_at=expires_at
    )
    try:
        db.add(db_session)
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to persist forensic session: {e}")
        raise HTTPException(status_code=500, detail="Failed to initialize secure forensic session.")
    
    # 3. Set httpOnly SameSite cookie
    # Secure flag driven by environment config
    is_prod = os.getenv("ENV") == "production" or os.getenv("NODE_ENV") == "production"
    cookie_secure = os.getenv("COOKIE_SECURE", str(is_prod)).lower() == "true"
    
    response.set_cookie(
        key="linkveil_session",
        value=session_token,
        httponly=True,
        samesite="lax",
        secure=cookie_secure,
        max_age=3600 * 24 # 24 hours
    )
    
    # Mask tenant_id in log to prevent sensitive data exposure
    masked_tenant = f"{tenant_id[:4]}...{tenant_id[-4:]}"
    logger.info(f"Provisioned new forensic session for tenant_id={masked_tenant}")
    
    return {
        "tenant_id": tenant_id,
        "expires_in": 3600 * 24,
        "status": "provisioned"
    }

@router.post("/logout")
async def logout(
    response: Response, 
    db: Session = Depends(get_db), 
    linkveil_session: Optional[str] = Cookie(None)
):
    """Revokes the current session."""
    if linkveil_session:
        try:
            db.query(ForensicSession).filter(ForensicSession.session_token == linkveil_session).delete()
            db.commit()
        except Exception as e:
            db.rollback()
            logger.warning(f"Failed to revoke session from DB during logout: {e}")
            # Continue to delete cookie anyway to help the client
    
    response.delete_cookie("linkveil_session")
    return {"status": "revoked"}
