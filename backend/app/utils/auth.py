from fastapi import Header, HTTPException, Depends, Cookie, Query
from typing import Optional, Literal
import re
import logging
import os

logger = logging.getLogger(__name__)

class AuthUser:
    def __init__(self, client_id: str, is_admin: bool = False):
        self.client_id = client_id
        self.is_admin = is_admin

def validate_client_id_pattern(client_id: str):
    """Utility to validate client ID format."""
    if not client_id or not re.match(r"^[a-zA-Z0-9-]+$", client_id):
        raise HTTPException(status_code=400, detail="Invalid x_client_id format")
    if len(client_id) > 64:
        raise HTTPException(status_code=400, detail="x_client_id is too long (max 64 chars)")
    return client_id

from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.models.db_models import ForensicSession
from datetime import datetime, timezone

def get_current_user(
    x_client_id: Optional[str] = Header(None),
    cid: Optional[str] = Query(None),
    linkveil_session: Optional[str] = Cookie(None),
    db: Session = Depends(get_db)
) -> AuthUser:
    """
    Dependency to retrieve the current authenticated user.
    Requires both a tenant identifier (X-Client-ID or 'cid' query param) and a session token (Cookie).
    Validated against the server-side session store.
    """
    # Prioritize Header, then Query Param
    client_id = x_client_id or cid
    
    # 1. Define environment mode (Fail-closed: treat unset/ambiguous as production)
    is_dev = os.getenv("ENV") in {"development", "dev"} or os.getenv("NODE_ENV") in {"development", "dev"}
    is_prod = not is_dev
    
    if not linkveil_session:
        # If no cookie, we MUST have a client ID to even try to talk about sessions
        if not client_id:
            raise HTTPException(status_code=401, detail="Authentication required: Missing session cookie and Client ID")
            
        # In development, we allow the Client ID as a fallback if the cookie is blocked
        if is_dev:
            logger.info(f"Dev Fallback: Authenticating via Client ID for {client_id}")
        else:
            logger.warning(f"Unauthorized access attempt for client {client_id}: Missing session cookie")
            raise HTTPException(status_code=401, detail="Secure forensic session cookie required")

    # 2. Validate session in database
    # In dev fallback (no cookie), we find the most recent active session for this tenant
    if not linkveil_session and is_dev:
        validate_client_id_pattern(client_id)
        session_record = db.query(ForensicSession).filter(
            ForensicSession.tenant_id == client_id,
            ForensicSession.expires_at > datetime.now(timezone.utc)
        ).order_by(ForensicSession.created_at.desc()).first()
    else:
        # Standard strict cookie-based validation
        query = db.query(ForensicSession).filter(
            ForensicSession.session_token == linkveil_session,
            ForensicSession.expires_at > datetime.now(timezone.utc)
        )
        
        if client_id:
            validate_client_id_pattern(client_id)
            query = query.filter(ForensicSession.tenant_id == client_id)
        
        session_record = query.first()
    
    if not session_record:
        msg = f"Invalid or expired session for client {client_id}" if client_id else "Invalid or expired forensic session"
        logger.warning(msg)
        # Use generic error message to prevent leaking tenant identifiers to the client
        raise HTTPException(status_code=401, detail="Invalid or expired session")

    # Use the inferred or verified client_id
    effective_client_id = session_record.tenant_id
    return AuthUser(client_id=effective_client_id, is_admin=bool(session_record.is_admin))

def has_access_to_client(user: AuthUser, requested_client_id: Optional[str]) -> Literal[True]:
    """
    Enforces authorization: users can only access their own client data.
    Ensures every path returns True or raises an HTTPException.
    """
    if requested_client_id is None:
        if user.is_admin:
            return True
        raise HTTPException(
            status_code=403, 
            detail="Forbidden: Explicit client ID filter required for non-admin users"
        )
        
    if user.is_admin or user.client_id == requested_client_id:
        return True
        
    raise HTTPException(
        status_code=403, 
        detail="Forbidden: You do not have access to this client's data"
    )
