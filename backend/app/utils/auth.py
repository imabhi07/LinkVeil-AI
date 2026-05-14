from fastapi import Header, HTTPException, Depends, Cookie
from typing import Optional, Literal
import re
import logging

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
    linkveil_session: Optional[str] = Cookie(None),
    db: Session = Depends(get_db)
) -> AuthUser:
    """
    Dependency to retrieve the current authenticated user.
    Requires both a tenant identifier (X-Client-ID) and a session token (Cookie).
    Validated against the server-side session store.
    """
    if not x_client_id:
        raise HTTPException(status_code=401, detail="X-Client-ID header required for authentication")
    
    # Validate pattern BEFORE logging to prevent log injection vectors
    validate_client_id_pattern(x_client_id)
    
    if not linkveil_session:
        logger.warning(f"Unauthorized access attempt for client {x_client_id}: Missing session cookie")
        raise HTTPException(status_code=401, detail="Secure forensic session cookie required")

    # Validate session in database
    session_record = db.query(ForensicSession).filter(
        ForensicSession.session_token == linkveil_session,
        ForensicSession.tenant_id == x_client_id,
        ForensicSession.expires_at > datetime.now(timezone.utc)
    ).first()
    
    if not session_record:
        logger.warning(f"Invalid or expired session for client {x_client_id}")
        raise HTTPException(status_code=401, detail="Invalid or expired forensic session")

    # The client_id scopes the forensic context, while the session record determines identity and roles
    return AuthUser(client_id=x_client_id, is_admin=bool(session_record.is_admin))

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
