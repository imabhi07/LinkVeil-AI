import re
import uuid
from datetime import datetime
from typing import Optional

class Sanitizer:
    """
    Utility class for scrubbing PII and sensitive tokens from forensic snippets.
    """
    
    # Regex for email addresses
    EMAIL_REGEX = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
    
    # Regex for long tokens (20+ alphanumeric characters)
    TOKEN_REGEX = re.compile(r'[a-zA-Z0-9]{20,}')
    
    # Regex for potential phone numbers (simple version)
    PHONE_REGEX = re.compile(r'\+?\d[\d\-\(\) ]{8,}\d')

    @classmethod
    def scrub(cls, text: str, max_length: int = 300) -> str:
        """
        Scrubs PII (emails, phone numbers) and long tokens from text.
        Enforces a maximum length.
        """
        if not text:
            return ""

        # 1. Scrub emails
        text = cls.EMAIL_REGEX.sub("[EMAIL_REDACTED]", text)
        
        # 2. Scrub long tokens
        text = cls.TOKEN_REGEX.sub("[TOKEN_REDACTED]", text)
        
        # 3. Scrub phone numbers
        text = cls.PHONE_REGEX.sub("[PHONE_REDACTED]", text)
        
        # 4. Enforce max length
        if len(text) > max_length:
            text = text[:max_length] + "..."
            
        return text

def generate_scan_id() -> str:
    """Generates a unique scan ID."""
    return str(uuid.uuid4())

def get_iso_timestamp() -> str:
    """Returns the current UTC timestamp in ISO format."""
    return datetime.utcnow().isoformat() + "Z"

class ForensicErrorEnvelope:
    """
    Helper to standardize engine failures into the forensic_errors list.
    """
    @staticmethod
    def wrap(engine: str, error: Exception, retryable: bool = False) -> dict:
        return {
            "engine": engine,
            "message": str(error),
            "retryable": retryable
        }
