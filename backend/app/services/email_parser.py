import email
from email import policy
from email.utils import parseaddr
import re
import logging

logger = logging.getLogger(__name__)

def strip_html(html_content: str) -> str:
    """Simple regex-based HTML tag removal."""
    # Remove script and style elements
    clean = re.sub(r'<(script|style).*?>.*?</\1>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
    # Remove all other tags
    clean = re.sub(r'<.*?>', ' ', clean)
    # Normalize whitespace
    clean = re.sub(r'\s+', ' ', clean).strip()
    return clean

def extract_body(msg: email.message.Message) -> dict:
    """Recursively extracts both raw and plain text body from a message."""
    raw_body = ""
    clean_body = ""
    
    if msg.is_multipart():
        # Collect all text and html parts for link extraction
        parts_content = []
        text_part = None
        
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            if "attachment" in content_disposition:
                continue
                
            if content_type in ("text/html", "text/plain"):
                try:
                    encoding = part.get("Content-Transfer-Encoding", "").lower()
                    payload = part.get_payload(decode=True)
                    
                    # Robust Fallback: If payload still looks like base64 or encoding is non-standard
                    # and decode=True didn't result in plain text, try manual base64 decoding.
                    import base64
                    if b'<' not in payload and b' ' not in payload and len(payload) > 20:
                        try:
                            # Try to see if it's base64 despite labeling
                            candidate = base64.b64decode(payload, validate=True)
                            if len(candidate) > 10:
                                payload = candidate
                                logger.info("Forensic Hit: Mislabeled base64 part successfully decoded.")
                        except:
                            pass

                    decoded = payload.decode(part.get_content_charset() or 'utf-8', errors='ignore')
                    parts_content.append(decoded)
                    if content_type == "text/plain" and not text_part:
                        text_part = part
                except Exception as e:
                    logger.warning(f"Failed to decode email part: {e}")
        
        raw_body = "\n---\n".join(parts_content)
                
        # Determine Clean Body (for heuristics)
        if text_part:
            try:
                payload = text_part.get_payload(decode=True)
                clean_body = payload.decode(text_part.get_content_charset() or 'utf-8', errors='ignore')
            except Exception as e:
                logger.warning(f"Failed to extract clean body: {e}")
                clean_body = strip_html(raw_body) if raw_body else ""
        else:
            clean_body = strip_html(raw_body) if raw_body else ""
            
    else:
        # Single part message
        try:
            payload = msg.get_payload(decode=True)
            charset = msg.get_content_charset() or 'utf-8'
            raw_body = payload.decode(charset, errors='ignore')
            if msg.get_content_type() == "text/html":
                clean_body = strip_html(raw_body)
            else:
                clean_body = raw_body
        except Exception as e:
            logger.warning(f"Failed to parse single-part message: {e}")
            
    return {"clean": clean_body, "raw": raw_body}

def extract_auth_results(msg: email.message.Message) -> dict:
    """Extracts SPF, DKIM, and DMARC status from headers."""
    auth_header = msg.get("Authentication-Results", "")
    results = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}
    
    if auth_header:
        for mechanism in ["spf", "dkim", "dmarc"]:
            match = re.search(rf"{mechanism}=([a-z]+)", auth_header, re.IGNORECASE)
            if match:
                results[mechanism] = match.group(1).lower()
    
    # Fallback to individual headers
    if results["spf"] == "unknown":
        spf_header = msg.get("Received-SPF", "")
        if "pass" in spf_header.lower(): results["spf"] = "pass"
        elif "fail" in spf_header.lower(): results["spf"] = "fail"
        
    return results

def parse_email_message(msg: email.message.Message) -> dict:
    """Helper to convert email.message.Message to our internal dict format."""
    from_header = msg.get("From", "")
    from_name, from_email = parseaddr(from_header)
    
    reply_header = msg.get("Reply-To", "")
    _, reply_email = parseaddr(reply_header)
    
    body_data = extract_body(msg)
    
    return {
        "from_name": from_name if from_name else None,
        "from_email": from_email if from_email else None,
        "reply_to": reply_email if reply_email else None,
        "subject": msg.get("Subject"),
        "body": body_data["clean"],
        "raw_content": body_data["raw"],
        "auth_results": extract_auth_results(msg)
    }

def parse_email_from_string(raw_text: str) -> dict:
    """Parses raw text (headers + body) into a dictionary."""
    if not raw_text.strip():
        return {"from_name": None, "from_email": None, "reply_to": None, "subject": None, "body": "", "raw_content": ""}
        
    # Heuristic: If first line doesn't contain a colon, it's likely just a body paste.
    first_line = raw_text.splitlines()[0] if raw_text.splitlines() else ""
    if ":" not in first_line:
        return {
            "from_name": None,
            "from_email": None,
            "reply_to": None,
            "subject": None,
            "body": raw_text,
            "raw_content": raw_text
        }
        
    msg = email.message_from_string(raw_text, policy=policy.default)
    return parse_email_message(msg)

def parse_email_from_bytes(data: bytes) -> dict:
    """Parses .eml file bytes into a dictionary."""
    msg = email.message_from_bytes(data, policy=policy.default)
    return parse_email_message(msg)
