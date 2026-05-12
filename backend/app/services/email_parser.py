import email
import base64
from email import policy
from email.utils import parseaddr
import re
import asyncio
import logging
import unicodedata
from bs4 import BeautifulSoup
import tldextract
import hashlib
from typing import List, Dict, Any, Optional

from backend.app.utils.url_utils import is_safe_url, _normalize_url
from backend.app.utils.forensics import Sanitizer

logger = logging.getLogger(__name__)

# URL Regex for plain text extraction
URL_REGEX = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')

from urllib.parse import urlparse, parse_qs, unquote, urlunparse
import base64
import binascii
from backend.app.utils.unwrapper import resolve_shortener

def unwrap_redirect(url: str) -> Optional[str]:
    """Tries to find a destination URL within query parameters."""
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        target_params = ['url', 'dest', 'destination', 'link', 'redirect', 'target', 'u', 'uri', 'next', 'goto', 'continue', 'r']
        
        for p in target_params:
            if p in params:
                val = params[p][0]
                # Base64 check
                if len(val) > 10 and (val.endswith('==') or re.match(r'^[a-zA-Z0-9+/]+={0,2}$', val)):
                    try:
                        decoded = base64.b64decode(val).decode('utf-8')
                        if decoded.startswith('http'): return decoded
                    except (binascii.Error, UnicodeDecodeError):
                        pass
                # Standard unquote
                candidate = unquote(val)
                if candidate.startswith('http'): return candidate
        return None
    except (ValueError, KeyError):
        return None

async def extract_links_forensic(html_content: str, text_content: str) -> Dict[str, Any]:
    """
    Extracts and triages links from both HTML and Plain Text.
    Includes heuristic AND network-based redirect unwrapping.
    """
    raw_urls = set()
    unwrap_events = []
    triage_stats = {
        "total_found": 0,
        "analyzed": 0,
        "ignored": 0,
        "filtered": 0,
        "wrappers_unwrapped": 0,
        "pii_scrubbed": 0,
        "ignored_breakdown": {
            "static_assets": 0,
            "tracking_pixels": 0,
            "duplicates": 0,
            "unsub_links": 0,
            "mailto_tel_sms": 0,
            "assets": 0
        },
        "filtered_breakdown": {
            "unsupported_schemes": 0,
            "private_ip_blocked": 0,
            "localhost_blocked": 0,
            "metadata_ip_blocked": 0,
            "redirect_limit_hit": 0
        }
    }
    
    # Extraction Logic
    temp_urls = set()
    if html_content:
        soup = BeautifulSoup(html_content, 'html.parser')
        # 1. Standard Hyperlinks
        for a in soup.find_all('a', href=True):
            temp_urls.add(a['href'].strip())
        
        # 2. Asset Links
        for tag in soup.find_all(['img', 'script', 'source', 'link'], src=True):
            temp_urls.add(tag['src'].strip())
        for tag in soup.find_all('link', href=True):
            if tag.get('rel') and 'stylesheet' in tag['rel']:
                temp_urls.add(tag['href'].strip())

    if text_content:
        import html
        for raw_url in URL_REGEX.findall(text_content):
            cleaned = raw_url.rstrip('.,;?!)]}')
            cleaned = html.unescape(cleaned)
            temp_urls.add(cleaned)

    # Triage and Unwrap
    link_mismatches = []
    final_urls = []
    seen_normalized = set()
    
    from backend.app.services.engine_service import KNOWN_SAFE_DOMAINS, _root_domain

    async def process_url(url):
        nonlocal triage_stats
        triage_stats["total_found"] += 1
        
        # 1. Mailto/Tel check
        if any(url.lower().startswith(p) for p in ['mailto:', 'tel:', 'sms:']):
            triage_stats["ignored"] += 1
            triage_stats["ignored_breakdown"]["mailto_tel_sms"] += 1
            return None

        # 2. Asset & Whitelist Optimization
        url_root = _root_domain(url)
        is_whitelisted = url_root in KNOWN_SAFE_DOMAINS
        
        if is_whitelisted and url.split('?')[0].lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg', '.css', '.js')):
            triage_stats["ignored"] += 1
            triage_stats["ignored_breakdown"]["assets"] += 1
            return None

        # 3. Unwrap check (Heuristic + Async Network)
        # First check heuristic (query params)
        unwrapped = unwrap_redirect(url)
        if unwrapped:
            triage_stats["wrappers_unwrapped"] += 1
            unwrap_events.append({"found_url": url, "destination_url": unwrapped, "method": "heuristic_unquote"})
            url = unwrapped 
        
        # Then check network-based (shorteners)
        resolved = await resolve_shortener(url)
        if resolved:
            triage_stats["wrappers_unwrapped"] += 1
            unwrap_events.append({"found_url": url, "destination_url": resolved, "method": "network_resolve"})
            url = resolved

        # 4. SSRF check
        safe, reason = is_safe_url(url)
        if not safe:
            triage_stats["filtered"] += 1
            triage_stats["filtered_breakdown"][reason if reason in triage_stats["filtered_breakdown"] else "unsupported_schemes"] += 1
            return None
            
        # 5. Normalize & Dedup
        norm = _normalize_url(url)
        return {"original": url, "norm": norm}

    tasks = [process_url(u) for u in temp_urls]
    results = await asyncio.gather(*tasks)

    for res in results:
        if not res: continue
        norm = res["norm"]
        if norm in seen_normalized:
            triage_stats["ignored"] += 1
            triage_stats["ignored_breakdown"]["duplicates"] += 1
            continue
        
        seen_normalized.add(norm)
        final_urls.append(res["original"])
        triage_stats["analyzed"] += 1

    return {
        "urls": final_urls,
        "triage_stats": triage_stats,
        "link_mismatches": link_mismatches,
        "unwrap_events": unwrap_events
    }


def extract_attachments_forensic(msg: email.message.Message) -> List[Dict[str, Any]]:
    """Extracts attachment metadata without storing content."""
    attachments = []
    risky_extensions = {'.exe', '.vbs', '.js', '.docm', '.xlsm', '.zip', '.rar', '.7z', '.bat', '.ps1'}
    
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        if part.get('Content-Disposition') is None:
            continue
            
        filename = part.get_filename()
        if filename:
            payload = part.get_payload(decode=True)
            sha256 = hashlib.sha256(payload).hexdigest() if payload else "unknown"
            
            risk = "low"
            reasons = []
            ext = "." + filename.split('.')[-1].lower() if '.' in filename else ""
            
            if ext in risky_extensions:
                risk = "high"
                reasons.append("risky_extension")
            
            attachments.append({
                "filename": filename,
                "mime_type": part.get_content_type(),
                "size_bytes": len(payload) if payload else 0,
                "sha256": sha256,
                "risk": risk,
                "reasons": reasons
            })
            
    return attachments

def extract_html_forensics(html_content: str) -> Dict[str, Any]:
    """Detects hidden HTML, zero-width characters, and form tags."""
    findings = {
        "hidden_html": [],
        "form_tags_found": False,
        "zero_width_chars_found": False
    }
    
    if not html_content:
        return findings
        
    # Zero-width detection
    zero_width_chars = ['\u200b', '\u200c', '\u200d', '\ufeff', '\u2060']
    if any(c in html_content for c in zero_width_chars):
        findings["zero_width_chars_found"] = True
        
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # Form detection
    if soup.find('form'):
        findings["form_tags_found"] = True
        
    # Hidden HTML detection (basic)
    hidden_styles = [
        r'display\s*:\s*none',
        r'visibility\s*:\s*hidden',
        r'opacity\s*:\s*0',
        r'font-size\s*:\s*0',
        r'position\s*:\s*absolute\s*;\s*left\s*:\s*-\d+'
    ]
    
    for tag in soup.find_all(True, style=True):
        style = tag['style'].lower()
        for pattern in hidden_styles:
            if re.search(pattern, style):
                # Capture the start tag or the whole snippet if short
                tag_str = str(tag)
                snippet = tag_str if len(tag_str) < 120 else f"{tag_str[:120]}..."
                
                findings["hidden_html"].append({
                    "technique": pattern.split('\\')[0].replace(' ', '').upper(),
                    "snippet": snippet
                })
                break
                
    return findings

def extract_auth_results(msg: email.message.Message) -> Dict[str, Any]:
    """Improved auth parsing with alignment detection."""
    from_header = msg.get("From", "")
    _, from_email = parseaddr(from_header)
    sender_domain = from_email.split('@')[-1].lower() if '@' in from_email else ""
    
    auth_header = msg.get("Authentication-Results", "")
    results = {
        "spf": "none", 
        "dkim": "none", 
        "dmarc": "none",
        "sender_domain": sender_domain,
        "alignment": {
            "dkim_aligned": None,
            "spf_aligned": None,
            "mode": "unknown",
            "notes": []
        },
        "provider_flagged_spam": False,
        "provider_spam_signals": []
    }
    spam_headers = ["X-Spam-Flag", "X-Spam-Status", "X-Forefront-Antispam-Report"]
    for h in spam_headers:
        val = msg.get(h)
        if val:
            results["provider_spam_signals"].append({"header": h, "value": val[:100]})
            if "yes" in val.lower() or "spam" in val.lower():
                results["provider_flagged_spam"] = True

    if auth_header:
        # Standard parsing
        for mechanism in ["spf", "dkim", "dmarc"]:
            match = re.search(rf"{mechanism}=([a-z]+)", auth_header, re.IGNORECASE)
            if match:
                results[mechanism] = match.group(1).lower()
        
        # Alignment parsing (heuristic)
        if "dkim=pass" in auth_header.lower():
            results["alignment"]["dkim_aligned"] = True
        if "spf=pass" in auth_header.lower():
            results["alignment"]["spf_aligned"] = True
            
    return results

def _decode_payload_smart(part) -> str:
    """Decode MIME part payload with base64 fallback for mislabeled encodings."""
    raw = part.get_payload(decode=True)
    if raw is None:
        return ""
    text = raw.decode(part.get_content_charset() or 'utf-8', errors='ignore')
    
    # Heuristic: If decoded text has no HTML tags and looks like base64, try decoding
    stripped = text.strip()
    if stripped and '<' not in stripped[:200]:
        # Looks like raw base64 (no HTML tags in first 200 chars)
        try:
            # Check if it's likely base64 before trying to decode
            if re.match(r'^[A-Za-z0-9+/=\s]+$', stripped):
                decoded_bytes = base64.b64decode(stripped)
                decoded_text = decoded_bytes.decode('utf-8', errors='ignore')
                # Verify it actually produced HTML or text
                if '<' in decoded_text[:500] or len(decoded_text) > 10:
                    logger.info("Base64 fallback: Successfully decoded mislabeled part body")
                    return decoded_text
        except Exception:
            pass  # Not base64, return original
    
    return text


async def parse_email_message(msg: email.message.Message) -> dict:
    """Enhanced parser for Forensics++."""
    from_header = msg.get("From", "")
    from_name, from_email = parseaddr(from_header)
    
    reply_header = msg.get("Reply-To", "")
    _, reply_email = parseaddr(reply_header)
    
    return_path = msg.get("Return-Path", "")
    _, rp_email = parseaddr(return_path)
    
    # Extract body parts
    html_part = ""
    text_part = ""
    for part in msg.walk():
        if part.get_content_type() == "text/html":
            html_part = _decode_payload_smart(part)
        elif part.get_content_type() == "text/plain":
            text_part = _decode_payload_smart(part)
            
    # NFKC Normalization to defeat Unicode Obfuscation
    norm_subject = unicodedata.normalize('NFKC', msg.get("Subject", ""))
    norm_text = unicodedata.normalize('NFKC', text_part) if text_part else ""
    norm_html_text = unicodedata.normalize('NFKC', BeautifulSoup(html_part, 'html.parser').get_text()) if html_part else ""
    
    # Detect Unicode Obfuscation in Subject
    has_unicode_obfuscation = False
    if msg.get("Subject"):
        raw_sub = msg.get("Subject")
        if raw_sub != norm_subject:
            # We check if it's significant (e.g. bolded letters which are in a different block)
            # This is a strong indicator of phishing lures like "PAYMENT" or "URGENT"
            has_unicode_obfuscation = True

    link_data = await extract_links_forensic(html_part, norm_text)
    html_data = extract_html_forensics(html_part)
    
    # Identify mismatches
    mismatches = []
    if reply_email and from_email and reply_email.lower() != from_email.lower():
        mismatches.append("reply_to_mismatch")
    if rp_email and from_email and rp_email.lower() != from_email.lower():
        mismatches.append("return_path_mismatch")
        
    return {
        "identity": {
            "subject": norm_subject or ((norm_text or norm_html_text)[:50].strip() + "..." if (norm_text or norm_html_text) else "Untitled Forensic Analysis"),
            "raw_subject": msg.get("Subject", ""),
            "has_unicode_obfuscation": has_unicode_obfuscation,
            "from": {"name": from_name, "email": from_email, "domain": from_email.split('@')[-1] if '@' in from_email else ""},
            "reply_to": {"email": reply_email, "domain": reply_email.split('@')[-1]} if reply_email else None,
            "return_path": {"email": rp_email, "domain": rp_email.split('@')[-1]} if rp_email else None,
            "mismatches": mismatches,
            "mailing_list_detected": any(h in msg for h in ["List-Unsubscribe", "List-Id", "Precedence"]),
        },
        "auth": extract_auth_results(msg),
        "html_findings": {
            **html_data,
            "link_mismatches": link_data["link_mismatches"]
        },
        "links": link_data["urls"],
        "unwrap_events": link_data["unwrap_events"],
        "triage_stats": link_data["triage_stats"],
        "attachments": extract_attachments_forensic(msg),
        "subject": norm_subject,
        "clean_body": norm_text or norm_html_text,
        "raw_html": html_part
    }


async def parse_email_from_string(raw_text: str) -> dict:
    """Parses raw text into forensic dict."""
    if not raw_text.strip():
        return {}
    msg = email.message_from_string(raw_text, policy=policy.default)
    return await parse_email_message(msg)

async def parse_email_from_bytes(data: bytes) -> dict:
    """Parses .eml bytes into forensic dict."""
    msg = email.message_from_bytes(data, policy=policy.default)
    return await parse_email_message(msg)
