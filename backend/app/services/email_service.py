import re
import tldextract
from typing import List, Dict, Any

# Keyword lists based on requirements
URGENCY_PHRASES = [
    "act immediately", "action required", "within 24 hours", "suspended permanently",
    "final notice", "urgent security", "asap", "deadline approaching", "urgent", "immediately",
    "expires soon", "within 48 hours", "immediate attention", "restricted access"
]

CREDENTIAL_PHRASES = [
    "verify your account", "confirm your identity", "sign-in detected",
    "reset your password", "authorize access", "validate credentials",
    "login to your", "security verification", "one-time passcode", "otp is",
    "verify", "credentials", "password reset", "confirm details", "identify verification"
]

BILLING_PHRASES = [
    "invoice for", "payment received", "payment failed", "refund processed",
    "transaction details", "billing statement", "subscription active", 
    "overdue balance", "receipt for", "card ending in", "payment of", "received a payment",
    "wire transfer", "unpaid invoice", "remittance", "payment confirmation"
]

MARKETING_REWARDS_PHRASES = [
    "you've won", "exclusive deal", "special offer", "limited discount", 
    "claim your reward", "bonus points", "earn badges"
]

NEWSLETTER_INDICATORS = [
    "digest", "newsletter", "weekly", "monthly", "edition", 
    "update", "roundup", "summary", "read more"
]

IMPERSONATION_PHRASES = [
    "official support", "security desk", "verification center", "system administrator",
    "help desk team", "billing department", "no-reply@", "support", "helpdesk", "administrator"
]

def analyze_email(
    subject: str = None, 
    body: str = "", 
    from_email: str = None, 
    reply_to: str = None, 
    from_name: str = None,
    is_trusted: bool = False
) -> dict:
    """
    Analyzes email content for suspicious heuristics.
    Returns:
    {
      "flags": {
        "urgency": bool,
        "credential_request": bool,
        "financial_hook": bool,
        "impersonation": bool,
        "reply_to_mismatch": bool
      },
      "heuristic_score": int,   # 0–40
      "reasons": ["..."]
    }
    """
    subject = subject or ""
    body = body or ""
    from_name = from_name or ""
    
    # Normalize Unicode characters to standard ASCII-like forms (NFKC)
    # This prevents bypasses using bold/italic Unicode or similar homographs
    import unicodedata
    def normalize(t):
        return unicodedata.normalize('NFKC', t)
        
    subject = normalize(subject)
    body = normalize(body)
    from_name = normalize(from_name)
    
    combined_text = (from_name + " " + subject + " " + body).lower()
    
    flags = {
        "urgency": False,
        "credential_request": False,
        "financial_hook": False,
        "impersonation": False,
        "reply_to_mismatch": False
    }
    
    reasons = []
    score = 0
    
    def contains_any(text: str, phrases: List[str]) -> bool:
        # Match whole phrases or specific keywords with word boundaries
        # This is MUCH more accurate than simple 'word in text'
        for phrase in phrases:
            pattern = r'\b' + re.escape(phrase) + r'\b'
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

    # 0. Identity Alignment Check (High Signal)
    # Check if the 'from_name' is claiming to be a major service that doesn't match the domain
    if from_name and from_email:
        major_services = ["paypal", "amazon", "bank", "netflix", "microsoft", "google", "apple", "stripe"]
        from_name_lower = from_name.lower()
        from_email_lower = from_email.lower()
        
        # Extract root domain for accurate comparison
        ext = tldextract.extract(from_email_lower)
        root_domain = f"{ext.domain}.{ext.suffix}"
        
        for service in major_services:
            # If name says "PayPal" but email domain isn't the legitimate one
            if service in from_name_lower and service not in root_domain:
                flags["impersonation"] = True
                score += 15
                reasons.append(f"Sender name '{from_name}' claims to be a major service but domain '{root_domain}' is not recognized.")
                break

    # 1. Urgency Check (+15)
    if contains_any(combined_text, URGENCY_PHRASES):
        flags["urgency"] = True
        score += 15
        reasons.append("Email uses strong urgency or high-pressure language.")
        
    # 2. Credential Check (+20)
    # Only flag if it's an INSTRUCTIONAL phrase, not just a mention
    if contains_any(combined_text, CREDENTIAL_PHRASES):
        flags["credential_request"] = True
        # Dampen significantly if trusted/authenticated
        # If it's a trusted security email, score is 0. If it's a suspicious email, score is 20.
        f_score = 0 if is_trusted else 20
        score += f_score
        if not is_trusted:
            reasons.append("Email contains specific instructions to verify credentials or identity.")
        
    # 3. Finance Check (+25)
    is_billing = contains_any(combined_text, BILLING_PHRASES)
    is_marketing = contains_any(combined_text, MARKETING_REWARDS_PHRASES)
    is_newsletter = contains_any(combined_text, NEWSLETTER_INDICATORS)
    
    if is_billing or (is_marketing and not is_newsletter):
        flags["financial_hook"] = True
        f_score = 0
        if is_billing:
            f_score = 25
            reasons.append("Email mentions a specific financial transaction or billing event (High sensitivity).")
        elif is_marketing:
            f_score = 10
            reasons.append("Email uses promotional rewards or marketing incentives.")
            
        # Dampen if it's a likely newsletter OR trusted
        if is_newsletter or is_trusted:
            f_score = max(0, f_score - 15)
            
        score += f_score
        
    # 4. Impersonation Check (+6)
    # Use phrases like "Verification Center" instead of just "Support"
    if not flags["impersonation"] and contains_any(combined_text, IMPERSONATION_PHRASES):
        # We only flag if it's not a trusted sender using their own name
        is_legit_service = False
        if is_trusted and from_name and from_email and '@' in from_email:
            # If CodeRabbit says "CodeRabbit Support", it's legit
            # We check if the core domain matches the name
            ext = tldextract.extract(from_email.lower())
            domain_part = ext.domain.lower()
            if domain_part and domain_part in from_name.lower():
                is_legit_service = True
        
        if not is_legit_service:
            flags["impersonation"] = True
            score += 6
            reasons.append("Email uses generic authority titles (e.g., 'Help Desk') without clear identity.")
        
    # 5. Reply-to Mismatch (+10)
    if from_email and reply_to and from_email.lower() != reply_to.lower():
        # Check domain-level alignment
        def get_domain(email_addr):
            if not email_addr or "@" not in email_addr: return ""
            return email_addr.split("@")[-1].lower()
            
        from_domain = get_domain(from_email)
        reply_domain = get_domain(reply_to)
        
        if from_domain != reply_domain:
            # Domain discrepancy is high signal
            flags["reply_to_mismatch"] = True
            score += 6 if is_trusted else 10
            reasons.append(f"Reply-To address domain '{reply_domain}' does not match sender domain.")
        else:
            # Same domain but different address (common for support/automated mail)
            # Only flag as minor if NOT trusted
            if not is_trusted:
                flags["reply_to_mismatch"] = True
                score += 2
                reasons.append("Reply-To address differs from the sender address (same domain).")
        
    # Cap score at 40
    score = min(score, 40)
    
    return {
        "flags": flags,
        "heuristic_score": score,
        "reasons": reasons
    }
