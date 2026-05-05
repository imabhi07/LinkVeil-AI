import re
import tldextract
import unicodedata
from typing import List, Dict, Any, Optional

from backend.app.utils.forensics import Sanitizer, ForensicErrorEnvelope

# Keyword lists based on requirements
URGENCY_PHRASES = [
    "act immediately", "action required", "within 24 hours", "suspended permanently",
    "final notice", "urgent security", "asap", "deadline approaching", "urgent", "immediately",
    "expires soon", "within 48 hours", "immediate attention", "restricted access",
    "last chance", "forfeited", "removed from your account", "will be removed", "48 hours",
    "limited time offer", "unlimited access", "one click away"
]

CREDENTIAL_PHRASES = [
    "verify your account", "confirm your identity", "sign-in detected",
    "reset your password", "authorize access", "validate credentials",
    "login to your", "security verification", "one-time passcode", "otp is",
    "verify", "credentials", "password reset", "confirm details", "identify verification",
    "confirm your info", "verify*", "account information"
]

BILLING_PHRASES = [
    "invoice for", "payment received", "payment failed", "refund processed",
    "transaction details", "billing statement", "subscription active", 
    "overdue balance", "receipt for", "card ending in", "payment of", "received a payment",
    "wire transfer", "unpaid invoice", "remittance", "payment confirmation",
    "payout verification", "$7000.00", "free spins", "millionaire’s life", "unclaimed rewards",
    "casino limitless", "chips will be forfeited", "iptv", "sports, movies & tv",
    "premium entertainment", "subscription renewal", "entertainment service"
]

IMPERSONATION_PHRASES = [
    "official support", "security desk", "verification center", "system administrator",
    "help desk team", "billing department", "no-reply@", "support", "helpdesk", "administrator",
    "entertainment service"
]

def analyze_social_engineering(text: str) -> Dict[str, Any]:
    """Analyzes text for social engineering lures with detailed snippets."""
    text_lower = text.lower()
    matches = []
    score = 0
    
    categories = [
        ("Urgency", URGENCY_PHRASES, 30),
        ("Credential Lure", CREDENTIAL_PHRASES, 35),
        ("Financial Bait", BILLING_PHRASES, 40),
        ("Authority Impersonation", IMPERSONATION_PHRASES, 20),
        ("Deceptive Lures", ["lottery", "winner", "inheritance", "bitcoin", "crypto", "account shutdown", "security alert", "suspicious activity", "locked account"], 25)
    ]

    for category, phrases, weight in categories:
        for phrase in phrases:
            if phrase in text_lower:
                # Find the actual snippet in original case
                idx = text_lower.find(phrase)
                start = max(0, idx - 30)
                end = min(len(text), idx + len(phrase) + 30)
                snippet = text[start:end].replace("\n", " ").strip()
                
                matches.append({
                    "category": category,
                    "keyword": phrase,
                    "snippet": snippet,
                    "confidence": "HIGH"
                })
                score += weight
                break # One match per category to avoid score bloat
        
    return {
        "overall_threat": min(score, 100),
        "matches": matches
    }

class ForensicsBrain:
    """
    Core logic for fusing email and link analysis into a single forensic verdict.
    """
    
    @staticmethod
    def calculate_email_risk(parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculates risk based on identity, auth, and content. Returns granular scores."""
        score_identity = 0
        score_linguistic = 0
        reasons = []
        signals = []
        
        identity = parsed_data.get("identity", {})
        auth = parsed_data.get("auth", {})
        html_findings = parsed_data.get("html_findings", {})
        
        # 1. Identity Analysis
        mismatches = identity.get("mismatches", [])
        from_email = identity.get("from", {}).get("email", "sender")
        from_domain = identity.get("from", {}).get("domain", "").lower()
        
        if identity.get("has_unicode_obfuscation"):
            signals.append({"signal": "Unicode Obfuscation", "points": 35, "reason": "Subject uses stylized Unicode characters to bypass filtering."})
            score_identity += 35
            reasons.append("Anti-evasion hit: Stylized Unicode characters detected in subject line.")

        # Infrastructure Consensus (Pre-Flagged)
        if auth.get("provider_flagged_spam"):
            signals.append({"signal": "Infrastructure Junk", "points": 40, "reason": "Mail server has already flagged this message as SPAM/Junk."})
            score_identity += 40
            reasons.append("Technical Consensus: Message was pre-flagged as junk by the sending/receiving provider.")

        if "reply_to_mismatch" in mismatches:
            rt_email = identity.get("reply_to", {}).get("email", "unknown")
            rt_domain = identity.get("reply_to", {}).get("domain", "").lower()
            
            p = 35
            msg = f"Reply-To '{rt_email}' does not match From '{from_email}'."
            if rt_domain and from_domain and rt_domain != from_domain:
                p += 15
                msg += " (Critical: Different Domain detected)"
            
            signals.append({"signal": "Reply-To Mismatch", "points": p, "reason": msg})
            score_identity += p
            reasons.append(f"Identity Discrepancy: Reply-To ({rt_email}) mismatch.")
            
        if "return_path_mismatch" in mismatches:
            rp_email = identity.get("return_path", {}).get("email", "unknown")
            signals.append({"signal": "Return-Path Mismatch", "points": 30, "reason": "Return-Path discrepancy: potential sender spoofing."})
            score_identity += 30
            reasons.append(f"Return-Path Mismatch: Sender '{from_email}' differs from route '{rp_email}'.")
            
        # 2. Authentication Analysis
        if auth.get("spf") == "fail":
            signals.append({"signal": "SPF Failure", "points": 30, "reason": "Sender Policy Framework check failed."})
            score_identity += 30
            reasons.append(f"SPF authentication failed for {from_email.split('@')[-1]}.")
        elif auth.get("spf") == "none":
            signals.append({"signal": "Missing SPF", "points": 10, "reason": "Domain has no SPF record."})
            score_identity += 10
            reasons.append(f"Missing SPF record: Domain '{from_email.split('@')[-1]}' identity unverified.")
            
        if auth.get("dkim") == "fail":
            signals.append({"signal": "DKIM Failure", "points": 25, "reason": "DKIM signature invalid or tampered."})
            score_identity += 25
            reasons.append("DKIM cryptographic signature invalid.")
            
        if auth.get("dmarc") == "fail":
            signals.append({"signal": "DMARC Failure", "points": 35, "reason": "DMARC policy failed."})
            score_identity += 35
            reasons.append(f"DMARC policy failure: high risk of spoofing for {from_email.split('@')[-1]}.")
            
        # 3. HTML & Link Analysis
        shorteners = ["t.co", "bit.ly", "tinyurl.com", "cutt.ly", "shorturl.at", "ow.ly", "goo.gl", "is.gd"]
        found_shorteners = [u for u in (parsed_data.get("links") or []) if any(s in u.lower() for s in shorteners)]
        if found_shorteners:
            signals.append({"signal": "Evasive Link Strategy", "points": 20, "reason": f"Detected {len(found_shorteners)} link shortener(s) used to mask destination."})
            score_identity += 20
            reasons.append("Forensic hit: Usage of link shorteners to obfuscate target destination.")

        if html_findings.get("zero_width_chars_found"):
            signals.append({"signal": "Unicode Obfuscation", "points": 40, "reason": "Zero-width characters detected."})
            score_identity += 40
            reasons.append("Zero-width characters detected in HTML content (Anti-evasion hit).")
            
        if html_findings.get("hidden_html"):
            hidden_count = len(html_findings.get("hidden_html", []))
            signals.append({"signal": "Hidden Elements", "points": 30, "reason": f"Detected {hidden_count} hidden HTML element(s)."})
            score_identity += 30
            reasons.append(f"Hidden HTML: Found {hidden_count} elements used to hide text or links.")
            
        if html_findings.get("link_mismatches"):
            mismatch_count = len(html_findings.get("link_mismatches", []))
            signals.append({"signal": "Deceptive Hyperlink", "points": 45, "reason": "Visible text domain mismatch."})
            score_identity += 45
            reasons.append(f"Deceptive links: {mismatch_count} instances where link text hides a different destination.")
            
        # 4. Social Engineering
        se_results = analyze_social_engineering(parsed_data.get("clean_body", ""))
        score_linguistic = se_results["overall_threat"]
        se_weighted = score_linguistic * 0.4
        if se_weighted > 0:
            signals.append({"signal": "Social Engineering", "points": int(se_weighted), "reason": f"Detected {len(se_results['matches'])} threat patterns."})
        
        # Calculate final combined email score
        total_email_score = min(score_identity + se_weighted, 100)
        
        return {
            "score": round(total_email_score, 2),
            "score_identity": min(score_identity, 100),
            "score_linguistic": min(score_linguistic, 100),
            "reasons": reasons,
            "signals": signals,
            "social_engineering": se_results
        }


    @staticmethod
    def fuse_verdict(email_score: float, link_score: float) -> Dict[str, Any]:
        """
        Fuses email and link scores. 
        Rule: Link score is the 'payload', email score is the 'intent'.
        """
        final_score = 0
        source = "tie"
        
        if link_score >= 70:
            # High-risk link found, this is the primary driver
            final_score = link_score
            source = "link"
        elif email_score >= 80:
            # Extremely high forensic intent found
            final_score = email_score
            source = "email"
        else:
            # Balanced fusion
            # Balanced fusion: Give more weight to whichever is higher if both are significant
            if link_score > 30 and email_score > 30:
                final_score = (link_score * 0.5) + (email_score * 0.5)
            else:
                final_score = (link_score * 0.6) + (email_score * 0.4)
            source = "link" if link_score > email_score else "email"
            
        label = "safe"
        if final_score >= 75: label = "malicious"
        elif final_score >= 40: label = "suspicious"
        
        return {
            "final_score": round(final_score, 2),
            "verdict_label": label,
            "final_verdict_source": source
        }

    @staticmethod
    def judge_confidence(email_data: Dict[str, Any], link_results: List[Any]) -> Dict[str, Any]:
        """Judges how confident we are in the result."""
        reasons = []
        level = "high"
        
        if not link_results and email_data.get("triage_stats", {}).get("analyzed", 0) > 0:
            level = "low"
            reasons.append("Link analysis failed or timed out.")
        
        auth = email_data.get("auth", {})
        if auth.get("spf") == "none" and auth.get("dkim") == "none":
            reasons.append("Unauthenticated sender: identity remains unverified.")
            if level != "low": level = "medium"
            
        if not reasons:
            reasons.append("Multiple forensic engines aligned on verdict.")
            
        return {"level": level, "reasons": reasons}
