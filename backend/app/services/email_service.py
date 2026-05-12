import re
import tldextract
import unicodedata
from typing import List, Dict, Any, Optional

from backend.app.utils.forensics import Sanitizer, ForensicErrorEnvelope
from backend.app.services.engine_service import KNOWN_SAFE_DOMAINS

# Keyword lists based on requirements
URGENCY_PHRASES = [
    "act immediately", "action required", "within 24 hours", "suspended permanently",
    "final notice", "urgent security", "asap", "deadline approaching", "urgent", "immediately",
    "expires soon", "within 48 hours", "immediate attention", "restricted access",
    "last chance", "forfeited", "removed from your account", "will be removed", "48 hours",
    "limited time offer", "unlimited access", "one click away", "has been locked", "account locked"
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
    "premium entertainment", "subscription renewal", "entertainment service", "photos and videos"
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
            
        # SPF Misalignment Detection
        spf_val = auth.get("spf", "none").lower()
        if spf_val == "pass" and "return_path_mismatch" in mismatches:
            signals.append({
                "signal": "SPF Misalignment", 
                "points": 20, 
                "reason": "SPF passes for the envelope sender but the From domain is different. This SPF result does not authenticate the visible sender."
            })
            score_identity += 20
            reasons.append("SPF misalignment: Envelope and header sender domains differ.")
            
        dkim_val = auth.get("dkim", "none").lower()
        if dkim_val in ("fail", "permerror"):
            points = 25 if dkim_val == "fail" else 20
            signals.append({
                "signal": "DKIM Failure", 
                "points": points, 
                "reason": f"DKIM signature {dkim_val}: {'invalid or tampered' if dkim_val == 'fail' else 'signing key does not exist (forged signature)'}."
            })
            score_identity += points
            reasons.append(f"DKIM cryptographic signature {dkim_val}.")
        elif dkim_val == "temperror":
            signals.append({"signal": "DKIM Temporary Error", "points": 10, "reason": "DKIM lookup temporarily failed."})
            score_identity += 10
            reasons.append("DKIM lookup temporarily unavailable.")
            
        dmarc_val = auth.get("dmarc", "none").lower()
        if dmarc_val == "fail":
            signals.append({"signal": "DMARC Failure", "points": 35, "reason": "DMARC policy failed."})
            score_identity += 35
            reasons.append(f"DMARC policy failure: high risk of spoofing for {from_email.split('@')[-1]}.")
        elif dmarc_val == "none" and from_domain not in KNOWN_SAFE_DOMAINS:
            signals.append({
                "signal": "Missing DMARC", 
                "points": 15, 
                "reason": "Sender domain has no DMARC policy — no spoofing protection."
            })
            score_identity += 15
            reasons.append(f"Missing DMARC: Domain '{from_domain}' has no anti-spoofing policy.")
            
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
            
        # 4. Social Engineering (Scan Subject + Body)
        combined_content = f"{parsed_data.get('subject', '')}\n\n{parsed_data.get('clean_body', '')}"
        se_results = analyze_social_engineering(combined_content)
        score_linguistic = se_results["overall_threat"]
        
        # ── 5. Safe Harbor Logic (Anti-False-Positive) ──
        is_safe_harbor = False
        # If DMARC/SPF pass and domain is high-authority, suppress linguistic flags
        dmarc = auth.get("dmarc", "none").lower()
        spf = auth.get("spf", "none").lower()
        dkim = auth.get("dkim", "none").lower()
        
        # Check if from_domain is in a list of trusted high-authority domains
        is_trusted_brand = from_domain in KNOWN_SAFE_DOMAINS
        
        # Determine dampening factor
        dampener = 1.0
        if dmarc == "pass" and dkim == "pass" and spf == "pass" and is_trusted_brand:
            dampener = 0.1  # 90% reduction for authenticated trusted brands
            is_safe_harbor = True
            signals.append({"signal": "Safe Harbor", "points": -50, "reason": f"Verified official communication from {from_domain}. Forensic flags suppressed."})
            reasons.append(f"Trust Signal: This is a cryptographically verified email from the official {from_domain} domain.")
        elif dmarc == "pass" and is_trusted_brand:
            dampener = 0.3 # 70% reduction if at least DMARC passes
            reasons.append(f"Trust Signal: Authenticated brand communication ({from_domain}).")
            
        se_weighted = (score_linguistic * 0.4) * dampener
        if se_weighted > 0:
            categories = ", ".join(list(set(m['category'] for m in se_results['matches'])))
            signals.append({
                "signal": "Social Engineering", 
                "points": round(se_weighted), 
                "reason": f"Linguistic analysis detected {categories} patterns."
            })
        
        # Calculate final combined email score
        total_email_score = min(score_identity + se_weighted, 100)
        
        # If it's a perfect Safe Harbor, ensure score is low
        if dampener < 0.2:
            total_email_score = min(total_email_score, 15.0)
        
        # Update parsed data for downstream UI
        if "identity" in parsed_data:
            parsed_data["identity"]["is_safe_harbor"] = is_safe_harbor
        
        return {
            "score": round(total_email_score, 2),
            "score_identity": min(score_identity, 100),
            "score_linguistic": min(score_linguistic, 100),
            "reasons": reasons,
            "signals": signals,
            "social_engineering": se_results,
            "functional_description": ForensicsBrain.get_email_functional_description(parsed_data, {
                "score": total_email_score,
                "social_engineering": se_results
            })
        }

    @staticmethod
    def get_email_functional_description(parsed_data: Dict[str, Any], email_risk: Dict[str, Any]) -> str:
        """Generates a professional description of the email's intent."""
        from_domain = parsed_data.get("identity", {}).get("from", {}).get("domain", "the sender's domain")
        se_results = email_risk.get("social_engineering", {})
        se_matches = se_results.get("matches", [])
        
        if not se_matches:
            if email_risk.get("score", 0) < 20:
                return f"This communication appears to be a standard informational or transactional message from the {from_domain} infrastructure."
            return f"This email is a general communication originating from {from_domain}, currently undergoing forensic verification."

        # Find the most prominent category
        category = se_matches[0]["category"]
        if category == "Urgency":
            return f"This email serves as an urgent administrative notification from {from_domain}, requiring immediate user intervention."
        if category == "Credential Lure":
            return f"This communication is an identity verification request from {from_domain}, designed to facilitate account or password management."
        if category == "Financial Bait":
            return f"This message is a billing-related notification from {from_domain}, pertaining to transaction processing or invoice management."
        if category == "Authority Impersonation":
            return f"This email is structured as an official system administration notice from the {from_domain} support desk."
            
        return f"This is a {category.lower()} notification originating from {from_domain} intended for user-targeted communication."


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
        elif link_score == 0:
            # No links extracted — email signals are the ONLY evidence
            # Don't dilute them with a zero link score
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
