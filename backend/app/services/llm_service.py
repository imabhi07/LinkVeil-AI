import os
import json
import time
import asyncio
import logging
from typing import Optional
from pydantic import BaseModel, Field, ValidationError
from google import genai
from google.genai import types

logger = logging.getLogger(__name__)

# ── LLM response cache (URL → validated dict) ──
_llm_cache: dict[str, tuple[float, dict]] = {}
LLM_CACHE_TTL = 600  # 10 minutes — LLM results change less often than probe results

# ── Gemini Model Rotation Stack ──
# If one model hits quota limits (429), we fall back through the list
AVAILABLE_MODELS = [
    "gemini-3.1-flash-lite",
    "gemini-3-flash",
    "gemini-2.5-flash",
    "gemini-2.5-flash-lite",
    "gemini-2.0-flash",
    "gemini-1.5-flash",
    "gemini-1.5-flash-8b",
]


class RiskAnalysis(BaseModel):
    """
    Validates and coerces the raw JSON returned by Gemini.
    Using this instead of raw json.loads() catches bad types early
    (e.g. riskScore returned as "85" string instead of 85 int).
    """
    riskScore: float = Field(default=50.0, ge=0, le=100)
    risk_level: str = Field(default="Unknown")
    explanation: str = Field(default="No explanation provided.")
    brand_impersonation: bool = Field(default=False)
    brand_name: Optional[str] = Field(default=None)
    verdictTitle: Optional[str] = Field(default=None)
    technicalDetails: Optional[dict] = Field(default=None)
    forensicData: Optional[dict] = Field(default=None)
    mitigationAdvice: Optional[list[str]] = Field(default=None)
    agentReport: Optional[dict] = Field(default=None)

    def model_post_init(self, __context):
        level = self.risk_level.strip().capitalize()
        if level not in ("Low", "High"):
            level = "Unknown"
        self.risk_level = level


# ── Pre-built Gemini client singleton ──
_client: Optional[genai.Client] = None


def _get_client():
    global _client
    if _client is None:
        api_key = os.environ.get("GEMINI_API_KEY")
        if api_key and api_key != "your_api_key_here":
            _client = genai.Client(api_key=api_key)
    return _client


SYSTEM_INSTRUCTION = """You are "LinkVeil Sentinel", a Tier-3 AI Cybersecurity Forensic Analyst. Your mission is to provide surgical, data-driven URL threat assessments.

Tone: Professional, clinical, precise, and authoritative. Use terminology like "Entropy", "TLD Variance", "Heuristic Mismatch", "SSL Stripping Potential", and "Credential Harvester".

TASKS:
1. **DEEP URL ANALYSIS**:
   - Calculate perceived "visual entropy" (too many random chars/dots).
   - Check for Typosquatting (roblox -> robioox).
   - Check for Homoglyph attacks (googIe.com vs google.com).
   - Identify suspicious subdomains (login.secure.verify.amazon.com.ru).
2. **HEURISTIC VISUAL FORENSICS**:
   - Predict if the page uses known "Phishing Kits" (e.g., Evilginx, Phishlet).
   - Identify "Brand Shadowing" where a legitimate service name is used in a path on a completely unrelated domain.
3. **ACTOR TACTICS (TTPs)**:
   - Identify likely Social Engineering hooks (Urgency, Reward, Verification).
   - Analyze query parameters for tracking IDs or base64 encoded user emails (common in spearphishing).
4. **FREE HOSTING & CLOUD ABUSE**:
   - Legitimate brands host login/auth on dedicated private infrastructure.
   - Any login portal on github.io, netlify.app, vercel.app, firebaseapp.com, web.app, etc., should be flagged as HIGH RISK brand impersonation unless it is the developer's own site.
5. **CALIBRATION — AVOID FALSE POSITIVES**:
   - Standard SaaS signup/login pages (e.g., lovable.dev/signup, vercel.com/login) on their OWN domain are LEGITIMATE. Do not inflate scores for normal authentication UIs.
   - Query parameters like `?ref=`, `?utm_`, `?source=` are standard marketing/affiliate referral codes, NOT spearphishing tracking IDs. Only flag query params if they contain base64-encoded email addresses or obfuscated redirect chains.
   - A page having a signup or login form does NOT make it phishing. Phishing requires the domain to be impersonating ANOTHER brand.
   - **SECURITY TOOLS & REPOS**: Do not penalize URLs just because they contain words like "PhishGuard", "LinkVeil", "Security", or "Exploit" if they are clearly on a legitimate developer platform like GitHub or a security company's blog. These are educational/defensive tools, not threats.
   - If the domain is well-known (GitHub, Microsoft, Google, etc.) or clearly belongs to a real company/product, the riskScore should be VERY LOW (0-15) unless there is concrete evidence of a file-based exploit or hosted malware.

OUTPUT FORMAT:
Return a valid JSON object.
- riskScore: 0-100 (Integer).
- risk_level: "Low" | "High".
- explanation: A professional, 6-8 bullet point summary of core findings.
- technicalDetails:
    - "urlDeepDive": Expert analysis of the URL's structure and entropy.
    - "domainForensics": Analysis of the TLD, registrar patterns, and impersonation intent.
    - "socialEngineering": Detailed breakdown of the psychological manipulation used.
- forensicData:
    - "threatTactics": Analysis of the likely phishing kit or redirection chain.
    - "visualPrediction": Description of expected UI elements (favicon spoofing, fake SSL badges).
- mitigationAdvice: List of 3-4 actionable steps for the end-user.
- **verdictTitle**: A short, punchy forensic summary (3-5 words) that summarizes the core finding (e.g., "Credential Harvester Detected", "Legitimate Domain Verified", "Suspicious Homoglyph Pattern").

JSON structure:
{
  "riskScore": number,
  "risk_level": "High/Medium/Low",
  "explanation": "Expert summary...",
  "brand_impersonation": boolean,
  "brand_name": "Target Brand Name",
  "verdictTitle": "Dynamic Forensic Title",
  "technicalDetails": {"urlDeepDive": "...", "domainForensics": "...", "socialEngineering": "..."},
  "forensicData": {"threatTactics": "...", "visualPrediction": "..."},
  "mitigationAdvice": ["Step 1", "Step 2", "Step 3"],
  "agentReport": {"visualForensics": {"analyzed": true, "brandImpersonation": "...", "hostingMismatch": "..."}}
}"""


async def analyze_url(url: str, features: dict) -> dict:
    """
    Analyzes a URL using Gemini and structured outputs.
    Optimizations: singleton client, LLM response cache, retry with backoff.
    """
    fallback = {
        "riskScore": 50.0,
        "risk_level": "Unknown",
        "explanation": "Analysis unavailable due to API error.",
        "brand_impersonation": False,
        "brand_name": None,
        "recommendation": "⚠️ Caution: Detailed analysis unavailable."
    }

    # ── Check LLM cache ──
    if url in _llm_cache:
        ts, cached = _llm_cache[url]
        if time.time() - ts < LLM_CACHE_TTL:
            logger.info(f"LLM cache HIT for {url}")
            return cached
        else:
            del _llm_cache[url]

    client = _get_client()
    if client is None:
        logger.warning("GEMINI_API_KEY not set or invalid. Using fallback.")
        fallback["explanation"] = "API Error: GEMINI_API_KEY environment variable is missing or invalid."
        return fallback

    prompt = f'Investigate this URL: "{url}". Lexical features: {json.dumps(features)}. Analyze ONLY the URL structure, domain reputation signals, and lexical features provided. Do NOT simulate probing, form interactions, or credential testing — that is handled by a separate system.'

    # ── Model Rotation & Retry Loop ──
    for model_name in AVAILABLE_MODELS:
        # Retry with backoff
        max_retries = 2
        for attempt in range(max_retries + 1):
            try:
                logger.debug(f"Attempting analysis with {model_name} (attempt {attempt + 1})")
                response = await client.aio.models.generate_content(
                    model=model_name,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        system_instruction=SYSTEM_INSTRUCTION,
                        temperature=0.1,
                    ),
                )

                if response.text:
                    text = response.text.strip()
                    if text.startswith("```json"):
                        text = text[7:]
                    elif text.startswith("```"):
                        text = text[3:]
                    if text.endswith("```"):
                        text = text[:-3]

                    raw = json.loads(text.strip())
                    validated = RiskAnalysis(**raw)
                    result = validated.model_dump()

                    # Cache the result
                    _llm_cache[url] = (time.time(), result)
                    # Evict if too large
                    if len(_llm_cache) > 100:
                        oldest = min(_llm_cache, key=lambda k: _llm_cache[k][0])
                        del _llm_cache[oldest]

                    return result
                else:
                    logger.error(f"Empty response from {model_name}.")
                    break # Try next model

            except json.JSONDecodeError as e:
                logger.error(f"LLM returned non-JSON (model {model_name}, attempt {attempt + 1}): {e}")
                if attempt < max_retries:
                    await asyncio.sleep(1)
                    continue
                break # Try next model

            except ValidationError as e:
                logger.error(f"LLM response failed Pydantic validation: {e}")
                break # Try next model

            except Exception as e:
                error_msg = str(e)
                is_quota_error = any(kw in error_msg for kw in ["429", "RESOURCE_EXHAUSTED", "QUOTA_EXHAUSTED"])
                is_not_found = any(kw in error_msg for kw in ["404", "NOT_FOUND"])
                
                if is_quota_error:
                    if attempt < max_retries:
                        wait_time = 5 * (attempt + 1)
                        logger.warning(f"Quota exhausted for {model_name} (attempt {attempt + 1}), waiting {wait_time}s...")
                        await asyncio.sleep(wait_time)
                        continue
                    else:
                        logger.warning(f"Quota exhausted for {model_name}. Falling back to next model.")
                        break
                    
                if is_not_found:
                    logger.warning(f"Model {model_name} not available (404). Falling back to next model if available.")
                    break # Immediately try next model in AVAILABLE_MODELS
                
                is_retryable = any(kw in error_msg for kw in ["503", "UNAVAILABLE", "deadline", "timeout"])

                if is_retryable and attempt < max_retries:
                    wait = 2 ** attempt
                    logger.warning(f"Retryable error for {model_name} (attempt {attempt + 1}), waiting {wait}s: {error_msg[:100]}")
                    await asyncio.sleep(wait)
                    continue

                logger.error(f"Critical error during LLM analysis with {model_name}: {e}")
                break # Try next model

    return fallback