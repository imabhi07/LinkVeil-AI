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
    agentReport: Optional[dict] = Field(default=None)

    def model_post_init(self, __context):
        level = self.risk_level.strip().capitalize()
        if level not in ("Low", "Medium", "High"):
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


# ── Compact system instruction (trimmed tokens vs original) ──
SYSTEM_INSTRUCTION = """You are "PhishGuard Agent", an autonomous AI Cyber-Analyst.
Investigate suspicious URLs by simulating human analyst behavior using Active Probing and Visual Forensics.
Since you cannot browse the live web, perform a HIGH-FIDELITY SIMULATION based on URL patterns and phishing kit knowledge.

Tasks:
1. **Active Probing**: Analyze if the URL fits credential harvester patterns. If it looks like a login page, simulate fake credential injection (User: "test_admin", Pass: "123456"). Phishing kits accept ANY credentials and redirect to the real site.
2. **Visual Forensics**: Predict visual appearance. Does the URL imply brand impersonation? Is there a hosting mismatch?
3. **Brand Verification**: CRITICAL — If the URL IS the official domain of a major brand (google.com, paypal.com etc.), classify as "Low" risk. ONLY flag impersonators/typosquats.
4. **Suspicious (Medium)**: URL shorteners, uncommon TLDs without brand impersonation, or ambiguous URLs = "Medium". Use "High" ONLY for active deception/mimicry.

Output: Return a valid JSON object (no markdown fences). riskScore MUST be a number. Include 4-5 detailed bullet points in explanation. technicalDetails fields must be full paragraphs.

JSON structure:
{"riskScore": number(0-100), "risk_level": "Low"|"Medium"|"High", "explanation": "string", "brand_impersonation": boolean, "brand_name": string|null, "verdictTitle": string, "technicalDetails": {"urlStructure": string, "domainReputation": string, "socialEngineeringTricks": string}, "agentReport": {"activeProbing": {"performed": true, "credentialsUsed": "User: test_admin | Pass: *******", "outcome": string, "behaviorRisk": "High"|"Medium"|"Low"}, "visualForensics": {"analyzed": true, "brandImpersonation": string, "hostingMismatch": string}}}"""


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

    prompt = f'Investigate this URL: "{url}". Features: {json.dumps(features)}. Perform active probing simulation and visual forensics analysis.'

    # ── Retry with exponential backoff (handles transient 429/5xx) ──
    max_retries = 2
    for attempt in range(max_retries + 1):
        try:
            response = await client.aio.models.generate_content(
                model='gemini-2.5-flash-lite',
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
                logger.error("Empty response from LLM.")
                return fallback

        except json.JSONDecodeError as e:
            logger.error(f"LLM returned non-JSON (attempt {attempt + 1}): {e}")
            if attempt < max_retries:
                await asyncio.sleep(1)
                continue
            return fallback

        except ValidationError as e:
            logger.error(f"LLM response failed Pydantic validation: {e}")
            return fallback

        except Exception as e:
            error_msg = str(e)
            is_retryable = any(kw in error_msg for kw in ["429", "RESOURCE_EXHAUSTED", "503", "UNAVAILABLE"])

            if is_retryable and attempt < max_retries:
                wait = 2 ** attempt  # 1s, 2s
                logger.warning(f"Retryable LLM error (attempt {attempt + 1}), waiting {wait}s: {error_msg[:100]}")
                await asyncio.sleep(wait)
                continue

            logger.error(f"LLM Error during analyze_url: {e}")
            if "429" in error_msg or "RESOURCE_EXHAUSTED" in error_msg:
                fallback["explanation"] = "LLM Contextual Analysis temporarily unavailable: API Rate Limit Exceeded. Please wait 1 minute and scan again."
            else:
                fallback["explanation"] = f"API Error: {error_msg}"
            return fallback

    return fallback