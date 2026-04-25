"""
vision_service.py
-----------------
Visual phishing detection using Gemini Vision Multimodal LLM.
Analyzes full-page screenshots to detect brand impersonation attempts visually.
"""

import os
import json
import logging
import asyncio
from PIL import Image
from typing import Optional
from pydantic import BaseModel, Field

from google import genai
from google.genai import types
from backend.app.services.llm_service import _get_client, AVAILABLE_MODELS

logger = logging.getLogger(__name__)

class VisionAnalysis(BaseModel):
    brand_logo_guess: Optional[str] = Field(description="The primary brand being impersonated (e.g. 'Netflix', 'Google', 'Microsoft'). Return None if no clear brand is found.")
    confidence: float = Field(description="Confidence score from 0.0 to 1.0 of the visual brand match.")

class VisionService:
    def __init__(self):
        pass

    async def analyze_screenshot(self, screenshot_path: str) -> dict:
        """
        Passes the screenshot to Gemini Vision to detect visual brand impersonation.
        Returns {
            "visual_score": float (0-1),
            "brand_logo_guess": str | None,
            "similarity_distance": int | None,
            "phash": str
        }
        """
        fallback = {"visual_score": 0.0, "brand_logo_guess": None, "phash": "AI-VISION-FAILED"}
        
        if not os.path.exists(screenshot_path):
            logger.warning(f"Screenshot not found at {screenshot_path}")
            return fallback

        client = _get_client()
        if client is None:
            logger.warning("GEMINI_API_KEY not set. Visual forensic unavailable.")
            return fallback

        try:
            with Image.open(screenshot_path) as img:
                # Resize image slightly to save tokens if it's massive
                img.thumbnail((1280, 1280))
                
                prompt = (
                    "Analyze this screenshot of a webpage. What famous brand, company, or service is the *primary* subject of this page? "
                    "Is the page actively trying to impersonate them? "
                    "CRITICAL: Ignore generic 'Sign in with [Brand]', 'Continue with [Brand]', or 'Login with [Brand]' SSO (Single Sign-On) buttons. "
                    "Only output a brand if the ENTIRE PAGE is designed to look like that brand's official page (e.g., a fake Google login page). "
                    "Return your answer strictly as a JSON object matching this schema: "
                    "{\"brand_logo_guess\": \"BrandName\" or null, \"confidence\": float between 0.0 and 1.0}."
                )

                for model_name in AVAILABLE_MODELS:
                    max_retries = 2
                    for attempt in range(max_retries + 1):
                        try:
                            logger.debug(f"Attempting visual analysis with {model_name} (attempt {attempt + 1})")
                            response = await client.aio.models.generate_content(
                                model=model_name,
                                contents=[img, prompt],
                                config=types.GenerateContentConfig(
                                    temperature=0.1,
                                    response_mime_type="application/json",
                                    response_schema=VisionAnalysis,
                                )
                            )

                            if response.text:
                                raw = json.loads(response.text.strip())
                                score = float(raw.get("confidence", 0.0))
                                brand = raw.get("brand_logo_guess")
                                
                                # Strip Markdown from brand name if LLM hallucinated markdown
                                if isinstance(brand, str) and brand.lower() == "null":
                                    brand = None

                                return {
                                    "visual_score": round(score, 4),
                                    "brand_logo_guess": brand if score >= 0.5 else None,
                                    "similarity_distance": 0, # Legacy field
                                    "phash": "AI-VISION-MATCH",
                                    "score": round(score, 4),
                                    "brand_match": brand if score >= 0.5 else None
                                }
                            else:
                                logger.error(f"Empty visual response from {model_name}.")
                                break

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
                                    break
                                
                            if is_not_found:
                                break
                            
                            is_retryable = any(kw in error_msg for kw in ["503", "UNAVAILABLE", "deadline", "timeout"])
                            if is_retryable and attempt < max_retries:
                                wait = 2 ** attempt
                                await asyncio.sleep(wait)
                                continue
                            
                            break # Try next model
                            
        except Exception as e:
            logger.error(f"Error preparing image for VisionService: {e}")
            
        return fallback

# Singleton
vision_service = VisionService()
