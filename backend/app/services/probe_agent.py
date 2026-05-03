"""
probe_agent.py — LinkVeil Real Active Probe Agent
====================================================
Performs actual headless browser probing of URLs using Playwright.

Optimizations:
  - Reusable browser singleton (avoids 1-2s Chromium cold-start per request)
  - Stricter timeout cascade
  - Domain skip-list (handled by engine_service, but defended here too)

SETUP (one-time):
    pip install playwright
    playwright install chromium
"""

import asyncio
import logging
import re
import threading
import os
import hashlib
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, List, Dict
from dataclasses import dataclass, field
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

FAKE_USER = "test_admin@linkveil.local"
FAKE_PASS = "Phish@Guard#Fake!2024"

NAVIGATION_TIMEOUT_MS = 30000   # increased from 20s for heavy/global sites
FORM_WAIT_MS = 4000             # increased from 2.5s for modern JS/SPA rendering

TRUSTED_REDIRECT_DOMAINS = {
    "google.com", "google.co", "accounts.google.com",
    "microsoft.com", "live.com", "login.microsoftonline.com",
    "apple.com", "appleid.apple.com",
    "facebook.com", "github.com", "twitter.com", "x.com",
    "linkedin.com", "amazon.com", "yahoo.com",
    "netflix.com", "paytm.com", "flipkart.com", "spotify.com",
    "dropbox.com", "uber.com", "airbnb.com", "pinterest.com",
    "razorpay.com", "phonepe.com",
}


# ── Browser Singleton ──
_browser_lock = threading.Lock()
_pw_instance = None
_browser = None


def _get_browser():
    """
    Lazily launch a SHARED Chromium instance.
    Thread-safe. Reused across all probe calls to avoid cold-start overhead.
    """
    global _pw_instance, _browser
    if _browser is not None:
        try:
            # Quick health check — if browser crashed, re-launch
            _browser.contexts
            return _browser
        except Exception:
            _browser = None

    with _browser_lock:
        if _browser is not None:
            return _browser

        try:
            from playwright.sync_api import sync_playwright
            _pw_instance = sync_playwright().start()
            _browser = _pw_instance.chromium.launch(
                headless=True,
                args=[
                    '--no-sandbox',
                    '--disable-blink-features=AutomationControlled',
                    '--disable-dev-shm-usage',
                    '--disable-gpu',
                    '--disable-extensions',
                ],
            )
            logger.info("Playwright Chromium browser launched (singleton)")
            return _browser
        except Exception as e:
            logger.error(f"Failed to launch Chromium: {e}")
            return None


def _root_domain(url: str) -> str:
    try:
        host = urlparse(url).netloc.lower()
        parts = host.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return host
    except Exception:
        return ""


def _is_same_domain_family(url_a: str, url_b: str) -> bool:
    return _root_domain(url_a) == _root_domain(url_b)


def _is_trusted_domain(url: str) -> bool:
    root = _root_domain(url)
    return any(root == d or root.endswith("." + d) for d in TRUSTED_REDIRECT_DOMAINS)


def _get_friendly_error(err_str: str) -> str:
    err_lower = err_str.lower()
    if "err_name_not_resolved" in err_lower:
        return "The domain name does not exist or the address is typed incorrectly."
    if "err_connection_refused" in err_lower:
        return "The server exists but refused the connection."
    if "err_connection_timed_out" in err_lower or "timeout" in err_lower:
        return "The connection timed out before the page could load."
    if "err_connection_reset" in err_lower:
        return "The connection was unexpectedly reset by the server."
    if "err_cert_" in err_lower:
        return "There is a problem with the site's security certificate."
    if "err_network_changed" in err_lower:
        return "Network connection interrupted."

    if "page.goto:" in err_lower:
        try:
            clean = err_str.split("net::")[1].split(" at ")[0]
            return f"Network error ({clean})"
        except IndexError:
            return err_str.split("page.goto:")[1].strip().capitalize()

    return err_str


@dataclass
class ProbeResult:
    performed: bool = False
    reachable: bool = False
    credentials_used: str = f"{FAKE_USER} / ••••••••"
    outcome: str = "Probe not performed."
    behavior_risk: str = "Unknown"
    
    login_form_found: bool = False
    fields_filled: bool = False
    post_submit_redirect: Optional[str] = None
    accepted_fake_creds: bool = False
    
    page_title: Optional[str] = None
    final_url: Optional[str] = None
    error: Optional[str] = None
    
    # New Forensic Fields
    screenshot_path: Optional[str] = None
    redirect_chain: List[str] = field(default_factory=list)
    form_fields: Dict = field(default_factory=dict)
    content_snippet: str = ""

def _cleanup_screenshots(max_files: int = 50):
    """Deletes oldest screenshots if the folder exceeds max_files cap."""
    try:
        path = "data/screenshots"
        if not os.path.exists(path):
            return
            
        files = [os.path.join(path, f) for f in os.listdir(path) if f.endswith(".png")]
        if len(files) <= max_files:
            return
            
        # Sort by modification time (oldest first)
        files.sort(key=os.path.getmtime)
        
        # Delete excess files
        to_delete = files[:len(files) - max_files]
        for f in to_delete:
            try:
                os.remove(f)
                logger.debug(f"Removed old screenshot: {f}")
            except Exception:
                pass
        if to_delete:
            logger.info(f"Storage Management: Purged {len(to_delete)} legacy screenshots (Cap: {max_files}).")
    except Exception as e:
        logger.warning(f"Screenshot cleanup failed: {e}")


def run_probe(url: str) -> ProbeResult:
    """
    Synchronous probe — run via asyncio.to_thread() from async context.
    Uses a SHARED browser singleton to avoid cold-start overhead.
    """
    result = ProbeResult(performed=True)

    try:
        from playwright.sync_api import TimeoutError as PWTimeout
    except ImportError:
        result.error = "Playwright not installed. Run: pip install playwright && playwright install chromium"
        result.outcome = "Probe failed: Playwright not installed."
        result.behavior_risk = "Unknown"
        logger.error(result.error)
        return result

    browser = _get_browser()
    if browser is None:
        result.error = "Failed to launch browser"
        result.outcome = "Probe failed: Could not launch Chromium."
        result.behavior_risk = "Unknown"
        return result

    context = None
    try:
        context = browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            viewport={"width": 1280, "height": 800},
            ignore_https_errors=True,
        )
        page = context.new_page()

        # --- Track redirect chain ---
        page.on("response", lambda res: result.redirect_chain.append(res.url) if 300 <= res.status < 400 else None)

        # --- Step 1: Navigate ---
        try:
            # Set a standard desktop viewport to avoid mobile-style distortion
            page.set_viewport_size({"width": 1280, "height": 1080})
            
            # networkidle is better for ensuring all assets (CSS/JS) are loaded
            page.goto(url, timeout=NAVIGATION_TIMEOUT_MS, wait_until="networkidle")
            result.reachable = True
            
            # Small delay for final rendering
            page.wait_for_timeout(2000)
            
            result.page_title = page.title()
            result.final_url = page.url
            logger.info(f"Probe: loaded '{result.page_title}' at {result.final_url}")
            
            # --- Capture Screenshot ---
            url_hash = hashlib.md5(url.encode()).hexdigest()
            screenshot_path = f"data/screenshots/{url_hash}.png"
            os.makedirs("data/screenshots", exist_ok=True)
            # Removed full_page=True as it causes layout issues on some reactive sites
            page.screenshot(path=screenshot_path)
            result.screenshot_path = screenshot_path
            
            # --- Capture Content Snippet ---
            result.content_snippet = page.content()[:2000]
            
            # --- Storage Hygiene: Purge old evidence ---
            _cleanup_screenshots(max_files=50)

        except PWTimeout:
            try:
                if page.url and page.url != "about:blank":
                    result.final_url = page.url
                elif result.redirect_chain:
                    result.final_url = result.redirect_chain[-1]
            except Exception:
                pass
            result.reachable = False
            result.outcome = "Target offline — probe failed. The URL did not respond within the timeout window."
            result.behavior_risk = "Unknown"
            return result
        except Exception as e:
            try:
                if page.url and page.url != "about:blank":
                    result.final_url = page.url
                elif result.redirect_chain:
                    result.final_url = result.redirect_chain[-1]
            except Exception:
                pass
            result.reachable = False
            error_msg = str(e).split('\n')[0].split('Call log:')[0].strip()
            friendly_msg = _get_friendly_error(error_msg)
            result.outcome = f"Target unreachable — {friendly_msg}"
            result.behavior_risk = "Unknown"
            result.error = str(e)
            return result

        # --- Step 2: Detect login forms (handles multi-step flows) ---
        # Many legitimate sites (Netflix, Google, Microsoft) split login:
        # Step 1: email/phone → click Continue → Step 2: password appears.
        password_fields = page.query_selector_all('input[type="password"]')
        text_fields = page.query_selector_all(
            'input[type="text"], input[type="email"], input[type="tel"], input:not([type])'
        )
        
        # --- Collect Form Metadata ---
        result.form_fields = {
            "password_count": len(password_fields),
            "text_email_count": len(text_fields),
            "submit_button_count": len(page.query_selector_all('button[type="submit"], input[type="submit"]')),
            "has_login_indicators": any(kw in page.content().lower() for kw in ["sign in", "login", "password", "username"])
        }
        multi_step = False

        # Multi-step detection: no password field yet but text/email fields exist
        if not password_fields and text_fields:
            logger.info("No password field initially — probing for multi-step login flow")
            visible_text = [f for f in text_fields if f.is_visible()]
            if visible_text:
                try:
                    visible_text[0].fill(FAKE_USER)
                    page.wait_for_timeout(500)

                    step1_buttons = page.query_selector_all(
                        'button[type="submit"], input[type="submit"], '
                        'button:has-text("continue"), button:has-text("next"), '
                        'button:has-text("sign in"), button:has-text("log in"), '
                        'button:has-text("login"), button:has-text("signin"), '
                        'a:has-text("login"), a:has-text("sign in"), '
                        'div[role="button"]:has-text("login"), div[role="button"]:has-text("sign in")'
                    )
                    visible_btns = [b for b in step1_buttons if b.is_visible()]
                    if visible_btns:
                        visible_btns[0].click()
                    else:
                        visible_text[0].press("Enter")

                    # Wait for step 2 to render (JS-heavy forms need time)
                    page.wait_for_timeout(3000)

                    # Re-check for password field after advancing
                    password_fields = page.query_selector_all('input[type="password"]')
                    if password_fields:
                        multi_step = True
                        logger.info("Multi-step login confirmed — password field appeared after email step")
                except Exception as e:
                    logger.warning(f"Multi-step login probe failed: {e}")

        result.login_form_found = len(password_fields) > 0

        if not result.login_form_found:
            result.outcome = (
                f"No login form detected on target page. "
                f"Page title: '{result.page_title}'. "
                "The page does not appear to be a credential harvester — "
                "no password input fields were found in the DOM."
            )
            result.behavior_risk = "Low"
            return result

        # --- Step 3: Fill credentials ---
        logger.info(
            f"Probe: found {len(password_fields)} password field(s), "
            f"attempting fill (multi_step={multi_step})"
        )

        try:
            # Fill email/username ONLY if not already done in multi-step step 1
            if not multi_step:
                if text_fields:
                    visible_text = [f for f in text_fields if f.is_visible()]
                    if visible_text:
                        visible_text[0].fill(FAKE_USER)

            visible_pass = [f for f in password_fields if f.is_visible()]
            if visible_pass:
                visible_pass[0].fill(FAKE_PASS)
                result.fields_filled = True
        except Exception as e:
            logger.warning(f"Probe: could not fill fields: {e}")

        if not result.fields_filled:
            result.outcome = (
                "Login form detected but password field was not interactable "
                "(possibly hidden or JavaScript-gated). "
                "This is suspicious — phishing kits sometimes hide forms until JS loads."
            )
            result.behavior_risk = "Medium"
            return result

        pre_submit_url = page.url

        # --- Step 4: Submit ---
        # Re-detect submit buttons (page may have changed in multi-step flow)
        submit_buttons = page.query_selector_all(
            'button[type="submit"], input[type="submit"], button:has-text("login"), '
            'button:has-text("sign in"), button:has-text("submit"), button:has-text("continue")'
        )
        try:
            if submit_buttons:
                visible_buttons = [b for b in submit_buttons if b.is_visible()]
                if visible_buttons:
                    visible_buttons[0].click()
                else:
                    visible_pass[0].press("Enter")
            else:
                visible_pass[0].press("Enter")

            page.wait_for_timeout(FORM_WAIT_MS)
        except Exception as e:
            logger.warning(f"Probe: submit failed: {e}")

        # --- Step 5: Analyse post-submit behaviour ---
        post_submit_url = page.url
        post_title = page.title()
        result.final_url = post_submit_url

        url_changed = post_submit_url.rstrip('/') != pre_submit_url.rstrip('/')
        result.post_submit_redirect = post_submit_url if url_changed else None

        same_domain_redirect = url_changed and _is_same_domain_family(pre_submit_url, post_submit_url)
        cross_domain_redirect = url_changed and not _is_same_domain_family(pre_submit_url, post_submit_url)
        landing_on_trusted = _is_trusted_domain(post_submit_url)

        page_text = page.inner_text("body").lower()
        error_keywords = [
            "invalid", "incorrect", "wrong password", "failed", "error",
            "try again", "not found", "bad credentials", "unauthorized",
            "couldn't find", "doesn't match"
        ]
        success_keywords = [
            "welcome back", "dashboard", "logout", "sign out",
            "my profile", "inbox", "success", "verified", "you're in",
            "logged in", "my account"
        ]

        showed_error = any(kw in page_text for kw in error_keywords)
        showed_success = any(kw in page_text for kw in success_keywords)

        # --- Step 6: Classify ---
        if showed_error or same_domain_redirect:
            result.accepted_fake_creds = False
            result.behavior_risk = "Low"
            if showed_error:
                result.outcome = (
                    f"Fake credentials were correctly rejected — an error message was displayed. "
                    f"This is consistent with a legitimate service that validates credentials server-side. "
                    f"Page title after submit: '{post_title}'."
                )
            else:
                result.outcome = (
                    f"Redirect occurred within the same domain family "
                    f"({_root_domain(pre_submit_url)} → {_root_domain(post_submit_url)}). "
                    "This is normal SSO/auth flow behaviour, not a phishing signal. "
                    f"Page title: '{post_title}'."
                )

        elif cross_domain_redirect and not landing_on_trusted:
            result.accepted_fake_creds = True
            result.behavior_risk = "High"
            result.outcome = (
                f"⚠️  CREDENTIAL HARVESTER CONFIRMED: After submitting fake credentials, "
                f"the page redirected to a different domain: {post_submit_url}. "
                "Phishing kits harvest credentials silently then redirect to the real site "
                "to avoid suspicion. This cross-domain redirect is the defining signature."
            )

        elif cross_domain_redirect and landing_on_trusted:
            result.accepted_fake_creds = True
            result.behavior_risk = "High"
            result.outcome = (
                f"⚠️  LIKELY CREDENTIAL HARVESTER: Fake credentials were submitted and the page "
                f"redirected to a trusted domain ({_root_domain(post_submit_url)}). "
                "This is a classic phishing kit pattern — harvest credentials, "
                "then redirect the victim to the real site to avoid suspicion."
            )

        elif showed_success and not _is_trusted_domain(pre_submit_url):
            result.accepted_fake_creds = True
            result.behavior_risk = "High"
            result.outcome = (
                f"⚠️  CREDENTIAL HARVESTER CONFIRMED: Fake credentials were accepted "
                f"and a success-like response was shown on an untrusted domain. "
                "Legitimate services never accept obviously fake credentials. "
                f"Page title: '{post_title}'."
            )

        else:
            result.accepted_fake_creds = False
            result.behavior_risk = "Medium"
            result.outcome = (
                "Login form found and credentials submitted, but the response was ambiguous — "
                "no clear accept or reject signal detected. "
                f"{'Redirect to: ' + post_submit_url if url_changed else 'No redirect occurred.'} "
                "Manual review recommended."
            )

        return result

    except Exception as e:
        logger.error(f"Probe agent critical error for {url}: {e}")
        result.error = str(e)
        error_msg = str(e).split('\n')[0].split('Call log:')[0].strip()
        friendly_msg = _get_friendly_error(error_msg)
        result.outcome = f"Target unreachable — {friendly_msg}"
        result.behavior_risk = "Unknown"
        return result

    finally:
        # Always close context (NOT browser — it's shared)
        if context:
            try:
                context.close()
            except Exception:
                pass


# ── Dedicated single-thread executor for Playwright ──
# Playwright's sync API has strict thread affinity: the browser must always
# be accessed from the SAME thread it was created on. asyncio.to_thread()
# dispatches to random pool threads, causing "Cannot switch to a different
# thread" crashes. This executor pins ALL probe work to one persistent thread.
_probe_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="pw-probe")


async def run_probe_async(url: str) -> ProbeResult:
    """Async wrapper that always dispatches to the dedicated Playwright thread."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_probe_executor, run_probe, url)


def probe_result_to_dict(r: ProbeResult) -> dict:
    """Converts ProbeResult to the agentReport.activeProbing dict the frontend expects."""
    return {
        "performed": r.performed,
        "credentialsUsed": r.credentials_used,
        "outcome": r.outcome,
        "behaviorRisk": r.behavior_risk,
        "reachable": r.reachable,
        "loginFormFound": r.login_form_found,
        "fieldsFilled": r.fields_filled,
        "acceptedFakeCredentials": r.accepted_fake_creds,
        "postSubmitRedirect": r.post_submit_redirect,
        "pageTitle": r.page_title,
        "finalUrl": r.final_url,
        "error": r.error,
        # New Forensic Fields
        "screenshotPath": r.screenshot_path,
        "redirectChain": r.redirect_chain,
        "formFields": r.form_fields,
        "contentSnippet": r.content_snippet
    }