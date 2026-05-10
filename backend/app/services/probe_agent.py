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

FAKE_USER = "security.audit@gmail.com"
FAKE_PASS = "Audit#Verify_992!Auth"

NAVIGATION_TIMEOUT_MS = 30000   # increased from 20s for heavy/global sites
FORM_WAIT_MS = 4000             # increased from 2.5s for modern JS/SPA rendering

TRUSTED_REDIRECT_DOMAINS = {
    "google.com", "google.co", "accounts.google.com", "gmail.com",
    "microsoft.com", "live.com", "login.microsoftonline.com", "outlook.com", "office.com",
    "apple.com", "appleid.apple.com", "icloud.com",
    "facebook.com", "fb.com", "instagram.com", "github.com", "twitter.com", "x.com",
    "linkedin.com", "amazon.com", "amazon.in", "yahoo.com",
    "paytm.com", "flipkart.com", "spotify.com",
    "dropbox.com", "uber.com", "airbnb.com", "pinterest.com",
    "razorpay.com", "phonepe.com", "stripe.com", "paypal.com",
    "slack.com", "trello.com", "zoom.us", "canva.com",
    "discord.com", "discord.gg", "atlassian.com", "jira.com", "bitbucket.org", "gitlab.com",
    "adobe.com", "salesforce.com", "okta.com", "auth0.com",
    "vercel.com", "vercel.app", "netlify.com", "netlify.app", "digitalocean.com",
    "heroku.com", "cloudflare.com", "notion.so", "figma.com", "intercom.com"
}



# ── Browser Thread-Local Storage ──
_thread_local = threading.local()

def _get_browser():
    """
    Lazily launch a thread-local Chromium instance.
    Reused across probe calls on the same thread to avoid cold-start overhead,
    while completely avoiding cross-thread Playwright crashes.
    """
    if hasattr(_thread_local, 'browser') and _thread_local.browser is not None:
        try:
            # Quick health check — if browser crashed, re-launch
            _thread_local.browser.contexts
            return _thread_local.browser
        except Exception:
            _thread_local.browser = None
            _thread_local.pw_instance = None

    try:
        from playwright.sync_api import sync_playwright
        _thread_local.pw_instance = sync_playwright().start()
        _thread_local.browser = _thread_local.pw_instance.chromium.launch(
            headless=True,
            args=[
                '--no-sandbox',
                '--disable-blink-features=AutomationControlled',
                '--disable-dev-shm-usage',
                '--disable-gpu',
                '--disable-extensions',
            ],
        )
        logger.info(f"Playwright Chromium browser launched on thread {threading.get_ident()}")
        return _thread_local.browser
    except Exception as e:
        logger.error(f"Failed to launch Chromium on thread {threading.get_ident()}: {e}")
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
    explicitly_offline: bool = False # NEW: True ONLY for NXDOMAIN/Refused, not for Timeouts
    
    # New Forensic Fields
    screenshot_path: Optional[str] = None # Deprecated: use screenshots list
    screenshots: List[str] = field(default_factory=list)
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
            
            # Identify if it's a known aggressive bot-blocker
            headers = {}
            if "t.co" in url or "wa.me" in url:
                # Mimic a click from a social app or standard browser
                headers["Referer"] = "https://t.co/" if "t.co" in url else "https://wa.me/"
            
            if headers:
                page.set_extra_http_headers(headers)
            
            # Use 'domcontentloaded' to avoid infinite timeouts on sites with websockets/streams.
            # Playwright automatically follows HTTP redirects, so this will trigger on the final page.
            # We handle heavy dynamic content with explicit scrolling and waits below.
            page.goto(url, timeout=NAVIGATION_TIMEOUT_MS, wait_until="domcontentloaded")
            result.reachable = True
            
            # Now wait for full load and additional time for dynamic assets/hydration
            try:
                page.wait_for_load_state("load", timeout=10000)
            except:
                pass 
            
            result.page_title = page.title()
            result.final_url = page.url
            logger.info(f"Probe: loaded '{result.page_title}' at {result.final_url}")
            
            # --- Capture Screenshot ---
            # Multi-stage wait for heavy media sites (like IPTV hubs)
            try:
                # Trigger lazy loading by scrolling
                page.evaluate("window.scrollTo(0, 800)")
                page.wait_for_timeout(1500)
                page.evaluate("window.scrollTo(0, 0)")
                # Wait for any transition animations or overlays to clear
                page.wait_for_timeout(3500)
            except Exception:
                page.wait_for_timeout(5000)
            
            url_hash = hashlib.md5(url.encode()).hexdigest()
            initial_screenshot = f"data/screenshots/{url_hash}_initial.png"
            os.makedirs("data/screenshots", exist_ok=True)
            page.screenshot(path=initial_screenshot)
            result.screenshots.append(initial_screenshot)
            result.screenshot_path = initial_screenshot # Fallback for old UI
            
            # --- Capture Content Snippet ---
            result.content_snippet = page.content()[:2000]
            
            # --- Storage Hygiene: Purge old evidence ---
            _cleanup_screenshots(max_files=50)

        except PWTimeout:
            # PARTIAL RECOVERY: If we have a URL, the site is technically ONLINE
            try:
                current_url = page.url
                if current_url and current_url != "about:blank":
                    result.reachable = True
                    result.final_url = current_url
                    result.page_title = page.title() or "Timed out (partial load)"
                    result.outcome = "Target reached but load timed out (partial data captured)."
                    
                    # Try to get a screenshot of what DID load
                    url_hash = hashlib.md5(url.encode()).hexdigest()
                    screenshot_path = f"data/screenshots/{url_hash}_partial.png"
                    os.makedirs("data/screenshots", exist_ok=True)
                    page.screenshot(path=screenshot_path)
                    result.screenshot_path = screenshot_path
                    result.content_snippet = page.content()[:2000]
                    logger.info(f"Probe: Partial recovery for {url}")
                    return result 
            except Exception:
                pass
            
            result.reachable = False
            result.explicitly_offline = False # Timeout != Offline
            result.outcome = "Probe timed out - site might be slow or blocking bots."
            return result
        except Exception as e:
            try:
                if page.url and page.url != "about:blank":
                    result.reachable = True
                    result.final_url = page.url
                    result.page_title = page.title() or "Error (partial load)"
            except Exception:
                pass
            
            if result.reachable:
                result.outcome = f"Target reached but encountered error: {str(e).splitlines()[0]}"
                return result
                
            result.reachable = False
            err_str = str(e).lower()
            # Hard failures: DNS or Refused
            if "err_name_not_resolved" in err_str or "err_connection_refused" in err_str:
                result.explicitly_offline = True
                result.outcome = "Target confirmed offline (Domain not found or connection refused)."
            else:
                result.explicitly_offline = False
                result.outcome = f"Target unreachable - {_get_friendly_error(str(e).splitlines()[0])}"
            
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
                    
                    # Capture intermediate step for forensics
                    step_screenshot = f"data/screenshots/{url_hash}_step1.png"
                    page.screenshot(path=step_screenshot)
                    result.screenshots.append(step_screenshot)

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
                f"Successfully reached target: '{result.page_title}'. "
                f"Final Destination: {result.final_url}. "
                "Analysis: No password fields or login forms were detected in the page layout. "
                "The site appears to be an informational page, redirector, or landing page rather than a credential harvester."
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
            "logged in", "my account", "workspace", "home", "settings",
            "search", "notifications", "activity"
        ]

        showed_error = any(kw in page_text for kw in error_keywords)
        showed_success = any(kw in page_text for kw in success_keywords)

        # --- Step 6: Classify ---
        # Logic: Re-verify safety by checking the final state of the page.
        # If we are still on a login page after submitting fake creds, they were likely rejected.
        final_password_fields = [f for f in page.query_selector_all('input[type="password"]') if f.is_visible()]
        still_on_login = len(final_password_fields) > 0
        
        # Take a post-submit screenshot to capture the final forensic state
        try:
            final_screenshot_path = f"data/screenshots/{url_hash}_final.png"
            page.screenshot(path=final_screenshot_path)
            result.screenshots.append(final_screenshot_path)
            result.screenshot_path = final_screenshot_path
            result.content_snippet = page.content()[:2000]
        except:
            pass

        is_trusted = _is_trusted_domain(post_submit_url)

        if showed_error or (still_on_login and same_domain_redirect):
            result.accepted_fake_creds = False
            result.behavior_risk = "Low"
            result.outcome = (
                f"Fake credentials were rejected — {'an error was shown' if showed_error else 'the login form persisted'}. "
                f"This is the expected behavior of a secure, legitimate service. "
                f"Final state: '{post_title}'."
            )

        elif same_domain_redirect and not showed_success:
            # Re-verify: Same-domain transitions are typical for safe sites (multi-step)
            result.accepted_fake_creds = False
            result.behavior_risk = "Low" if is_trusted else "Medium"
            
            risk_desc = "Safe (Trusted Domain)" if is_trusted else "Ambiguous (Unknown Domain)"
            result.outcome = (
                f"Redirect occurred within the same domain family ({_root_domain(post_submit_url)}). "
                f"Classification: {risk_desc}. "
                "This behavior is typical of multi-step login flows or internal authentication routing. "
                f"Final state: '{post_title}'."
            )

        elif not url_changed and not showed_success:
            # Stayed on the same page: Check if it's a trusted brand
            result.accepted_fake_creds = False
            result.behavior_risk = "Low" if is_trusted else "Medium"
            
            risk_desc = "Safe (Trusted Domain)" if is_trusted else "Ambiguous (Unknown Domain)"
            result.outcome = (
                f"Remained on the same page ({_root_domain(post_submit_url)}). "
                f"Classification: {risk_desc}. "
                "No immediate redirect or error was detected. "
                f"{'Typical of SPA/JavaScript applications on trusted sites.' if is_trusted else 'Ambiguous outcome — no conclusive evidence of harvesting or rejection.'}"
            )

        elif cross_domain_redirect:
            # Cross-domain redirects after submission are EXTREMELY suspicious
            landing_on_trusted_final = _is_trusted_domain(post_submit_url)
            result.accepted_fake_creds = True
            result.behavior_risk = "High"
            
            if landing_on_trusted_final:
                result.outcome = (
                    f"⚠️  LIKELY CREDENTIAL HARVESTER: Fake credentials were submitted and the page "
                    f"redirected to a trusted third-party domain ({_root_domain(post_submit_url)}). "
                    "This is a classic phishing kit pattern — harvest credentials, "
                    "then redirect the victim to the real site to avoid suspicion."
                )
            else:
                result.outcome = (
                    f"⚠️  CREDENTIAL HARVESTER CONFIRMED: After submitting fake credentials, "
                    f"the page redirected to an external domain: {post_submit_url}. "
                    "Phishing kits harvest credentials silently then redirect to a different site "
                    "to avoid suspicion. This is a definitive threat signature."
                )

        elif showed_success and not is_trusted:
             result.accepted_fake_creds = True
             result.behavior_risk = "High"
             result.outcome = (
                 f"⚠️  CREDENTIAL HARVESTER CONFIRMED: Fake credentials were accepted "
                 f"and a success-like response was shown on an unverified domain. "
                 "Legitimate services never accept obviously fake credentials. "
                 f"Page title: '{post_title}'."
             )

        else:
            result.accepted_fake_creds = False
            result.behavior_risk = "Medium"
            result.outcome = (
                "Login form interaction completed, but the outcome was inconclusive. "
                "No explicit error or successful cross-domain redirect detected. "
                f"Final state: '{post_title}' on {_root_domain(post_submit_url)}. "
                "Forensic Capture: Post-submission state recorded for manual verification."
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


# ── Dedicated multi-thread executor for Playwright ──
# We use a small pool to allow parallel probing of multiple links.
_probe_executor = ThreadPoolExecutor(max_workers=5, thread_name_prefix="pw-probe")


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
        "screenshots": r.screenshots,
        "redirectChain": r.redirect_chain,
        "explicitlyOffline": r.explicitly_offline,
        "formFields": r.form_fields,
        "contentSnippet": r.content_snippet
    }