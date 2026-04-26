"""
URL sandbox engine — headless Chromium screenshot, login-form detection,
and brand impersonation indicator analysis via Playwright.
Always returns a dict and never propagates exceptions to the caller.
"""
from __future__ import annotations

import asyncio
import base64
import logging
from typing import Any

logger = logging.getLogger(__name__)

_BRAND_KEYWORDS: list[str] = [
    "paypal", "apple", "google", "microsoft", "amazon", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "chase",
    "wellsfargo", "citibank", "bankofamerica", "dropbox", "icloud",
    "outlook", "office", "office365", "coinbase", "binance", "stripe",
    "blockchain", "ebay", "walmart", "target", "bestbuy", "usps",
    "fedex", "dhl", "ups", "irs", "ssn", "social security",
]

_BLOCKED_RESOURCE_TYPES = {"image", "font", "stylesheet", "media"}


async def screenshot_url(url: str) -> dict[str, Any]:
    """
    Navigate headless Chromium to `url`, capture a screenshot,
    and return forensic page metadata. Falls back on any error.
    """
    try:
        return await asyncio.wait_for(_do_screenshot(url), timeout=15)
    except asyncio.TimeoutError:
        logger.warning("Sandbox timed out for %s", url)
        return {"error": "sandbox timeout (15s exceeded)", "url": url}
    except Exception as exc:
        logger.exception("Sandbox uncaught error for %s", url)
        return {"error": f"sandbox unavailable: {exc}", "url": url}


async def _do_screenshot(url: str) -> dict[str, Any]:
    """Inner implementation, wrapped with timeout by the caller."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {
            "error": "playwright not installed — run: pip install playwright && playwright install chromium",
            "url": url,
        }

    result: dict[str, Any] = {
        "url": url,
        "screenshot_b64": None,
        "page_title": "",
        "redirect_final": url,
        "has_password_field": False,
        "has_login_form": False,
        "brand_logos_detected": [],
        "form_action_domains": [],
    }

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--disable-software-rasterizer",
            ],
        )

        context = await browser.new_context(
            viewport={"width": 1280, "height": 900},
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            ignore_https_errors=True,
        )

        page = await context.new_page()

        # Block heavy resources to speed up analysis
        async def _block_resources(route: Any, request: Any) -> None:
            if request.resource_type in _BLOCKED_RESOURCE_TYPES:
                await route.abort()
            else:
                await route.continue_()

        await page.route("**/*", _block_resources)

        # Navigate with short timeout — we're doing forensics, not QA
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=8000)
        except Exception as nav_exc:
            logger.debug("Navigation partial/failed for %s: %s", url, nav_exc)

        # Capture final URL after JS redirects
        result["redirect_final"] = page.url

        # Page title
        try:
            result["page_title"] = await asyncio.wait_for(page.title(), timeout=3)
        except Exception:
            pass

        # Screenshot
        try:
            png = await asyncio.wait_for(
                page.screenshot(full_page=False, timeout=5000),
                timeout=6,
            )
            result["screenshot_b64"] = base64.b64encode(png).decode()
        except Exception as ss_exc:
            logger.debug("Screenshot failed for %s: %s", url, ss_exc)

        # Detect password fields
        try:
            pw_inputs = await page.query_selector_all('input[type="password"]')
            result["has_password_field"] = len(pw_inputs) > 0
        except Exception:
            pass

        # Detect login forms (password field + user/email field)
        try:
            user_inputs = await page.query_selector_all(
                'input[type="email"], '
                'input[name*="user" i], input[name*="email" i], '
                'input[id*="user" i], input[id*="email" i], '
                'input[placeholder*="email" i], input[placeholder*="username" i]'
            )
            result["has_login_form"] = (
                result["has_password_field"] and len(user_inputs) > 0
            )
        except Exception:
            pass

        # Collect form action domains
        try:
            forms = await page.query_selector_all("form[action]")
            for form in forms:
                action = await form.get_attribute("action")
                if action and action.startswith("http"):
                    from urllib.parse import urlparse as _up
                    result["form_action_domains"].append(_up(action).netloc)
        except Exception:
            pass

        # Brand impersonation via page text analysis
        try:
            body_text = (await page.inner_text("body")).lower()
            title_lower = result["page_title"].lower()
            combined = body_text[:5000] + " " + title_lower
            for brand in _BRAND_KEYWORDS:
                if brand in combined:
                    result["brand_logos_detected"].append(brand)
        except Exception:
            pass

        await browser.close()

    return result
