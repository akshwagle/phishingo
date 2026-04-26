"""
Threat intelligence engine — checks URLs against:
  Google Safe Browsing v4, URLhaus (abuse.ch), PhishTank, OpenPhish.
OpenPhish feed is pulled at startup and refreshed every 30 min in a background task.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# ── OpenPhish in-memory cache ─────────────────────────────────────────────────
_openphish_urls: set[str] = set()
_openphish_last_refresh: float = 0.0
_OPENPHISH_REFRESH_INTERVAL = 1800  # 30 minutes

_OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
_URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/url/"
_PHISHTANK_API_URL = "https://checkurl.phishtank.com/checkurl/"
_GSB_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


async def refresh_openphish_loop() -> None:
    """
    Background coroutine: fetch the OpenPhish URL feed on startup
    and re-fetch every 30 minutes thereafter.
    """
    while True:
        await _refresh_openphish()
        await asyncio.sleep(_OPENPHISH_REFRESH_INTERVAL)


async def _refresh_openphish() -> None:
    """Pull the plain-text OpenPhish feed into the in-memory set."""
    global _openphish_urls, _openphish_last_refresh
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(_OPENPHISH_FEED_URL)
            if resp.status_code == 200:
                new_set = {
                    line.strip()
                    for line in resp.text.splitlines()
                    if line.strip().startswith("http")
                }
                _openphish_urls = new_set
                _openphish_last_refresh = time.time()
                logger.info("OpenPhish feed refreshed: %d URLs loaded", len(new_set))
            else:
                logger.warning(
                    "OpenPhish feed returned HTTP %s", resp.status_code
                )
    except Exception as exc:
        logger.warning("OpenPhish refresh failed: %s", exc)


async def check_threat_feeds(urls: list[str]) -> dict[str, Any]:
    """
    Check every URL against all four threat sources concurrently.
    Gracefully degrades — a failed source never blocks the overall result.
    """
    if not urls:
        return {"results": {}}

    tasks = [_check_single_url(url) for url in urls]
    raw_results = await asyncio.gather(*tasks, return_exceptions=True)

    results: dict[str, Any] = {}
    for url, res in zip(urls, raw_results):
        if isinstance(res, Exception):
            results[url] = {"error": str(res), "sources": []}
        else:
            results[url] = res

    return {"results": results}


async def _check_single_url(url: str) -> dict[str, Any]:
    """Check a single URL against all intelligence sources in parallel."""
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(12.0, connect=6.0),
        follow_redirects=False,
        headers={"User-Agent": "PhishFilter-Pro/1.0"},
    ) as client:
        gsb_task = asyncio.create_task(_check_gsb([url], client))
        urlhaus_task = asyncio.create_task(_check_urlhaus(url, client))
        phishtank_task = asyncio.create_task(_check_phishtank(url, client))

        gsb_res, urlhaus_res, phishtank_res = await asyncio.gather(
            gsb_task, urlhaus_task, phishtank_task,
            return_exceptions=True,
        )

    # OpenPhish: O(1) set lookup
    openphish_match = url in _openphish_urls
    if not openphish_match:
        # Also check stripped URL (trailing slash variants)
        openphish_match = url.rstrip("/") in _openphish_urls

    def _safe(r: Any) -> dict[str, Any]:
        return r if isinstance(r, dict) else {"match": False, "error": str(r)}

    gsb = _safe(gsb_res)
    urlhaus = _safe(urlhaus_res)
    phishtank = _safe(phishtank_res)

    sources: list[str] = []
    if gsb.get("match"):
        sources.append("google_safe_browsing")
    if urlhaus.get("match"):
        sources.append("urlhaus")
    if phishtank.get("match"):
        sources.append("phishtank")
    if openphish_match:
        sources.append("openphish")

    return {
        "gsb_match": gsb.get("match", False),
        "urlhaus_match": urlhaus.get("match", False),
        "phishtank_match": phishtank.get("match", False),
        "openphish_match": openphish_match,
        "gsb_threat_type": gsb.get("threat_type"),
        "urlhaus_threat": urlhaus.get("threat"),
        "sources": sources,
        "matched": len(sources) > 0,
    }


async def _check_gsb(urls: list[str], client: httpx.AsyncClient) -> dict[str, Any]:
    """Google Safe Browsing API v4 — batch URL check."""
    api_key = os.getenv("GSB_API_KEY", "").strip()
    if not api_key:
        return {"match": False, "error": "GSB_API_KEY not configured"}

    payload = {
        "client": {"clientId": "phishfilter-pro", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls],
        },
    }

    try:
        resp = await client.post(
            f"{_GSB_API_URL}?key={api_key}",
            json=payload,
        )
        resp.raise_for_status()
        data = resp.json()
        matches = data.get("matches", [])
        if matches:
            return {
                "match": True,
                "threat_type": matches[0].get("threatType"),
                "platform_type": matches[0].get("platformType"),
                "raw_matches": matches,
            }
        return {"match": False}
    except httpx.HTTPStatusError as exc:
        return {"match": False, "error": f"GSB HTTP {exc.response.status_code}"}
    except Exception as exc:
        return {"match": False, "error": str(exc)}


async def _check_urlhaus(url: str, client: httpx.AsyncClient) -> dict[str, Any]:
    """abuse.ch URLhaus public API — no key required."""
    try:
        resp = await client.post(
            _URLHAUS_API_URL,
            data={"url": url},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp.raise_for_status()
        data = resp.json()

        query_status = data.get("query_status", "no_results")

        # "no_results" → not in database; "is_reporter" → submitter; status field matters
        url_status = data.get("url_status")
        if url_status in ("online", "offline") and query_status != "is_reporter":
            return {
                "match": True,
                "status": url_status,
                "threat": data.get("threat"),
                "tags": data.get("tags", []),
                "date_added": data.get("date_added"),
            }
        return {"match": False, "query_status": query_status}
    except Exception as exc:
        return {"match": False, "error": str(exc)}


async def _check_phishtank(url: str, client: httpx.AsyncClient) -> dict[str, Any]:
    """PhishTank community database — no key required for basic lookups."""
    try:
        resp = await client.post(
            _PHISHTANK_API_URL,
            data={"url": url, "format": "json"},
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "PhishFilter-Pro/1.0",
            },
        )
        resp.raise_for_status()
        data = resp.json()
        results = data.get("results", {})
        in_db = bool(results.get("in_database", False))
        verified = bool(results.get("verified", False))
        return {
            "match": in_db and verified,
            "in_database": in_db,
            "verified": verified,
            "phish_id": results.get("phish_id"),
            "phish_detail_url": results.get("phish_detail_url"),
        }
    except Exception as exc:
        return {"match": False, "error": str(exc)}
