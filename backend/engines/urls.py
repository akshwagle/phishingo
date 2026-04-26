"""
URL redirect-chain analysis engine — follows each URL up to 10 hops,
detects shorteners, flags suspicious redirect patterns and anomalous URL structure.
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Any
from urllib.parse import urlparse, urljoin

import httpx

logger = logging.getLogger(__name__)

_SHORTENERS: frozenset[str] = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "short.io", "rebrand.ly", "tiny.cc", "lnkd.in",
    "cutt.ly", "bl.ink", "soo.gd", "s.id", "clicky.me", "budurl.com",
    "snipurl.com", "shorturl.at", "v.gd", "qr.io", "tr.im", "cli.gs",
    "su.pr", "twurl.nl", "ff.im", "j.mp", "ur1.ca", "1url.com",
    "prettylinkpro.com", "scrnch.me", "filoops.info", "vzturl.com",
    "qr.net", "1.usa.gov", "shorten.ws", "x.co", "yourls.org",
})

_MAX_HOPS = 10
_TIMEOUT = httpx.Timeout(connect=5.0, read=5.0, write=5.0, pool=5.0)

_SUSPICIOUS_URL_PATTERNS: list[tuple[str, str]] = [
    (r"@", "@ in URL obscures true hostname"),
    (r"//\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "IP-literal host (no domain)"),
    (r"(?:%[0-9a-fA-F]{2}){4,}", "Heavy percent-encoding — possible evasion"),
    (r"\.{2,}", "Multiple consecutive dots in URL"),
    (r"[^\x20-\x7E]", "Non-ASCII characters in URL"),
    (r"\d{5,}", "Unusually long numeric sequence"),
]


async def analyze_urls(urls: list[str]) -> dict[str, Any]:
    """
    Analyze each URL's redirect chain concurrently.
    Caps total concurrency at 10 to avoid hammering targets.
    """
    if not urls:
        return {"urls": []}

    semaphore = asyncio.Semaphore(10)

    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=_TIMEOUT,
        verify=False,  # Intentional — we must inspect potentially invalid certs
        headers={
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            )
        },
        max_redirects=0,
    ) as client:

        async def bounded_analyze(url: str) -> dict[str, Any]:
            async with semaphore:
                return await _analyze_single_url(client, url)

        tasks = [bounded_analyze(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    url_results: list[dict[str, Any]] = []
    for url, res in zip(urls, results):
        if isinstance(res, Exception):
            url_results.append({
                "original": url,
                "error": str(res),
                "redirect_chain": [],
                "final_destination": url,
                "num_hops": 0,
                "suspicious_redirects": False,
                "https": url.startswith("https"),
                "is_shortener": _is_shortener(urlparse(url).netloc),
            })
        else:
            url_results.append(res)

    return {"urls": url_results}


async def _analyze_single_url(client: httpx.AsyncClient, url: str) -> dict[str, Any]:
    """Follow one URL through its full redirect chain, recording every hop."""
    parsed = urlparse(url)
    host = parsed.netloc.lower().split(":")[0]

    result: dict[str, Any] = {
        "original": url,
        "redirect_chain": [],
        "final_destination": url,
        "num_hops": 0,
        "suspicious_redirects": False,
        "https": parsed.scheme == "https",
        "is_shortener": _is_shortener(host),
        "suspicious_patterns": _check_suspicious_patterns(url),
        "js_redirect_possible": False,
    }

    current_url = url
    visited: set[str] = set()

    for _ in range(_MAX_HOPS):
        if current_url in visited:
            result["suspicious_redirects"] = True
            result["redirect_chain"].append({
                "url": current_url,
                "status": "loop_detected",
            })
            break
        visited.add(current_url)

        hop: dict[str, Any] = {
            "url": current_url,
            "status": None,
            "is_shortener": _is_shortener(urlparse(current_url).netloc.lower()),
        }

        try:
            resp = await client.head(current_url, follow_redirects=False)
            hop["status"] = resp.status_code

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location", "").strip()
                if not location:
                    result["redirect_chain"].append(hop)
                    break
                # Resolve relative locations
                if not location.startswith(("http://", "https://")):
                    location = urljoin(current_url, location)
                hop["redirect_to"] = location
                result["redirect_chain"].append(hop)

                if _is_shortener(urlparse(location).netloc.lower()):
                    result["suspicious_redirects"] = True

                current_url = location
                continue

            elif resp.status_code == 200:
                # 200 with no redirect — some shorteners use JS meta-refresh
                result["js_redirect_possible"] = True
                result["redirect_chain"].append(hop)
                result["final_destination"] = current_url
                break

            else:
                result["redirect_chain"].append(hop)
                result["final_destination"] = current_url
                break

        except httpx.TooManyRedirects:
            hop["status"] = "too_many_redirects"
            result["redirect_chain"].append(hop)
            result["suspicious_redirects"] = True
            break
        except httpx.TimeoutException:
            hop["status"] = "timeout"
            result["redirect_chain"].append(hop)
            break
        except Exception as exc:
            hop["status"] = f"error: {exc}"
            result["redirect_chain"].append(hop)
            break
    else:
        # Exhausted hop limit
        result["suspicious_redirects"] = True

    result["final_destination"] = current_url
    result["num_hops"] = len(result["redirect_chain"])

    # Final destination is a shortener that never resolved
    final_parsed = urlparse(current_url)
    if _is_shortener(final_parsed.netloc.lower()):
        result["suspicious_redirects"] = True

    # Flag if final destination differs from original
    if current_url != url:
        result["https"] = current_url.startswith("https")

    return result


def _is_shortener(host: str) -> bool:
    host = host.lower().lstrip("www.")
    return host in _SHORTENERS or any(
        host.endswith(f".{s}") for s in _SHORTENERS
    )


def _check_suspicious_patterns(url: str) -> list[str]:
    """Return list of human-readable suspicious pattern descriptions found in the URL."""
    found: list[str] = []
    for pattern, description in _SUSPICIOUS_URL_PATTERNS:
        if re.search(pattern, url):
            found.append(description)
    return found
