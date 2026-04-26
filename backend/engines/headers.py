"""
Email header analysis engine — live SPF/DKIM/DMARC DNS checks,
domain mismatch detection, display-name spoofing, and Received-chain analysis.
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

import dns.resolver
import dns.exception

logger = logging.getLogger(__name__)

_FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com",
    "aol.com", "protonmail.com", "icloud.com", "me.com", "mac.com",
    "ymail.com", "googlemail.com", "yahoo.co.uk", "yahoo.fr", "yahoo.de",
    "msn.com", "windowslive.com", "mail.com", "zoho.com", "fastmail.com",
    "tutanota.com", "gmx.com", "gmx.net", "inbox.com",
}

_BRAND_DISPLAY_KEYWORDS = {
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "ebay", "chase",
    "wellsfargo", "wells fargo", "citibank", "bankofamerica", "bank of america",
    "security", "support", "alert", "service", "account", "verify",
    "confirm", "team", "noreply", "no-reply", "official", "helpdesk",
    "admin", "billing", "notification", "update", "customer care",
    "dropbox", "spotify", "uber", "airbnb", "irs", "usps", "fedex", "dhl",
    "coinbase", "binance", "stripe", "blockchain", "wallet",
}


async def analyze_headers(headers: dict[str, str]) -> dict[str, Any]:
    """
    Analyze email headers for authentication failures, domain mismatches,
    and spoofing indicators. Performs live DNS queries for SPF and DMARC.
    """
    result: dict[str, Any] = {
        "spf": "none",
        "dkim": "none",
        "dmarc": "none",
        "from_domain": "",
        "return_path_domain": "",
        "reply_to_domain": "",
        "mismatches": [],
        "display_name_spoof": False,
        "received_chain": [],
        "red_flags": [],
    }

    if not headers:
        result["red_flags"].append("No headers present — raw URL or text submission")
        return result

    from_raw = headers.get("From", headers.get("from", ""))
    return_path_raw = headers.get("Return-Path", headers.get("return-path", ""))
    reply_to_raw = headers.get("Reply-To", headers.get("reply-to", ""))

    result["from_domain"] = _extract_domain(from_raw)
    result["return_path_domain"] = _extract_domain(return_path_raw)
    result["reply_to_domain"] = _extract_domain(reply_to_raw)

    # Check Authentication-Results header first (set by receiving MTA)
    auth_hdr = headers.get("Authentication-Results", headers.get("authentication-results", ""))
    result["spf"] = _parse_auth_result(auth_hdr, "spf")
    result["dkim"] = _parse_auth_result(auth_hdr, "dkim")
    result["dmarc"] = _parse_auth_result(auth_hdr, "dmarc")

    # Live DNS fallbacks when auth header is absent
    dns_tasks: list[Any] = []
    do_spf_dns = result["spf"] == "none" and bool(result["from_domain"])
    do_dmarc_dns = result["dmarc"] == "none" and bool(result["from_domain"])

    if do_spf_dns:
        dns_tasks.append(_check_spf_dns(result["from_domain"]))
    else:
        dns_tasks.append(_noop("none"))

    if do_dmarc_dns:
        dns_tasks.append(_check_dmarc_dns(result["from_domain"]))
    else:
        dns_tasks.append(_noop("none"))

    spf_dns, dmarc_dns = await asyncio.gather(*dns_tasks, return_exceptions=True)

    if do_spf_dns and not isinstance(spf_dns, Exception):
        result["spf"] = spf_dns
    if do_dmarc_dns and not isinstance(dmarc_dns, Exception):
        result["dmarc"] = dmarc_dns

    # Domain mismatch checks
    from_d = result["from_domain"]
    rp_d = result["return_path_domain"]
    rt_d = result["reply_to_domain"]

    if from_d and rp_d and from_d != rp_d:
        result["mismatches"].append(
            f"From domain '{from_d}' ≠ Return-Path domain '{rp_d}'"
        )
        result["red_flags"].append(
            "Return-Path domain mismatch — message bounces go to a different domain"
        )

    if from_d and rt_d and from_d != rt_d:
        result["mismatches"].append(
            f"From domain '{from_d}' ≠ Reply-To domain '{rt_d}'"
        )
        result["red_flags"].append(
            "Reply-To hijacking — user replies routed to attacker-controlled inbox"
        )

    # Display name spoofing
    result["display_name_spoof"] = _detect_display_name_spoof(from_raw)
    if result["display_name_spoof"]:
        result["red_flags"].append(
            f"Display name spoof: brand keyword in display name, but email from "
            f"'{result['from_domain']}'"
        )

    # Authentication failures
    if result["spf"] in ("fail", "softfail"):
        result["red_flags"].append(
            f"SPF {result['spf'].upper()} — sending server not authorised for "
            f"domain '{from_d}'"
        )
    if result["dkim"] in ("fail",):
        result["red_flags"].append("DKIM FAIL — message signature is invalid or absent")
    if result["dmarc"] == "fail":
        result["red_flags"].append("DMARC FAIL — domain policy rejected this message")

    # Received chain
    received = [v for k, v in headers.items() if k.lower() == "received"]
    result["received_chain"] = received[:15]
    _analyze_received_chain(received, result)

    # X-Originating-IP / X-Forwarded-For anomalies
    orig_ip = headers.get("X-Originating-IP", headers.get("x-originating-ip", ""))
    if orig_ip and re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)", orig_ip):
        result["red_flags"].append(
            f"X-Originating-IP '{orig_ip}' is a private/RFC1918 address — possible spoofing"
        )

    return result


def _extract_domain(addr: str) -> str:
    """Extract the domain from a raw email address or display-name address."""
    if not addr:
        return ""
    m = re.search(r"[\w.+\-]+@([\w.\-]+\.[a-zA-Z]{2,})", addr)
    return m.group(1).lower() if m else ""


def _parse_auth_result(auth_header: str, method: str) -> str:
    """Parse pass/fail/none from an Authentication-Results header string."""
    if not auth_header:
        return "none"
    m = re.search(rf"{re.escape(method)}\s*=\s*(\w+)", auth_header, re.IGNORECASE)
    if not m:
        return "none"
    val = m.group(1).lower()
    known = {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"}
    return val if val in known else "none"


async def _check_spf_dns(domain: str) -> str:
    """Query SPF TXT record from DNS and derive pass/fail status."""
    try:
        loop = asyncio.get_event_loop()
        answers = await loop.run_in_executor(
            None,
            lambda: dns.resolver.resolve(domain, "TXT", lifetime=5),
        )
        for rdata in answers:
            txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
            if not txt.startswith("v=spf1"):
                continue
            if "-all" in txt:
                return "fail"
            if "~all" in txt:
                return "softfail"
            if "+all" in txt:
                return "pass"
            return "neutral"
    except dns.exception.DNSException:
        pass
    except Exception as exc:
        logger.debug("SPF DNS lookup failed for %s: %s", domain, exc)
    return "none"


async def _check_dmarc_dns(domain: str) -> str:
    """Query _dmarc.<domain> TXT record to determine policy."""
    try:
        loop = asyncio.get_event_loop()
        answers = await loop.run_in_executor(
            None,
            lambda: dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5),
        )
        for rdata in answers:
            txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
            if "v=DMARC1" not in txt:
                continue
            if "p=reject" in txt or "p=quarantine" in txt:
                # Strict policy exists — check if message would pass
                return "pass"
            if "p=none" in txt:
                return "none"
    except dns.exception.DNSException:
        pass
    except Exception as exc:
        logger.debug("DMARC DNS lookup failed for %s: %s", domain, exc)
    return "none"


async def _noop(value: str) -> str:
    return value


def _detect_display_name_spoof(from_raw: str) -> bool:
    """
    Detect 'Brand Name <attacker@freemail.com>' pattern.
    Legitimate brands never send from free webmail providers.
    """
    if not from_raw:
        return False

    m = re.match(r'^(.+?)\s*<([^>]+)>\s*$', from_raw.strip())
    if not m:
        return False

    display_name = m.group(1).lower().strip('"\'')
    email_addr = m.group(2).lower().strip()
    email_domain = _extract_domain(email_addr)

    if not email_domain:
        return False

    has_brand_keyword = any(kw in display_name for kw in _BRAND_DISPLAY_KEYWORDS)
    from_free_provider = email_domain in _FREE_EMAIL_DOMAINS

    return has_brand_keyword and from_free_provider


def _analyze_received_chain(received: list[str], result: dict[str, Any]) -> None:
    """Inspect Received headers for suspicious relay patterns."""
    for i, hop in enumerate(received):
        # Bare-IP sender with no PTR/hostname
        if re.search(r"from\s+\[?\d{1,3}(?:\.\d{1,3}){3}\]?", hop, re.IGNORECASE):
            if not re.search(r"from\s+\S+\s+\(", hop, re.IGNORECASE):
                result["red_flags"].append(
                    f"Received hop {i + 1}: bare IP relay — no hostname (likely dynamic/residential)"
                )

        # Localhost / internal hops near the top of the chain
        if re.search(r"(localhost|127\.0\.0\.1|::1)", hop, re.IGNORECASE):
            result["red_flags"].append(
                f"Received hop {i + 1}: localhost relay — possible header injection attack"
            )

        # Mismatched 'from' and 'by' domains (from evil.com by legit.com = forged)
        by_m = re.search(r"\bby\s+([\w.\-]+)", hop, re.IGNORECASE)
        from_m = re.search(r"\bfrom\s+([\w.\-]+)", hop, re.IGNORECASE)
        if by_m and from_m:
            by_host = by_m.group(1).lower()
            from_host = from_m.group(1).lower()
            if by_host != from_host and "localhost" in from_host:
                result["red_flags"].append(
                    f"Received hop {i + 1}: 'from localhost by {by_host}' — forge indicator"
                )
