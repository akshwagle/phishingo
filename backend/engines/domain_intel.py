"""
Domain intelligence engine — WHOIS registration age, SSL certificate analysis,
DNS nameserver records, TLD reputation, and free-DNS provider detection.
"""
from __future__ import annotations

import asyncio
import datetime
import logging
import socket
import ssl
import time
from typing import Any

import whois as whois_lib

logger = logging.getLogger(__name__)

_SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    "ru", "tk", "ml", "ga", "cf", "xyz", "top", "click", "work",
    "pw", "cc", "biz", "gq", "men", "loan", "download", "racing",
    "win", "stream", "gdn", "date", "faith", "review", "trade",
    "accountant", "science", "party", "cricket", "bid", "ninja",
    "space", "website", "site", "online", "tech",
})

_FREE_DNS_SIGNATURES: frozenset[str] = frozenset({
    "freenom", "afraid.org", "he.net", "no-ip.com", "dyndns",
    "changeip.com", "duckdns.org", "freedns", "namecheaphosting",
    "cloudns.net", "dnsdynamic", "zoneedit.com",
})


async def analyze_domain(domain: str) -> dict[str, Any]:
    """
    Gather WHOIS, SSL, NS, and TLD data for a single domain.
    All lookups are wrapped in try/except — never lets one failure crash the engine.
    """
    result: dict[str, Any] = {
        "domain": domain,
        "age_days": None,
        "registrar": None,
        "ssl_issuer": None,
        "ssl_valid": False,
        "ssl_expiry": None,
        "free_dns": False,
        "suspicious_tld": False,
        "ns_records": [],
        "risk_factors": [],
    }

    # Run WHOIS and SSL concurrently
    whois_task = asyncio.create_task(_whois_lookup(domain))
    ssl_task = asyncio.create_task(_ssl_lookup(domain))

    whois_data, ssl_data = await asyncio.gather(
        whois_task, ssl_task, return_exceptions=True
    )

    if not isinstance(whois_data, Exception):
        result.update(whois_data)
    else:
        logger.debug("WHOIS failed for %s: %s", domain, whois_data)

    if not isinstance(ssl_data, Exception):
        result.update(ssl_data)
    else:
        logger.debug("SSL lookup failed for %s: %s", domain, ssl_data)

    # TLD reputation
    tld = domain.rsplit(".", 1)[-1].lower() if "." in domain else ""
    result["suspicious_tld"] = tld in _SUSPICIOUS_TLDS

    # Build risk factor list
    if result["age_days"] is not None:
        if result["age_days"] < 7:
            result["risk_factors"].append(
                f"Domain registered only {result['age_days']} day(s) ago — extremely fresh"
            )
        elif result["age_days"] < 30:
            result["risk_factors"].append(
                f"Domain registered {result['age_days']} days ago — common campaign lifespan"
            )

    if result["suspicious_tld"]:
        result["risk_factors"].append(
            f"High-risk TLD '.{tld}' frequently used in phishing / free hosting"
        )

    if not result["ssl_valid"]:
        result["risk_factors"].append(
            "SSL certificate invalid, expired, or not present"
        )

    if result["free_dns"]:
        result["risk_factors"].append(
            "Uses free/anonymous DNS provider — low barrier to registration"
        )

    return result


async def _whois_lookup(domain: str) -> dict[str, Any]:
    """Run WHOIS in an executor thread to avoid blocking the event loop."""
    try:
        loop = asyncio.get_event_loop()
        return await asyncio.wait_for(
            loop.run_in_executor(None, _sync_whois, domain),
            timeout=12,
        )
    except asyncio.TimeoutError:
        logger.debug("WHOIS timed out for %s", domain)
        return {"age_days": None, "registrar": None, "ns_records": [], "free_dns": False}
    except Exception as exc:
        logger.debug("WHOIS executor error for %s: %s", domain, exc)
        return {"age_days": None, "registrar": None, "ns_records": [], "free_dns": False}


def _sync_whois(domain: str) -> dict[str, Any]:
    """Synchronous WHOIS query (runs in thread pool)."""
    try:
        w = whois_lib.whois(domain)

        # Age calculation
        age_days: int | None = None
        creation = w.creation_date
        if creation:
            if isinstance(creation, list):
                creation = creation[0]
            if isinstance(creation, datetime.datetime):
                delta = datetime.datetime.utcnow() - creation.replace(tzinfo=None)
                age_days = max(0, delta.days)

        # Registrar
        registrar = w.registrar
        if isinstance(registrar, list):
            registrar = registrar[0] if registrar else None
        registrar = str(registrar).strip() if registrar else None

        # Nameservers
        ns_raw = w.name_servers or []
        if isinstance(ns_raw, str):
            ns_raw = [ns_raw]
        ns_records = sorted({ns.lower().rstrip(".") for ns in ns_raw if ns})[:8]

        # Free DNS detection
        free_dns = any(
            sig in ns
            for ns in ns_records
            for sig in _FREE_DNS_SIGNATURES
        )

        return {
            "age_days": age_days,
            "registrar": registrar,
            "ns_records": ns_records,
            "free_dns": free_dns,
        }
    except Exception as exc:
        logger.debug("_sync_whois inner error for %s: %s", domain, exc)
        return {"age_days": None, "registrar": None, "ns_records": [], "free_dns": False}


async def _ssl_lookup(domain: str) -> dict[str, Any]:
    """Fetch SSL certificate details for the domain on port 443."""
    try:
        loop = asyncio.get_event_loop()
        return await asyncio.wait_for(
            loop.run_in_executor(None, _sync_ssl, domain),
            timeout=10,
        )
    except asyncio.TimeoutError:
        return {"ssl_issuer": None, "ssl_valid": False, "ssl_expiry": None}
    except Exception as exc:
        logger.debug("SSL executor error for %s: %s", domain, exc)
        return {"ssl_issuer": None, "ssl_valid": False, "ssl_expiry": None}


def _sync_ssl(domain: str) -> dict[str, Any]:
    """Synchronous SSL certificate check (runs in thread pool)."""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((domain, 443), timeout=8),
            server_hostname=domain,
        ) as sock:
            cert = sock.getpeercert()

        # Parse issuer organisation
        issuer_dict: dict[str, str] = {}
        for rdn in cert.get("issuer", ()):
            for k, v in rdn:
                issuer_dict[k] = v
        issuer_org = (
            issuer_dict.get("organizationName")
            or issuer_dict.get("O")
            or issuer_dict.get("commonName")
            or "Unknown"
        )

        # Validity
        not_after_str = cert.get("notAfter", "")
        valid = False
        expiry: str | None = None
        if not_after_str:
            not_after_ts = ssl.cert_time_to_seconds(not_after_str)
            valid = not_after_ts > time.time()
            expiry = not_after_str

        return {
            "ssl_issuer": issuer_org,
            "ssl_valid": valid,
            "ssl_expiry": expiry,
        }
    except ssl.SSLCertVerificationError:
        return {"ssl_issuer": None, "ssl_valid": False, "ssl_expiry": None}
    except (socket.timeout, ConnectionRefusedError, OSError):
        return {"ssl_issuer": None, "ssl_valid": False, "ssl_expiry": None}
    except Exception as exc:
        logger.debug("_sync_ssl inner error for %s: %s", domain, exc)
        return {"ssl_issuer": None, "ssl_valid": False, "ssl_expiry": None}
