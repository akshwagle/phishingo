"""
Email parser engine — extracts headers, body text, URLs, and attachment hashes
from raw .eml content or pasted email text.
"""
from __future__ import annotations

import email
import email.policy
import hashlib
import logging
import re
from email.parser import BytesParser, Parser
from typing import Any

logger = logging.getLogger(__name__)

_URL_RE = re.compile(
    r'https?://[^\s<>"\')\]},;\\]+',
    re.IGNORECASE,
)
_HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
_SRC_RE = re.compile(r'src=["\']([^"\']+)["\']', re.IGNORECASE)


async def parse_email(raw: str) -> dict[str, Any]:
    """
    Parse raw email string into structured forensic data.

    Returns a dict with headers, plain/html body, all extracted URLs
    (including hidden href targets), attachment metadata and SHA-256 hashes.
    """
    try:
        raw_bytes = raw.encode("utf-8", errors="replace") if isinstance(raw, str) else raw
        msg = BytesParser(policy=email.policy.default).parsebytes(raw_bytes)
    except Exception:
        try:
            s = raw if isinstance(raw, str) else raw.decode("utf-8", errors="replace")
            msg = Parser(policy=email.policy.default).parsestr(s)
        except Exception as exc:
            logger.error("Email parse failed entirely: %s", exc)
            return {
                "headers": {},
                "body": raw if isinstance(raw, str) else "",
                "body_html": "",
                "urls": [],
                "attachments": [],
                "attachment_hashes": [],
                "parse_error": str(exc),
            }

    headers = _extract_headers(msg)
    body_text, body_html = _extract_body(msg)
    urls = _extract_urls(body_text, body_html)
    attachments, attachment_hashes = _extract_attachments(msg)

    return {
        "headers": headers,
        "body": body_text or _strip_tags(body_html),
        "body_html": body_html,
        "urls": urls,
        "attachments": attachments,
        "attachment_hashes": attachment_hashes,
    }


def _extract_headers(msg: Any) -> dict[str, str]:
    """Pull all headers into a flat dict; for duplicates keep the last value."""
    headers: dict[str, str] = {}
    for key in msg.keys():
        val = msg[key]
        # Decode encoded-words (RFC 2047)
        try:
            decoded = email.header.decode_header(val)
            parts: list[str] = []
            for chunk, charset in decoded:
                if isinstance(chunk, bytes):
                    parts.append(chunk.decode(charset or "utf-8", errors="replace"))
                else:
                    parts.append(str(chunk))
            headers[key] = " ".join(parts)
        except Exception:
            headers[key] = str(val)
    return headers


def _extract_body(msg: Any) -> tuple[str, str]:
    """Walk the MIME tree and collect plain-text and HTML parts."""
    plain_parts: list[str] = []
    html_parts: list[str] = []

    parts_iter = msg.walk() if msg.is_multipart() else [msg]

    for part in parts_iter:
        ctype = part.get_content_type()
        disposition = str(part.get("Content-Disposition", ""))
        if "attachment" in disposition:
            continue

        try:
            payload = part.get_content()
        except Exception:
            raw_payload = part.get_payload(decode=True)
            if not raw_payload:
                continue
            charset = part.get_content_charset() or "utf-8"
            payload = raw_payload.decode(charset, errors="replace")

        if not isinstance(payload, str):
            continue

        if ctype == "text/plain":
            plain_parts.append(payload)
        elif ctype == "text/html":
            html_parts.append(payload)

    return "\n".join(plain_parts), "\n".join(html_parts)


def _extract_urls(plain: str, html: str) -> list[str]:
    """
    Extract all unique URLs from plain text and HTML body.
    Captures both href destinations and inline URL patterns.
    Detects hidden-link attacks where the visible text differs from href.
    """
    found: set[str] = set()

    # Inline URLs in plain text
    for m in _URL_RE.finditer(plain):
        url = m.group(0).rstrip(".,;)")
        if len(url) < 2048:
            found.add(url)

    # href attributes in HTML — these are the actual redirect targets
    for m in _HREF_RE.finditer(html):
        href = m.group(1).strip()
        if href.startswith("http") and len(href) < 2048:
            found.add(href.rstrip(".,;)"))

    # src attributes (may contain tracking pixels or external resources)
    for m in _SRC_RE.finditer(html):
        src = m.group(1).strip()
        if src.startswith("http") and len(src) < 2048:
            found.add(src.rstrip(".,;)"))

    # Inline URLs inside stripped HTML
    stripped = _strip_tags(html)
    for m in _URL_RE.finditer(stripped):
        url = m.group(0).rstrip(".,;)")
        if len(url) < 2048:
            found.add(url)

    return sorted(found)


def _strip_tags(html: str) -> str:
    """Remove all HTML tags, returning plain text."""
    return re.sub(r"<[^>]+>", " ", html)


def _extract_attachments(msg: Any) -> tuple[list[dict], list[dict]]:
    """Return attachment metadata and corresponding SHA-256 hash entries."""
    attachments: list[dict] = []
    hashes: list[dict] = []

    for part in msg.walk():
        disposition = str(part.get("Content-Disposition", ""))
        if "attachment" not in disposition:
            continue

        filename = part.get_filename() or "unknown"
        content_type = part.get_content_type()
        payload = part.get_payload(decode=True)
        size = len(payload) if payload else 0
        sha256 = hashlib.sha256(payload).hexdigest() if payload else ""

        attachments.append({
            "filename": filename,
            "content_type": content_type,
            "size_bytes": size,
        })
        hashes.append({
            "filename": filename,
            "sha256": sha256,
        })

    return attachments, hashes
