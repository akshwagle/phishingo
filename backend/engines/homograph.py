"""
Homograph / IDN attack detector.
Identifies Unicode lookalike characters used to impersonate legitimate brand domains.
Covers: Cyrillic/Greek confusables, zero-width chars, punycode/IDN, capital-I/lowercase-l.
"""
from __future__ import annotations

import logging
import re
import unicodedata
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ── Zero-width / invisible characters ─────────────────────────────────────────
_ZERO_WIDTH: frozenset[str] = frozenset({
    "​",  # ZERO WIDTH SPACE
    "‌",  # ZERO WIDTH NON-JOINER
    "‍",  # ZERO WIDTH JOINER
    "﻿",  # ZERO WIDTH NO-BREAK SPACE (BOM)
    "⁠",  # WORD JOINER
    "­",  # SOFT HYPHEN
})

# ── Confusable character → canonical ASCII mapping ────────────────────────────
# Only single-char-to-single-char mappings to keep it deterministic
_CONFUSABLE: dict[str, str] = {
    # Cyrillic lookalikes
    "а": "a",  # Cyrillic а
    "е": "e",  # Cyrillic е
    "о": "o",  # Cyrillic о
    "р": "r",  # Cyrillic р
    "с": "c",  # Cyrillic с
    "х": "x",  # Cyrillic х
    "у": "y",  # Cyrillic у
    "і": "i",  # Cyrillic і
    "ѕ": "s",  # Cyrillic ѕ
    "ј": "j",  # Cyrillic ј
    "ԁ": "d",  # Cyrillic ԁ
    "ԛ": "q",  # Cyrillic ԛ
    "һ": "h",  # Cyrillic ħ
    "ԑ": "n",  # Cyrillic ԑ
    # Greek lookalikes
    "α": "a",  # Greek α
    "β": "b",  # Greek β (loose)
    "ε": "e",  # Greek ε
    "ι": "i",  # Greek ι
    "κ": "k",  # Greek κ
    "ο": "o",  # Greek ο
    "ρ": "r",  # Greek ρ
    "τ": "t",  # Greek τ
    "υ": "y",  # Greek υ
    "χ": "x",  # Greek χ
    "ν": "v",  # Greek ν
    # Latin lookalikes
    "Ι": "I",  # Greek IOTA used as I
    "Ӏ": "I",  # Cyrillic Palochka (looks like I)
    "ᴀ": "a",  # LATIN LETTER SMALL CAPITAL A
    "ʁ": "r",  # LATIN LETTER SMALL CAPITAL INVERTED R
    # Digit substitutions
    "0": "o",
    "1": "l",
    "3": "e",
    "5": "s",
    "6": "b",
    "8": "b",
    "@": "a",
}

# ── Regex to detect punycode labels ───────────────────────────────────────────
_PUNYCODE_RE = re.compile(r"xn--", re.IGNORECASE)


async def detect_homographs(
    urls: list[str],
    brands: list[str],
) -> dict[str, Any]:
    """
    Check each URL's hostname for homograph attacks against the brand list.
    Returns per-URL findings with attack type and evidence.
    """
    if not urls:
        return {"homographs": []}

    brand_roots = _build_brand_roots(brands)
    homographs: list[dict[str, Any]] = []

    for url in urls:
        try:
            parsed = urlparse(url)
            netloc = parsed.netloc.lower()
            domain = netloc.split(":")[0].lstrip("www.")
            if not domain:
                continue

            findings = _check_domain(domain, brand_roots)
            for f in findings:
                f["url"] = url
                homographs.append(f)
        except Exception as exc:
            logger.debug("Homograph check error for %s: %s", url, exc)

    return {"homographs": homographs}


def _build_brand_roots(brands: list[str]) -> list[tuple[str, str]]:
    """
    Build (root_label, full_domain) pairs.
    'paypal.com' → ('paypal', 'paypal.com')
    """
    roots: list[tuple[str, str]] = []
    seen: set[str] = set()
    for b in brands:
        b = b.strip().lower()
        b = re.sub(r"^https?://", "", b).split("/")[0]
        label = b.split(".")[0]
        if label and label not in seen:
            seen.add(label)
            roots.append((label, b))
    return roots


def _check_domain(
    domain: str,
    brand_roots: list[tuple[str, str]],
) -> list[dict[str, Any]]:
    """Apply every homograph detection strategy to a single domain."""
    results: list[dict[str, Any]] = []

    # 1. Zero-width character injection
    zw_found = [f"U+{ord(c):04X}" for c in domain if c in _ZERO_WIDTH]
    if zw_found:
        results.append({
            "brand_imitated": _guess_brand_after_cleanup(domain, brand_roots),
            "attack_type": "zero_width",
            "evidence": f"Zero-width chars in domain: {', '.join(zw_found)}",
        })

    # 2. Punycode / IDN label
    labels = domain.split(".")
    for label in labels:
        if _PUNYCODE_RE.match(label):
            try:
                decoded = domain.encode("ascii").decode("idna")
            except Exception:
                decoded = domain
            brand = _find_brand_match(_normalize(decoded.split(".")[0]), brand_roots)
            results.append({
                "brand_imitated": brand or decoded,
                "attack_type": "punycode_idn",
                "evidence": f"Punycode domain '{domain}' decodes to '{decoded}'",
            })
            return results  # Further checks on punycode aren't useful

    # 3. Confusable/mixed-script characters
    normalized = _normalize(domain)
    if normalized != domain:
        # Only flag if the normalized version matches a known brand
        norm_root = normalized.split(".")[0]
        brand = _find_brand_match(norm_root, brand_roots)
        if brand:
            scripts = _detect_scripts(domain)
            if "Cyrillic" in scripts:
                attack = "cyrillic_swap"
            elif "Greek" in scripts:
                attack = "greek_swap"
            elif len(scripts) > 1:
                attack = "mixed_script"
            else:
                attack = "confusable_chars"
            results.append({
                "brand_imitated": brand,
                "attack_type": attack,
                "evidence": (
                    f"'{domain}' contains confusable chars; normalizes to "
                    f"'{normalized}' which matches brand '{brand}'"
                ),
            })

    # 4. Capital-I / lowercase-l / digit visual confusion
    # Also catches lowercase i/l (visually identical in sans-serif: paypaI → paypai → paypal)
    il_normalized = domain.translate(str.maketrans("iIl1O0", "lllloooo"[:6]))
    if il_normalized != domain:
        norm_root = il_normalized.split(".")[0]
        brand = _find_brand_match(norm_root, brand_roots) or _find_brand_prefix_match(norm_root, brand_roots)
        if brand:
            results.append({
                "brand_imitated": brand,
                "attack_type": "capital_i_lowercase_l",
                "evidence": (
                    f"'{domain}' exploits I/l/i/1 or O/0 visual ambiguity; "
                    f"normalizes to match brand '{brand}'"
                ),
            })

    return results


def _normalize(text: str) -> str:
    """Replace confusable Unicode chars with their ASCII canonical equivalents."""
    return "".join(_CONFUSABLE.get(ch, ch) for ch in text)


def _detect_scripts(text: str) -> set[str]:
    """Identify Unicode scripts present among alphabetic characters."""
    scripts: set[str] = set()
    for ch in text:
        if not ch.isalpha():
            continue
        try:
            name = unicodedata.name(ch, "")
            if "CYRILLIC" in name:
                scripts.add("Cyrillic")
            elif "GREEK" in name:
                scripts.add("Greek")
            elif "LATIN" in name:
                scripts.add("Latin")
        except Exception:
            pass
    return scripts


def _find_brand_match(
    label: str,
    brand_roots: list[tuple[str, str]],
) -> str:
    """Return the brand domain if label is an exact match after normalization."""
    label_lower = label.lower()
    for root, full in brand_roots:
        if label_lower == root.lower():
            return full
    return ""


def _find_brand_prefix_match(
    label: str,
    brand_roots: list[tuple[str, str]],
) -> str:
    """Return brand if label starts with brand_root followed by a separator (paypal-secure → paypal)."""
    label_lower = label.lower()
    for root, full in brand_roots:
        root_lower = root.lower()
        if len(root_lower) < 4:
            continue  # Skip very short roots to avoid false positives
        if label_lower.startswith(root_lower + "-") or label_lower.startswith(root_lower + "."):
            return full
    return ""


def _guess_brand_after_cleanup(
    domain: str,
    brand_roots: list[tuple[str, str]],
) -> str:
    """Best-effort brand guess after stripping zero-width chars and normalizing."""
    cleaned = "".join(c for c in domain if c not in _ZERO_WIDTH)
    normalized = _normalize(cleaned)
    root = normalized.split(".")[0]
    return _find_brand_match(root, brand_roots) or domain
