"""
Typosquat detection engine — identifies brand impersonation via edit distance,
appended/prepended words, TLD swaps, hyphen insertion, and digit substitution.
"""
from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlparse

from Levenshtein import distance as levenshtein_distance

logger = logging.getLogger(__name__)

_COMMON_SQUATTING_SUFFIXES = [
    "secure", "login", "signin", "verify", "update", "account",
    "support", "help", "service", "online", "web", "my", "portal",
    "access", "auth", "confirm", "validate", "official", "safe",
    "protect", "protection", "alert", "notice",
]

_COMMON_SQUATTING_PREFIXES = [
    "my", "www", "secure", "login", "signin", "mail", "webmail",
    "new", "real", "official", "the", "get",
]


async def detect_typosquats(
    urls: list[str],
    brands: list[str],
) -> dict[str, Any]:
    """
    Check each URL's domain against all known brand domains using six techniques.
    """
    if not urls:
        return {"typosquats": []}

    brand_roots = _build_brand_roots(brands)
    typosquats: list[dict[str, Any]] = []
    seen: set[str] = set()  # Deduplicate (url, brand) pairs

    for url in urls:
        try:
            parsed = urlparse(url)
            netloc = parsed.netloc.lower()
            domain = netloc.split(":")[0].lstrip("www.")
            if not domain:
                continue

            findings = _check_domain(domain, brand_roots)
            for f in findings:
                key = f"{url}:{f['closest_brand']}:{f['technique']}"
                if key not in seen:
                    seen.add(key)
                    f["url"] = url
                    typosquats.append(f)
        except Exception as exc:
            logger.debug("Typosquat check error for %s: %s", url, exc)

    return {"typosquats": typosquats}


def _build_brand_roots(brands: list[str]) -> list[tuple[str, str]]:
    """
    Build (root_label, full_domain) pairs, stripping protocol and path.
    'paypal.com' → ('paypal', 'paypal.com')
    """
    result: list[tuple[str, str]] = []
    seen: set[str] = set()
    for b in brands:
        b = b.strip().lower()
        b = re.sub(r"^https?://", "", b).split("/")[0]
        parts = b.split(".")
        root = parts[0] if parts else b
        if root and root not in seen:
            seen.add(root)
            result.append((root, b))
    return result


def _check_domain(
    domain: str,
    brand_roots: list[tuple[str, str]],
) -> list[dict[str, Any]]:
    """Run all typosquat heuristics against all brand roots."""
    results: list[dict[str, Any]] = []
    parts = domain.split(".")
    domain_root = parts[0]

    # Normalize i/l/I/1 confusables once for use in homograph-aware suffix checks
    _IL_TABLE = str.maketrans("iIl1O0", "lllloooo"[:6])

    for brand_root, brand_full in brand_roots:
        # Skip trivial exact matches
        if domain_root == brand_root:
            continue

        # ── 1. Levenshtein edit distance ≤ 2 ──────────────────────────────
        dist = levenshtein_distance(domain_root, brand_root)
        if 0 < dist <= 2 and len(brand_root) > 3:
            results.append({
                "closest_brand": brand_full,
                "edit_distance": dist,
                "technique": "levenshtein_edit",
                "evidence": (
                    f"'{domain_root}' is {dist} edit(s) from '{brand_root}' "
                    f"(double-hit, transposition, or substitution)"
                ),
            })
            continue

        # ── 2. Brand with appended keyword ────────────────────────────────
        # e.g. paypal-secure.com, paypal-login.net
        # Also check i/l-normalized root so paypaI-secure → paypal-secure matches paypal
        norm_root = domain_root.translate(_IL_TABLE)
        suffix_matched = False
        for check_root in dict.fromkeys([domain_root, norm_root]):
            for suffix in _COMMON_SQUATTING_SUFFIXES:
                if check_root in (
                    f"{brand_root}{suffix}",
                    f"{brand_root}-{suffix}",
                    f"{brand_root}.{suffix}",
                ):
                    results.append({
                        "closest_brand": brand_full,
                        "edit_distance": 0,
                        "technique": "brand_with_suffix",
                        "evidence": (
                            f"'{domain}' appends '{suffix}' to brand '{brand_root}'"
                        ),
                    })
                    suffix_matched = True
                    break
            if suffix_matched:
                break

        if not suffix_matched:
            # ── 3. Brand with prepended keyword ───────────────────────────
            for check_root in dict.fromkeys([domain_root, norm_root]):
                for prefix in _COMMON_SQUATTING_PREFIXES:
                    if check_root in (
                        f"{prefix}{brand_root}",
                        f"{prefix}-{brand_root}",
                    ):
                        results.append({
                            "closest_brand": brand_full,
                            "edit_distance": 0,
                            "technique": "brand_with_prefix",
                            "evidence": (
                                f"'{domain}' prepends '{prefix}' to brand '{brand_root}'"
                            ),
                        })
                        break

        # ── 4. Digit substitution — g00gle.com, pay-pal1.com ──────────────
        digit_stripped = re.sub(r"[0-9]", "", domain_root)
        if (
            any(c.isdigit() for c in domain_root)
            and levenshtein_distance(digit_stripped, brand_root) <= 1
        ):
            results.append({
                "closest_brand": brand_full,
                "edit_distance": levenshtein_distance(domain_root, brand_root),
                "technique": "digit_substitution",
                "evidence": (
                    f"'{domain_root}' substitutes digits for letters in '{brand_root}'"
                ),
            })
            continue

        # ── 5. Hyphen insertion — pay-pal.com, micro-soft.com ─────────────
        dehyphenated = domain_root.replace("-", "")
        if dehyphenated == brand_root and "-" in domain_root:
            results.append({
                "closest_brand": brand_full,
                "edit_distance": 1,
                "technique": "hyphen_insertion",
                "evidence": f"'{domain}' inserts hyphens into brand '{brand_root}'",
            })
            continue

        # ── 6. TLD swap — paypal.co, paypal.net, paypal.org ──────────────
        if domain_root == brand_root and len(parts) >= 2:
            brand_tld = brand_full.rsplit(".", 1)[-1]
            domain_tld = domain.rsplit(".", 1)[-1]
            if domain_tld != brand_tld:
                results.append({
                    "closest_brand": brand_full,
                    "edit_distance": 0,
                    "technique": "tld_swap",
                    "evidence": (
                        f"'{domain}' uses TLD '.{domain_tld}' "
                        f"instead of legitimate '.{brand_tld}'"
                    ),
                })

    return results
