"""
Score aggregator — combines signals from all engines into a final
risk score, verdict, confidence rating, and human-readable breakdown.
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

_VERDICT_THRESHOLDS = {
    "SAFE": (0, 30),
    "SUSPICIOUS": (30, 65),
    "DANGEROUS": (65, 101),
}


def aggregate_score(engine_results: dict[str, Any]) -> dict[str, Any]:
    """
    Combine all engine outputs into a single phishing risk assessment.

    Score weights (max total before LLM contribution: 145 points, capped at 100):
      - SPF/DKIM/DMARC failures: up to 20
      - From/Return-Path domain mismatch: 15
      - Display name spoof: 10
      - Homograph attack: 25
      - Typosquat: 20
      - Domain age <7d: 20, <30d: 10
      - Suspicious TLD: 5 per domain (capped at 5 total)
      - Threat feed hit: 30
      - LLM risk_score × 0.30: up to 30
      - Sandbox login form on suspicious page: 15
    """
    raw_score = 0
    breakdown: list[dict[str, Any]] = []
    engines_ok = 0
    engines_total = len(engine_results)
    llm_confidence = 0

    def add(signal: str, weight: int, reasoning: str) -> None:
        nonlocal raw_score
        raw_score += weight
        breakdown.append({
            "signal": signal,
            "weight": weight,
            "contribution": weight,
            "reasoning": reasoning,
        })

    # ── 1. Email header authentication ────────────────────────────────────
    hdrs = engine_results.get("headers", {})
    if isinstance(hdrs, dict) and "error" not in hdrs and hdrs:
        engines_ok += 1
        auth_weight = 0
        auth_details: list[str] = []

        if hdrs.get("spf") in ("fail", "softfail"):
            auth_weight += 7
            auth_details.append(f"SPF={hdrs['spf']}")
        if hdrs.get("dkim") in ("fail", "none"):
            auth_weight += 7
            auth_details.append(f"DKIM={hdrs['dkim']}")
        if hdrs.get("dmarc") in ("fail", "none"):
            auth_weight += 6
            auth_details.append(f"DMARC={hdrs['dmarc']}")

        if auth_weight > 0:
            add(
                "SPF/DKIM/DMARC failures",
                min(auth_weight, 20),
                "Authentication failures: " + ", ".join(auth_details),
            )

        if hdrs.get("mismatches"):
            add(
                "From/Return-Path domain mismatch",
                15,
                "; ".join(hdrs["mismatches"]),
            )

        if hdrs.get("display_name_spoof"):
            add(
                "Display name spoofing",
                10,
                (
                    f"Brand keyword in display name, but email originates from "
                    f"'{hdrs.get('from_domain', 'unknown')}'"
                ),
            )

    # ── 2. Homograph attacks ───────────────────────────────────────────────
    homograph = engine_results.get("homograph", {})
    if isinstance(homograph, dict) and "error" not in homograph:
        engines_ok += 1
        findings = homograph.get("homographs", [])
        if findings:
            evidence = "; ".join(
                f"{h.get('attack_type', '?')} targeting '{h.get('brand_imitated', '?')}'"
                for h in findings[:3]
            )
            add("Homograph attack detected", 25, f"{len(findings)} finding(s): {evidence}")

    # ── 3. Typosquatting ──────────────────────────────────────────────────
    typo = engine_results.get("typosquat", {})
    if isinstance(typo, dict) and "error" not in typo:
        engines_ok += 1
        findings = typo.get("typosquats", [])
        if findings:
            evidence = "; ".join(
                f"{t.get('technique', '?')} of '{t.get('closest_brand', '?')}'"
                for t in findings[:3]
            )
            add("Typosquat detected", 20, f"{len(findings)} finding(s): {evidence}")

    # ── 4. Domain intelligence ────────────────────────────────────────────
    domain_intel = engine_results.get("domain_intel", {})
    if isinstance(domain_intel, dict) and "error" not in domain_intel:
        engines_ok += 1
        tld_flagged = False
        for domain, info in domain_intel.items():
            if not isinstance(info, dict):
                continue
            age = info.get("age_days")
            if age is not None:
                if age < 7:
                    add(
                        f"Very new domain: {domain}",
                        20,
                        f"Registered only {age} day(s) ago — brand new infrastructure",
                    )
                elif age < 30:
                    add(
                        f"New domain: {domain}",
                        10,
                        f"Registered {age} days ago — typical phishing campaign lifespan",
                    )
            if info.get("suspicious_tld") and not tld_flagged:
                tld = domain.rsplit(".", 1)[-1] if "." in domain else "?"
                add(
                    f"High-risk TLD: .{tld}",
                    5,
                    f"TLD '.{tld}' is commonly abused in phishing / free hosting",
                )
                tld_flagged = True

    # ── 5. Threat intelligence feeds ──────────────────────────────────────
    threat = engine_results.get("threat_intel", {})
    if isinstance(threat, dict) and "error" not in threat:
        engines_ok += 1
        url_results = threat.get("results", {})
        threat_added = False
        for url, res in url_results.items():
            if isinstance(res, dict) and res.get("matched") and not threat_added:
                sources = res.get("sources", [])
                add(
                    "Threat feed match",
                    30,
                    f"URL '{url[:80]}' matched: {', '.join(sources)}",
                )
                threat_added = True
                break

    # ── 6. LLM ensemble ──────────────────────────────────────────────────
    llm = engine_results.get("llm", {})
    if isinstance(llm, dict) and "error" not in llm and llm.get("model_count", 0) > 0:
        engines_ok += 1
        llm_risk = llm.get("risk_score", 0)
        llm_confidence = llm.get("confidence", 50)
        llm_contribution = int(llm_risk * 0.30)
        if llm_contribution > 0:
            add(
                "LLM semantic analysis",
                llm_contribution,
                (
                    f"Ensemble ({llm.get('model_count', 0)} models) verdict: "
                    f"{llm.get('verdict')} — risk {llm_risk}/100, "
                    f"model agreement {llm_confidence}%"
                ),
            )

    # ── 7. Sandbox credential harvesting ─────────────────────────────────
    sandbox = engine_results.get("sandbox", {})
    if isinstance(sandbox, dict) and "error" not in sandbox:
        engines_ok += 1
        for url, sb in sandbox.items():
            if isinstance(sb, dict) and sb.get("has_login_form") and raw_score > 20:
                brands = sb.get("brand_logos_detected", [])
                brand_str = f" (brand: {', '.join(brands[:2])})" if brands else ""
                add(
                    f"Credential harvesting page detected",
                    15,
                    f"Login form found at '{url[:80]}'{brand_str}",
                )
                break

    # ── Final score ───────────────────────────────────────────────────────
    score = min(100, max(0, raw_score))

    if score < 30:
        verdict = "SAFE"
    elif score < 65:
        verdict = "SUSPICIOUS"
    else:
        verdict = "DANGEROUS"

    # Confidence: blend of engine success rate and LLM model agreement
    engine_success_pct = (engines_ok / engines_total * 100) if engines_total else 0
    confidence = int(engine_success_pct * 0.60 + llm_confidence * 0.40)
    confidence = min(100, max(0, confidence))

    return {
        "score": score,
        "verdict": verdict,
        "confidence": confidence,
        "breakdown": breakdown,
        "engines_succeeded": engines_ok,
        "engines_total": engines_total,
    }
