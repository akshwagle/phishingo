"""
LLM ensemble semantic analysis engine.
Queries 5 models via Hack Club AI proxy in parallel.

Voting rules:
  - Need ≥2 successful responses to proceed (else returns degraded result)
  - VERDICT: simple majority vote across successful responses
  - RISK_SCORE: weighted average (kimi-k2-thinking and gpt-oss-120b → 1.5×, others 1.0×)
  - RED_FLAGS: union of all unique flags across all models (deduped by category+evidence)
  - CONFIDENCE: (models agreeing on majority verdict / total successful) × 100
  - MODELS_USED: per-model status reported in result for frontend display
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_API_BASE = "https://ai.hackclub.com/proxy/v1/chat/completions"

# ── Model roster ──────────────────────────────────────────────────────────────
# (model_id, weight) — higher weight = stronger pull on RISK_SCORE
_MODELS: list[tuple[str, float]] = [
    ("qwen/qwen3-32b",              1.0),   # primary analyst
    ("moonshotai/kimi-k2-thinking", 1.5),   # deep reasoning — boosted
    ("deepseek/deepseek-r1-0528",   1.0),   # structured output specialist
    ("google/gemini-2.5-flash",     1.0),   # fast cross-check
    ("openai/gpt-oss-120b",         1.5),   # high-confidence tiebreaker — boosted
]

_SYSTEM_PROMPT = """\
You are an elite phishing forensics analyst with 20 years of experience at CISA.
Analyze the provided email or content and return ONLY valid JSON with NO markdown fences.
Exact schema required:
{
  "risk_score": <integer 0-100>,
  "verdict": <"SAFE" | "SUSPICIOUS" | "DANGEROUS">,
  "red_flags": [
    {
      "category": <"urgency" | "authority" | "credentials" | "grammar" | "spoofing" | "threat" | "prize" | "impersonation">,
      "severity": <"critical" | "high" | "medium" | "low">,
      "evidence": "<exact quote from the email>",
      "explanation": "<why this is a phishing indicator>"
    }
  ],
  "social_engineering_tactics": ["<tactic1>", "<tactic2>"],
  "brand_impersonated": "<brand name or null>",
  "target_demographic": "<who this phish targets>",
  "sophistication_level": <"script_kiddie" | "intermediate" | "advanced" | "nation_state">,
  "summary": "<one sentence verdict for non-technical user>",
  "confidence": <integer 0-100>
}
Be aggressive. A risk_score of 0-29 = SAFE, 30-64 = SUSPICIOUS, 65-100 = DANGEROUS.
Detect: fake urgency, authority impersonation, credential requests, threats,
prizes/lotteries, grammatical fingerprints of non-native-English scammers,
mismatched sender claims, suspicious calls to action, brand impersonation,
domain anomalies, social engineering pressure patterns.\
"""

_VALID_VERDICTS = {"SAFE", "SUSPICIOUS", "DANGEROUS"}
_VALID_CATEGORIES = {"urgency", "authority", "credentials", "grammar",
                     "spoofing", "threat", "prize", "impersonation"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_SOPHISTICATION = {"script_kiddie", "intermediate", "advanced", "nation_state"}

# Minimum successful model responses required before we trust the ensemble
_MIN_MODELS_REQUIRED = 2


async def semantic_analysis(email_content: str) -> dict[str, Any]:
    """
    Run all 5 models in parallel and return a weighted ensemble verdict.
    Requires at least 2 successful responses; degrades gracefully on failures.
    """
    api_key = os.getenv("HACKCLUB_API_KEY", "").strip()
    if not api_key:
        return _unavailable_result("HACKCLUB_API_KEY not configured")

    # Truncate to ~8k chars to stay within token budgets across all models
    content = email_content[:8000]

    # Track per-model status for the report
    model_statuses: dict[str, str] = {m: "pending" for m, _ in _MODELS}

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(45.0, connect=10.0),
        limits=httpx.Limits(max_connections=10),
    ) as client:
        tasks = [
            asyncio.wait_for(
                _query_model(client, model, weight, content, api_key, model_statuses),
                timeout=50.0,
            )
            for model, weight in _MODELS
        ]
        raw_responses = await asyncio.gather(*tasks, return_exceptions=True)

    # Separate valid responses from failures, preserving weights
    valid: list[tuple[dict[str, Any], float]] = []
    for (model, weight), resp in zip(_MODELS, raw_responses):
        if isinstance(resp, Exception):
            model_statuses[model] = f"exception: {resp}"
            logger.warning("Model '%s' raised exception: %s", model, resp)
            continue
        if isinstance(resp, dict) and "error" not in resp:
            valid.append((resp, weight))
            logger.info(
                "Model '%s' OK — verdict=%s risk=%s",
                model, resp.get("verdict"), resp.get("risk_score"),
            )
        else:
            err = resp.get("error", "unknown") if isinstance(resp, dict) else str(resp)
            model_statuses[model] = f"error: {err}"
            logger.warning("Model '%s' returned error: %s", model, err)

    if len(valid) < _MIN_MODELS_REQUIRED:
        return _unavailable_result(
            f"Only {len(valid)}/{len(_MODELS)} models succeeded "
            f"(minimum {_MIN_MODELS_REQUIRED} required)",
            models_used=model_statuses,
        )

    return _ensemble_vote(valid, model_statuses)


async def _query_model(
    client: httpx.AsyncClient,
    model: str,
    weight: float,
    content: str,
    api_key: str,
    statuses: dict[str, str],
) -> dict[str, Any]:
    """Send one model request, parse JSON response, update status map."""
    payload: dict[str, Any] = {
        "model": model,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user",   "content": content},
        ],
        "temperature": 0.2,
        "max_tokens": 2000,
        "stream": False,
    }

    try:
        resp = await client.post(
            _API_BASE,
            json=payload,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
        )
        resp.raise_for_status()
        data = resp.json()
        raw_text: str = data["choices"][0]["message"]["content"]
        parsed = _extract_json(raw_text)
        statuses[model] = "ok"
        return parsed
    except httpx.HTTPStatusError as exc:
        statuses[model] = f"http_{exc.response.status_code}"
        return {"error": f"HTTP {exc.response.status_code}: {exc.response.text[:200]}"}
    except httpx.TimeoutException:
        statuses[model] = "timeout"
        return {"error": "request timed out"}
    except (ValueError, KeyError) as exc:
        statuses[model] = f"parse_error: {exc}"
        return {"error": str(exc)}
    except Exception as exc:
        statuses[model] = f"unknown: {exc}"
        return {"error": str(exc)}


def _extract_json(text: str) -> dict[str, Any]:
    """
    Robustly extract a JSON object from model output.
    Handles markdown fences, preamble text, trailing commentary, trailing commas.
    """
    # Strip all variants of markdown code fences
    text = re.sub(r"```(?:json|JSON)?\s*", "", text)
    text = re.sub(r"```\s*", "", text).strip()

    # Locate the outermost JSON object
    start = text.find("{")
    end   = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError(f"No JSON object in model output: {text[:300]!r}")

    json_str = text[start:end + 1]

    try:
        parsed = json.loads(json_str)
    except json.JSONDecodeError:
        # Fix trailing commas before ] or }
        json_str = re.sub(r",\s*([}\]])", r"\1", json_str)
        parsed = json.loads(json_str)

    if not isinstance(parsed, dict):
        raise ValueError("Model returned a JSON array, not an object")

    # ── Defaults and coercions ────────────────────────────────────────────
    parsed.setdefault("risk_score", 50)
    parsed.setdefault("verdict", "SUSPICIOUS")
    parsed.setdefault("red_flags", [])
    parsed.setdefault("social_engineering_tactics", [])
    parsed.setdefault("brand_impersonated", None)
    parsed.setdefault("target_demographic", "general public")
    parsed.setdefault("sophistication_level", "intermediate")
    parsed.setdefault("summary", "")
    parsed.setdefault("confidence", 50)

    try:
        parsed["risk_score"] = max(0, min(100, int(parsed["risk_score"])))
        parsed["confidence"] = max(0, min(100, int(parsed["confidence"])))
    except (TypeError, ValueError):
        parsed["risk_score"] = 50
        parsed["confidence"] = 50

    v = str(parsed.get("verdict", "SUSPICIOUS")).strip().upper()
    parsed["verdict"] = v if v in _VALID_VERDICTS else "SUSPICIOUS"

    sl = str(parsed.get("sophistication_level", "intermediate")).strip().lower()
    parsed["sophistication_level"] = sl if sl in _VALID_SOPHISTICATION else "intermediate"

    # Normalise red_flag entries
    clean_flags: list[dict[str, Any]] = []
    for flag in parsed.get("red_flags", []):
        if not isinstance(flag, dict):
            continue
        cat = str(flag.get("category", "spoofing")).lower()
        sev = str(flag.get("severity", "medium")).lower()
        clean_flags.append({
            "category":    cat if cat in _VALID_CATEGORIES else "spoofing",
            "severity":    sev if sev in _VALID_SEVERITIES else "medium",
            "evidence":    str(flag.get("evidence", ""))[:500],
            "explanation": str(flag.get("explanation", ""))[:500],
        })
    parsed["red_flags"] = clean_flags

    return parsed


def _ensemble_vote(
    valid: list[tuple[dict[str, Any], float]],
    model_statuses: dict[str, str],
) -> dict[str, Any]:
    """
    Combine weighted model responses into a single authoritative verdict.

    Weighting:
      - risk_score: weighted average by model weight
      - verdict:    simple majority (ties broken toward higher risk)
      - confidence: agreement % among successful models
      - red_flags:  union, deduplicated by (category, evidence[:80])
    """
    responses = [r for r, _ in valid]
    weights   = [w for _, w in valid]
    n = len(responses)

    # ── Weighted risk score ───────────────────────────────────────────────
    total_weight = sum(weights)
    weighted_risk = sum(
        r.get("risk_score", 50) * w
        for r, w in zip(responses, weights)
    )
    avg_risk = int(weighted_risk / total_weight)

    # ── Majority verdict ──────────────────────────────────────────────────
    verdict_counts: dict[str, int] = {}
    for r in responses:
        v = r.get("verdict", "SUSPICIOUS")
        verdict_counts[v] = verdict_counts.get(v, 0) + 1

    # Tie-break: prefer the more dangerous verdict
    _risk_rank = {"SAFE": 0, "SUSPICIOUS": 1, "DANGEROUS": 2}
    majority_verdict = max(
        verdict_counts,
        key=lambda k: (verdict_counts[k], _risk_rank.get(k, 0)),
    )

    # ── Confidence = agreement rate ───────────────────────────────────────
    agreeing = verdict_counts[majority_verdict]
    confidence_pct = int((agreeing / n) * 100)

    # ── Union of red flags ────────────────────────────────────────────────
    all_flags: list[dict[str, Any]] = []
    seen_flag_keys: set[str] = set()
    # Sort severity so critical flags from any model appear first
    _sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for r in responses:
        for flag in sorted(
            r.get("red_flags", []),
            key=lambda f: _sev_order.get(f.get("severity", "medium"), 2),
        ):
            dedup_key = (
                str(flag.get("category", "")).lower()
                + "||"
                + str(flag.get("evidence", ""))[:80].lower()
            )
            if dedup_key not in seen_flag_keys:
                seen_flag_keys.add(dedup_key)
                all_flags.append(flag)

    # ── Union of social engineering tactics ───────────────────────────────
    all_tactics: list[str] = []
    seen_tactics: set[str] = set()
    for r in responses:
        for tactic in r.get("social_engineering_tactics", []):
            t = str(tactic).strip()
            if t.lower() not in seen_tactics:
                seen_tactics.add(t.lower())
                all_tactics.append(t)

    # ── Best summary and metadata: prefer model matching majority verdict ─
    summary = ""
    brand_impersonated: str | None = None
    target_demographic = "general public"
    sophistication_level = "intermediate"

    for r in responses:
        if r.get("verdict") == majority_verdict:
            if not summary and r.get("summary"):
                summary = str(r["summary"])
            if brand_impersonated is None and r.get("brand_impersonated"):
                brand_impersonated = str(r["brand_impersonated"])
            if r.get("target_demographic"):
                target_demographic = str(r["target_demographic"])
            if r.get("sophistication_level") in _VALID_SOPHISTICATION:
                sophistication_level = str(r["sophistication_level"])

    if not summary and responses:
        summary = str(responses[0].get("summary", ""))

    # ── Per-model breakdown for the report ───────────────────────────────
    models_report: list[dict[str, Any]] = []
    model_ids = list(model_statuses.keys())
    for model_id in model_ids:
        status = model_statuses[model_id]
        # Find the corresponding response if it succeeded
        model_weight = next((w for m, w in _MODELS if m == model_id), 1.0)
        resp_data: dict[str, Any] | None = None
        for (resp, _w), (m, _) in zip(valid, [(m, w) for m, w in _MODELS if model_statuses[m] == "ok"]):
            if m == model_id:
                resp_data = resp
                break

        entry: dict[str, Any] = {
            "model": model_id,
            "status": status,
            "weight": model_weight,
        }
        if resp_data:
            entry["verdict"] = resp_data.get("verdict")
            entry["risk_score"] = resp_data.get("risk_score")
            entry["confidence"] = resp_data.get("confidence")

        models_report.append(entry)

    return {
        "risk_score":                avg_risk,
        "verdict":                   majority_verdict,
        "red_flags":                 all_flags,
        "social_engineering_tactics": all_tactics,
        "brand_impersonated":        brand_impersonated,
        "target_demographic":        target_demographic,
        "sophistication_level":      sophistication_level,
        "summary":                   summary,
        "confidence":                confidence_pct,
        "model_count":               n,
        "models_used":               model_statuses,
        "individual_verdicts":       [r.get("verdict") for r in responses],
    }


def _unavailable_result(
    reason: str,
    models_used: dict[str, str] | None = None,
) -> dict[str, Any]:
    return {
        "error":                      reason,
        "risk_score":                 50,
        "verdict":                    "SUSPICIOUS",
        "red_flags":                  [],
        "social_engineering_tactics": [],
        "brand_impersonated":         None,
        "target_demographic":         "unknown",
        "sophistication_level":       "unknown",
        "summary":                    f"LLM analysis unavailable: {reason}",
        "confidence":                 0,
        "model_count":                0,
        "models_used":                models_used or {},
    }
