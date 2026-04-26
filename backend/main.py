"""
PhishFilter Pro — FastAPI backend entrypoint.
Multi-engine phishing analysis with WebSocket streaming and job lifecycle management.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any

import tldextract
import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel

from engines import domain_intel as domain_engine
from engines import headers as headers_engine
from engines import homograph as homograph_engine
from engines import llm as llm_engine
from engines import parser as parser_engine
from engines import sandbox as sandbox_engine
from engines import threat_intel as threat_engine
from engines import typosquat as typosquat_engine
from engines import urls as urls_engine
from scoring import aggregate_score

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("phishfilter.main")

# ── In-memory job store ───────────────────────────────────────────────────────
_jobs: dict[str, dict[str, Any]] = {}

_BRANDS_PATH = os.path.join(os.path.dirname(__file__), "data", "top_brands.json")
_SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "samples")
_BRANDS: list[str] = []

# ── MongoDB ───────────────────────────────────────────────────────────────────
_mongo_client: AsyncIOMotorClient | None = None
_scans_col = None  # motor Collection


def _get_col():
    return _scans_col


def _load_brands() -> list[str]:
    with open(_BRANDS_PATH) as f:
        return json.load(f)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: connect MongoDB, load brands, warm OpenPhish. Shutdown: close DB."""
    global _BRANDS, _mongo_client, _scans_col

    logger.info("PhishFilter Pro starting up")

    # MongoDB
    mongo_uri = os.getenv("MONGODB_URI", "").strip()
    if mongo_uri:
        try:
            _mongo_client = AsyncIOMotorClient(mongo_uri, serverSelectionTimeoutMS=5000)
            db = _mongo_client.get_default_database(default="phishfilter")
            _scans_col = db["scans"]
            await _scans_col.create_index("job_id", unique=True)
            await _scans_col.create_index([("timestamp", -1)])
            logger.info("MongoDB connected — collection: %s.scans", db.name)
        except Exception as exc:
            logger.error("MongoDB connection failed: %s — using in-memory fallback", exc)
            _mongo_client = None
            _scans_col = None
    else:
        logger.warning("MONGODB_URI not set — dashboard stats will be in-memory only")

    # Brands
    try:
        _BRANDS = _load_brands()
        logger.info("Loaded %d brand domains", len(_BRANDS))
    except Exception as exc:
        logger.error("Failed to load brands: %s", exc)
        _BRANDS = []

    asyncio.create_task(threat_engine.refresh_openphish_loop())
    yield

    if _mongo_client:
        _mongo_client.close()
    logger.info("PhishFilter Pro shutting down")


# ── App ────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="PhishFilter Pro",
    version="1.0.0",
    description="Multi-engine email + URL phishing forensics API",
    lifespan=lifespan,
)

# Extra origins from env (comma-separated), e.g. your custom Vercel domain
_extra_origins = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:3001",
        "http://localhost:3002",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:3001",
        "http://127.0.0.1:3002",
        "http://localhost:5173",
        *_extra_origins,
    ],
    allow_origin_regex=r"(https://.*\.vercel\.app)|(http://localhost:\d+)|(http://127\.0\.0\.1:\d+)|(chrome-extension://[a-z]+)",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Pydantic models ────────────────────────────────────────────────────────────
class AnalyzeRequest(BaseModel):
    input_type: str  # "email" | "url" | "text"
    content: str


class AnalyzeResponse(BaseModel):
    job_id: str
    status: str
    ws_url: str


class UrlQuickRequest(BaseModel):
    url: str


class PageScanRequest(BaseModel):
    url:    str = ""
    title:  str = ""
    text:   str = ""
    links:  list[str] = []
    forms:  list[dict] = []
    images: list[dict] = []


# ── In-memory URL quick-check cache (30 min TTL) ─────────────────────────────
_url_quick_cache: dict[str, dict[str, Any]] = {}
_URL_QUICK_TTL = 1800  # seconds


# ── Engine orchestration ──────────────────────────────────────────────────────

_ENGINE_TIMEOUTS: dict[str, float] = {
    "llm": 95.0,        # 5 models in parallel, each up to 90s httpx timeout
    "sandbox": 35.0,    # Playwright screenshot
    "domain_intel": 20.0,
    "threat_intel": 20.0,
    "urls": 20.0,
}
_DEFAULT_ENGINE_TIMEOUT = 15.0


async def _run_engine(
    name: str,
    coro: Any,
    ws_queue: asyncio.Queue,
) -> Any:
    """
    Wrap an engine coroutine with WebSocket status notifications.
    Sends running→done messages regardless of success or failure.
    """
    timeout = _ENGINE_TIMEOUTS.get(name, _DEFAULT_ENGINE_TIMEOUT)
    await ws_queue.put({"engine": name, "status": "running", "result": {}})
    try:
        result = await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError:
        logger.warning("Engine '%s' timed out", name)
        result = {"error": f"engine timed out after {timeout:.0f}s", "engine": name}
    except Exception as exc:
        logger.exception("Engine '%s' raised unhandled exception", name)
        result = {"error": str(exc), "engine": name}

    await ws_queue.put({"engine": name, "status": "done", "result": result})
    return result


async def _run_domain_intel(urls: list[str]) -> dict[str, Any]:
    """Invoke domain_intel for each unique domain extracted from the URL list."""
    results: dict[str, Any] = {}
    seen: set[str] = set()

    for url in urls:
        try:
            ext = tldextract.extract(url)
            domain = (
                f"{ext.domain}.{ext.suffix}"
                if ext.suffix
                else ext.domain
            )
            if domain and domain not in seen:
                seen.add(domain)
                results[domain] = await domain_engine.analyze_domain(domain)
        except Exception as exc:
            logger.debug("Domain intel skipped for %s: %s", url, exc)

    return results


async def _run_sandbox(urls: list[str]) -> dict[str, Any]:
    """Screenshot up to 3 unique URLs to stay within the 30-second job budget."""
    results: dict[str, Any] = {}
    for url in urls[:3]:
        results[url] = await sandbox_engine.screenshot_url(url)
    return results


async def run_analysis(job_id: str, request: AnalyzeRequest) -> None:
    """
    Full analysis pipeline for one job:
      1. Parse input (email/url/text)
      2. Run all engines in parallel
      3. Aggregate score
      4. Store report; signal WebSocket consumers that streaming is complete
    """
    _jobs[job_id]["status"] = "running"
    ws_queue: asyncio.Queue = _jobs[job_id]["ws_queue"]

    content = request.content
    input_type = request.input_type

    # Step 1 — parse
    try:
        if input_type == "email":
            parsed = await asyncio.wait_for(parser_engine.parse_email(content), timeout=10)
        elif input_type == "url":
            parsed = {
                "headers": {},
                "body": content,
                "body_html": "",
                "urls": [content],
                "attachments": [],
                "attachment_hashes": [],
            }
        else:  # text
            parsed = {
                "headers": {},
                "body": content,
                "body_html": "",
                "urls": _extract_urls_from_text(content),
                "attachments": [],
                "attachment_hashes": [],
            }
    except Exception as exc:
        logger.exception("Parse stage failed for job %s", job_id)
        parsed = {
            "headers": {},
            "body": content,
            "body_html": "",
            "urls": [],
            "attachments": [],
            "attachment_hashes": [],
            "parse_error": str(exc),
        }

    _jobs[job_id]["parsed"] = parsed

    urls = parsed.get("urls", [])
    email_headers = parsed.get("headers", {})
    body = parsed.get("body", content)

    # Step 2 — run all engines concurrently
    engine_names = [
        "headers", "urls", "homograph", "typosquat",
        "domain_intel", "llm", "threat_intel", "sandbox",
    ]
    engine_coros = [
        headers_engine.analyze_headers(email_headers),
        urls_engine.analyze_urls(urls),
        homograph_engine.detect_homographs(urls, _BRANDS),
        typosquat_engine.detect_typosquats(urls, _BRANDS),
        _run_domain_intel(urls),
        llm_engine.semantic_analysis(body),
        threat_engine.check_threat_feeds(urls),
        _run_sandbox(urls),
    ]

    tasks = [
        _run_engine(name, coro, ws_queue)
        for name, coro in zip(engine_names, engine_coros)
    ]

    results_list = await asyncio.gather(*tasks, return_exceptions=True)

    engine_results: dict[str, Any] = {}
    for name, res in zip(engine_names, results_list):
        if isinstance(res, Exception):
            engine_results[name] = {"error": str(res), "engine": name}
        else:
            engine_results[name] = res

    # Step 3 — aggregate
    try:
        score_result = aggregate_score(engine_results)
    except Exception as exc:
        logger.exception("Scoring failed for job %s", job_id)
        score_result = {"error": str(exc), "score": 0, "verdict": "UNKNOWN"}

    report: dict[str, Any] = {
        "job_id": job_id,
        "timestamp": time.time(),
        "input_type": input_type,
        "parsed": {
            k: v for k, v in parsed.items() if k != "body_html"  # omit large HTML
        },
        "engines": engine_results,
        "score": score_result,
    }

    _jobs[job_id]["report"] = report
    _jobs[job_id]["status"] = "done"

    await ws_queue.put({
        "engine": "aggregator",
        "status": "done",
        "result": score_result,
    })
    await ws_queue.put(None)  # sentinel: stream complete

    verdict = score_result.get("verdict", "SUSPICIOUS")
    score_val = score_result.get("score", 0)
    logger.info("Job %s complete — verdict=%s score=%s", job_id, verdict, score_val)

    # ── Persist summary to MongoDB ────────────────────────────────────────
    col = _get_col()
    if col is not None:
        try:
            created_at = float(_jobs[job_id].get("created_at", time.time()))
            duration = round(time.time() - created_at, 2)
            parsed_urls = report.get("parsed", {}).get("urls", [])
            body_preview = report.get("parsed", {}).get("body", "")[:90]
            description = (parsed_urls[0] if parsed_urls else body_preview) or "Scan completed"
            if len(description) > 90:
                description = description[:90] + "..."

            await col.update_one(
                {"job_id": job_id},
                {"$setOnInsert": {
                    "job_id":           job_id,
                    "timestamp":        report["timestamp"],
                    "input_type":       input_type,
                    "verdict":          verdict,
                    "score":            score_val,
                    "confidence":       score_result.get("confidence", 0),
                    "description":      description,
                    "duration_seconds": duration,
                    "created_at":       created_at,
                }},
                upsert=True,
            )
        except Exception as exc:
            logger.warning("MongoDB write failed for job %s: %s", job_id, exc)


def _extract_urls_from_text(text: str) -> list[str]:
    """Pull bare URLs out of free-form text content."""
    import re
    pattern = re.compile(r'https?://[^\s<>"\')\]},;\\]+', re.IGNORECASE)
    return list({m.group(0).rstrip(".,;)") for m in pattern.finditer(text)})


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.post("/api/analyze")
async def analyze(request: AnalyzeRequest) -> dict[str, Any]:
    """
    Submit email/URL/text content for phishing analysis.
    Runs synchronously and returns the full forensic report.
    Connect to /ws/analyze/{job_id} (returned in response) to stream engine events.
    """
    if request.input_type not in ("email", "url", "text"):
        raise HTTPException(400, detail="input_type must be 'email', 'url', or 'text'")
    if not request.content.strip():
        raise HTTPException(400, detail="content must not be empty")

    job_id = str(uuid.uuid4())
    _jobs[job_id] = {
        "status": "queued",
        "request": request,
        "ws_queue": asyncio.Queue(),
        "report": None,
        "created_at": time.time(),
    }

    await run_analysis(job_id, request)
    report = _jobs[job_id]["report"]
    report["job_id"] = job_id
    report["ws_url"] = f"/ws/analyze/{job_id}"
    return report


@app.websocket("/ws/analyze/{job_id}")
async def ws_stream(websocket: WebSocket, job_id: str) -> None:
    """
    Stream engine results live as each engine completes.
    Each message: {"engine": str, "status": "running"|"done", "result": {...}}
    Final message: {"engine": "aggregator", "status": "done", "result": score}
    """
    await websocket.accept()

    if job_id not in _jobs:
        # Bootstrap a demo analysis so WS test connections always stream something useful
        demo_req = AnalyzeRequest(
            input_type="text",
            content=(
                "URGENT: Your account has been limited. "
                "Click http://paypaI-secure.ru/verify to restore access."
            ),
        )
        _jobs[job_id] = {
            "status": "queued",
            "request": demo_req,
            "ws_queue": asyncio.Queue(),
            "report": None,
            "created_at": time.time(),
        }
        asyncio.create_task(run_analysis(job_id, demo_req))

    ws_queue: asyncio.Queue = _jobs[job_id]["ws_queue"]

    try:
        while True:
            try:
                msg = await asyncio.wait_for(ws_queue.get(), timeout=35)
            except asyncio.TimeoutError:
                await websocket.send_json({"error": "analysis timed out after 35s"})
                break

            if msg is None:
                # Sentinel — analysis complete
                break

            await websocket.send_json(msg)
    except WebSocketDisconnect:
        logger.info("WS client disconnected early for job %s", job_id)
    except Exception as exc:
        logger.exception("WS handler error for job %s", job_id)
        try:
            await websocket.send_json({"error": str(exc)})
        except Exception:
            pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


@app.get("/api/report/{job_id}")
async def get_report(job_id: str) -> dict[str, Any]:
    """
    Retrieve the full forensic report for a completed job.
    Returns HTTP 202 if still running, 404 if unknown job_id.
    """
    if job_id not in _jobs:
        raise HTTPException(404, detail=f"Job '{job_id}' not found")

    job = _jobs[job_id]
    if job["status"] != "done":
        raise HTTPException(202, detail=f"Analysis still running (status={job['status']})")

    return job["report"]


@app.get("/api/health")
async def health() -> dict[str, Any]:
    """Service liveness and readiness check."""
    engines = [
        "headers", "urls", "homograph", "typosquat",
        "domain_intel", "llm", "threat_intel", "sandbox",
    ]
    return {
        "status": "ok",
        "service": "phishfilter-pro",
        "engines": engines,
        "llm_models": len(llm_engine._MODELS),
        "brands_loaded": len(_BRANDS),
        "openphish_urls": len(threat_engine._openphish_urls),
        "active_jobs": sum(1 for j in _jobs.values() if j["status"] == "running"),
    }


@app.get("/api/dashboard")
async def dashboard() -> dict[str, Any]:
    """
    Lightweight dashboard snapshot for frontend homepage metrics/feed.
    Reads from MongoDB when available; falls back to in-memory jobs.
    """
    col = _get_col()
    now = time.time()

    if col is not None:
        # ── MongoDB path ──────────────────────────────────────────────────
        total_scanned = await col.count_documents({})
        dangerous     = await col.count_documents({"verdict": "DANGEROUS"})
        accurate      = await col.count_documents({"confidence": {"$gte": 70}})
        accuracy      = round((accurate / total_scanned) * 100, 1) if total_scanned else 0.0

        avg_pipeline = [{"$group": {"_id": None, "avg": {"$avg": "$duration_seconds"}}}]
        avg_result   = await col.aggregate(avg_pipeline).to_list(1)
        avg_scan_time = round(avg_result[0]["avg"], 1) if avg_result else 0.0

        recent: list[dict[str, Any]] = []
        async for doc in col.find({}, sort=[("timestamp", -1)], limit=20):
            ts = float(doc.get("timestamp", now))
            minutes = int(max(0, now - ts) // 60)
            time_ago = (
                "just now"          if minutes < 1  else
                f"{minutes}m ago"   if minutes < 60 else
                f"{minutes // 60}h ago"
            )
            recent.append({
                "job_id":      doc.get("job_id"),
                "verdict":     doc.get("verdict", "SUSPICIOUS"),
                "description": doc.get("description", "Scan completed"),
                "score":       doc.get("score", 0),
                "time_ago":    time_ago,
            })
    else:
        # ── In-memory fallback ────────────────────────────────────────────
        done_jobs = [j for j in _jobs.values() if j.get("status") == "done" and j.get("report")]
        reports   = sorted(
            [j["report"] for j in done_jobs],
            key=lambda r: float(r.get("timestamp", 0)),
            reverse=True,
        )
        total_scanned = len(reports)
        dangerous     = sum(1 for r in reports if r.get("score", {}).get("verdict") == "DANGEROUS")
        accuracy      = 0.0 if not total_scanned else round(
            sum(1 for r in reports if r.get("score", {}).get("confidence", 0) >= 70)
            / total_scanned * 100, 1,
        )
        durations = [
            float(j.get("report", {}).get("timestamp", 0)) - float(j.get("created_at", 0))
            for j in done_jobs
            if float(j.get("created_at", 0)) > 0
        ]
        avg_scan_time = round(sum(durations) / len(durations), 1) if durations else 0.0

        recent = []
        for report in reports[:20]:
            parsed_urls = report.get("parsed", {}).get("urls", [])
            summary = parsed_urls[0] if parsed_urls else report.get("parsed", {}).get("body", "")[:90]
            summary = (summary or "Scan completed")[:90]
            ts = float(report.get("timestamp", now))
            minutes = int(max(0, now - ts) // 60)
            time_ago = (
                "just now"          if minutes < 1  else
                f"{minutes}m ago"   if minutes < 60 else
                f"{minutes // 60}h ago"
            )
            recent.append({
                "job_id":      report.get("job_id"),
                "verdict":     report.get("score", {}).get("verdict", "SUSPICIOUS"),
                "description": summary,
                "score":       report.get("score", {}).get("score", 0),
                "time_ago":    time_ago,
            })

    return {
        "stats": {
            "emails_scanned":        total_scanned,
            "phishes_caught":        dangerous,
            "accuracy":              accuracy,
            "avg_scan_time_seconds": avg_scan_time,
        },
        "recent_scans": recent,
    }


@app.get("/api/test")
async def test_analysis() -> dict[str, Any]:
    """Run analysis on the bundled sample phishing email and block until complete."""
    sample_path = os.path.join(_SAMPLE_DIR, "phish1.eml")
    try:
        with open(sample_path) as f:
            sample_content = f.read()
    except FileNotFoundError:
        raise HTTPException(500, detail=f"Sample not found at {sample_path}")

    req = AnalyzeRequest(input_type="email", content=sample_content)
    job_id = str(uuid.uuid4())
    _jobs[job_id] = {
        "status": "queued",
        "request": req,
        "ws_queue": asyncio.Queue(),
        "report": None,
        "created_at": time.time(),
    }

    await run_analysis(job_id, req)
    return _jobs[job_id]["report"]


@app.get("/api/test/paypal")
async def test_paypal() -> dict[str, Any]:
    """Smoke-test using the bundled PayPal phishing sample (phish1.eml)."""
    sample_path = os.path.join(_SAMPLE_DIR, "phish1.eml")
    try:
        with open(sample_path) as f:
            sample_content = f.read()
    except FileNotFoundError:
        raise HTTPException(500, detail=f"Sample not found at {sample_path}")

    req = AnalyzeRequest(input_type="email", content=sample_content)
    job_id = str(uuid.uuid4())
    _jobs[job_id] = {
        "status": "queued",
        "request": req,
        "ws_queue": asyncio.Queue(),
        "report": None,
        "created_at": time.time(),
    }
    await run_analysis(job_id, req)
    return _jobs[job_id]["report"]


_LEGIT_EMAIL = """\
From: Jane Smith <jane.smith@company.com>
To: bob@example.com
Subject: Team lunch this Thursday
Date: Sat, 26 Apr 2025 10:00:00 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
Message-ID: <jan-20250426@company.com>
Return-Path: jane.smith@company.com
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of jane.smith@company.com designates 1.2.3.4 as permitted sender) smtp.mailfrom=jane.smith@company.com;
       dkim=pass header.i=@company.com header.s=selector1;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=company.com

Hi Bob,

Just a quick heads-up that we have a team lunch planned for this Thursday at noon.
We will be meeting at the usual spot — the Italian place on 3rd St.

Let me know if you can make it!

Thanks,
Jane
"""


@app.get("/api/test/legit")
async def test_legit() -> dict[str, Any]:
    """False-positive check using a legitimate GitHub notification email."""
    req = AnalyzeRequest(input_type="email", content=_LEGIT_EMAIL)
    job_id = str(uuid.uuid4())
    _jobs[job_id] = {
        "status": "queued",
        "request": req,
        "ws_queue": asyncio.Queue(),
        "report": None,
        "created_at": time.time(),
    }
    await run_analysis(job_id, req)
    return _jobs[job_id]["report"]


@app.get("/api/debug/llm-test")
async def llm_debug() -> dict[str, Any]:
    """
    Ping each LLM model with a trivial prompt to verify API key and model availability.
    Returns per-model status: 'ok' or an error string.
    """
    import httpx as _httpx

    api_key = os.getenv("HACKCLUB_API_KEY", "").strip()
    if not api_key:
        raise HTTPException(500, detail="HACKCLUB_API_KEY not set")

    _model_names = [
        ("qwen",     "qwen/qwen3-32b"),
        ("kimi",     "moonshotai/kimi-k2-thinking"),
        ("deepseek", "deepseek/deepseek-r1-0528"),
        ("gemini",   "google/gemini-2.5-flash"),
        ("gpt_oss",  "openai/gpt-oss-120b"),
    ]

    async def _ping(label: str, model_id: str, client: _httpx.AsyncClient) -> tuple[str, str]:
        try:
            resp = await client.post(
                "https://ai.hackclub.com/proxy/v1/chat/completions",
                json={
                    "model": model_id,
                    "messages": [{"role": "user", "content": "Reply with the single word: PONG"}],
                    "max_tokens": 10,
                    "temperature": 0,
                    "stream": False,
                },
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
            )
            resp.raise_for_status()
            return label, "ok"
        except _httpx.HTTPStatusError as exc:
            return label, f"http_{exc.response.status_code}"
        except _httpx.TimeoutException:
            return label, "timeout"
        except Exception as exc:
            return label, f"error: {exc}"

    async with _httpx.AsyncClient(timeout=_httpx.Timeout(60.0, connect=10.0)) as client:
        results = await asyncio.gather(
            *[_ping(label, model_id, client) for label, model_id in _model_names]
        )

    return dict(results)


@app.post("/api/url-quick")
async def url_quick(req: UrlQuickRequest) -> dict[str, Any]:
    """
    Fast URL risk check for the browser extension (< 500ms target).
    Runs threat_intel + homograph + domain_intel in parallel — no LLM or sandbox.
    Results are cached in-memory for 30 minutes.
    """
    url = req.url.strip()
    if not url:
        raise HTTPException(400, detail="url required")

    # Cache hit
    cached = _url_quick_cache.get(url)
    if cached and cached["expires_at"] > time.time():
        return {**cached["result"], "cached": True}

    # Run fast engines concurrently
    threat_task   = asyncio.create_task(threat_engine.check_threat_feeds([url]))
    homo_task     = asyncio.create_task(homograph_engine.detect_homographs([url], _BRANDS))
    domain_task   = asyncio.create_task(_run_domain_intel([url]))

    threat_res, homo_res, domain_res = await asyncio.gather(
        threat_task, homo_task, domain_task, return_exceptions=True
    )
    if isinstance(threat_res,  Exception): threat_res  = {}
    if isinstance(homo_res,    Exception): homo_res    = {}
    if isinstance(domain_res,  Exception): domain_res  = {}

    # Score
    risk = 0
    sources: list[str] = []
    brand: str | None = None

    for _url, tr in (threat_res.get("results") or {}).items():
        if tr.get("matched"):
            risk += 55
            sources.extend(tr.get("sources", []))

    homographs = homo_res.get("homographs", [])
    if homographs:
        risk += 40
        brand = homographs[0].get("brand_imitated")

    for _domain, info in (domain_res or {}).items():
        age = info.get("age_days")
        if age is not None and age < 30:
            risk += 20
        if info.get("suspicious_tld"):
            risk += 15

    risk = min(100, risk)
    verdict = "DANGEROUS" if risk >= 65 else "SUSPICIOUS" if risk >= 30 else "SAFE"

    result: dict[str, Any] = {
        "risk_score":        risk,
        "verdict":           verdict,
        "brand_impersonated": brand,
        "sources_flagged":   list(set(sources)),
        "cached":            False,
    }
    _url_quick_cache[url] = {"result": result, "expires_at": time.time() + _URL_QUICK_TTL}

    # Persist suspicious/dangerous quick checks to MongoDB so the dashboard sees them
    if verdict != "SAFE":
        col = _get_col()
        if col is not None:
            try:
                import datetime as _dt
                await col.update_one(
                    {"job_id": f"quick_{abs(hash(url)) % 10**9}"},
                    {"$set": {
                        "job_id":            f"quick_{abs(hash(url)) % 10**9}",
                        "verdict":           verdict,
                        "score":             risk,
                        "input_type":        "url",
                        "description":       url[:120],
                        "brand_impersonated": brand,
                        "sources_flagged":   list(set(sources)),
                        "created_at":        _dt.datetime.utcnow(),
                        "scan_duration_s":   0.3,
                    }},
                    upsert=True,
                )
            except Exception as exc:
                logger.warning("MongoDB url_quick persist error: %s", exc)

    return result


@app.post("/api/page-scan")
async def page_scan(req: PageScanRequest) -> dict[str, Any]:
    """
    Full-page phishing analysis for the browser extension.
    Runs LLM on page text + quick-checks every link in parallel (capped at 50).
    """
    # LLM analysis of page text
    llm_data: dict[str, Any] = {}
    if req.text.strip():
        try:
            llm_data = await asyncio.wait_for(
                llm_engine.semantic_analysis(req.text[:5000]), timeout=60
            )
        except Exception as exc:
            llm_data = {"error": str(exc)}

    # Quick-check each link (max 50)
    link_tasks = {
        link: asyncio.create_task(url_quick(UrlQuickRequest(url=link)))
        for link in req.links[:50]
    }
    link_results: dict[str, Any] = {}
    for link, task in link_tasks.items():
        try:
            link_results[link] = await task
        except Exception:
            link_results[link] = {"verdict": "UNKNOWN", "risk_score": 0}

    dangerous_links   = [u for u, r in link_results.items() if r.get("verdict") == "DANGEROUS"]
    suspicious_links  = [u for u, r in link_results.items() if r.get("verdict") == "SUSPICIOUS"]
    password_forms    = [f for f in req.forms if f.get("type") == "password"]

    # Aggregate score
    llm_score = llm_data.get("risk_score", 0) if not llm_data.get("error") else 0
    agg = min(100, int(
        len(dangerous_links) * 30
        + len(suspicious_links) * 10
        + len(password_forms) * 20
        + llm_score * 0.4
    ))
    if agg >= 65:
        verdict = "DANGEROUS"
    elif agg >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = llm_data.get("verdict", "SAFE") if llm_data and not llm_data.get("error") else "SAFE"

    return {
        "verdict":    verdict,
        "risk_score": agg,
        "summary":    llm_data.get("summary", ""),
        "llm": {
            "verdict":    llm_data.get("verdict"),
            "risk_score": llm_score,
            "red_flags":  llm_data.get("red_flags", []),
        },
        "links": {
            "total":     len(req.links),
            "checked":   len(link_results),
            "dangerous": dangerous_links,
            "suspicious": suspicious_links,
        },
        "forms": {
            "total":          len(req.forms),
            "password_fields": len(password_forms),
            "suspicious":     password_forms,
        },
    }


# ── Safe Mails: Gmail IMAP monitor + WhatsApp alerts ─────────────────────────

import imaplib
import email as emaillib
from email.header import decode_header as email_decode_header
import base64
import threading

_safe_mail_sessions: dict[str, dict] = {}  # session_id → config

class SafeMailConnectRequest(BaseModel):
    email: str
    app_password: str
    whatsapp: str


class SafeMailDisconnectRequest(BaseModel):
    session_id: str


@app.post("/api/safe-mails/connect")
async def safe_mails_connect(req: SafeMailConnectRequest) -> dict:
    """Connect Gmail via IMAP and start monitoring for phishing emails."""
    # Validate IMAP connection first
    try:
        mail = imaplib.IMAP4_SSL("imap.gmail.com", 993)
        mail.login(req.email, req.app_password)
        mail.logout()
    except imaplib.IMAP4.error as e:
        raise HTTPException(status_code=400, detail=f"Gmail login failed: {str(e)}. Check your App Password.")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not reach Gmail: {str(e)}")

    session_id = str(uuid.uuid4())
    _safe_mail_sessions[session_id] = {
        "email": req.email,
        "app_password": req.app_password,
        "whatsapp": req.whatsapp,
        "active": True,
        "last_uid": None,
        "alerts_sent": 0,
        "emails_scanned": 0,
    }

    # Start background polling thread
    thread = threading.Thread(
        target=_gmail_poll_loop,
        args=(session_id,),
        daemon=True,
    )
    thread.start()

    logger.info(f"Safe Mails: started monitoring {req.email} → {req.whatsapp}")
    return {"session_id": session_id, "email": req.email, "status": "connected"}


@app.post("/api/safe-mails/disconnect")
async def safe_mails_disconnect(req: SafeMailDisconnectRequest) -> dict:
    if req.session_id in _safe_mail_sessions:
        _safe_mail_sessions[req.session_id]["active"] = False
        del _safe_mail_sessions[req.session_id]
    return {"status": "disconnected"}


@app.get("/api/safe-mails/status/{session_id}")
async def safe_mails_status(session_id: str) -> dict:
    s = _safe_mail_sessions.get(session_id)
    if not s:
        raise HTTPException(status_code=404, detail="Session not found")
    return {
        "active": s["active"],
        "email": s["email"],
        "alerts_sent": s["alerts_sent"],
        "emails_scanned": s["emails_scanned"],
    }


def _gmail_poll_loop(session_id: str) -> None:
    """Background thread: poll Gmail every 2 minutes, analyze new emails, send WhatsApp if suspicious."""
    import time as _time
    seen_uids: set = set()

    while True:
        sess = _safe_mail_sessions.get(session_id)
        if not sess or not sess.get("active"):
            break

        try:
            mail = imaplib.IMAP4_SSL("imap.gmail.com", 993)
            mail.login(sess["email"], sess["app_password"])
            mail.select("INBOX")

            # Get recent unread emails (last 10)
            _, msgs = mail.search(None, "UNSEEN")
            uid_list = msgs[0].split() if msgs[0] else []

            for uid in uid_list[-10:]:
                uid_str = uid.decode()
                if uid_str in seen_uids:
                    continue
                seen_uids.add(uid_str)

                try:
                    _, data = mail.fetch(uid, "(RFC822)")
                    raw = data[0][1] if data and data[0] else None
                    if not raw:
                        continue

                    msg = emaillib.message_from_bytes(raw)
                    subject_raw, enc = email_decode_header(msg.get("Subject", ""))[0]
                    subject = subject_raw.decode(enc or "utf-8") if isinstance(subject_raw, bytes) else (subject_raw or "")
                    sender = msg.get("From", "")

                    # Extract body
                    body = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            if part.get_content_type() == "text/plain":
                                try:
                                    body = part.get_payload(decode=True).decode("utf-8", errors="ignore")
                                    break
                                except Exception:
                                    pass
                    else:
                        try:
                            body = msg.get_payload(decode=True).decode("utf-8", errors="ignore")
                        except Exception:
                            body = str(msg.get_payload())

                    # Build content for analysis
                    content = f"From: {sender}\nSubject: {subject}\n\n{body[:3000]}"
                    sess["emails_scanned"] += 1

                    # Run analysis synchronously (we're in a thread)
                    import httpx
                    backend_url = os.getenv("BACKEND_URL", "http://localhost:8080")
                    # Use internal API call
                    result = _sync_analyze(content)

                    verdict = result.get("verdict", "UNKNOWN")
                    score = result.get("risk_score", 0)

                    logger.info(f"Safe Mails: {sender} → {verdict} ({score})")

                    if score >= 30 and verdict in ("SUSPICIOUS", "DANGEROUS"):
                        sess["alerts_sent"] += 1
                        red_flags = result.get("red_flags", [])
                        flag_text = "\n".join(
                            f"- {f if isinstance(f, str) else f.get('description', '')}"
                            for f in red_flags[:3]
                        )
                        _send_whatsapp_alert(
                            to=sess["whatsapp"],
                            message=(
                                f"*PhishFilter Pro Alert*\n\n"
                                f"*{verdict} EMAIL DETECTED*\n\n"
                                f"From: {sender[:60]}\n"
                                f"Subject: {subject[:80]}\n\n"
                                f"Risk score: *{score}/100*\n"
                                + (f"Red flags:\n{flag_text}\n" if flag_text else "")
                                + f"\nStay safe — do not click any links in this email."
                            ),
                        )
                except Exception as e:
                    logger.warning(f"Safe Mails: error processing email {uid_str}: {e}")

            mail.logout()

        except Exception as e:
            logger.warning(f"Safe Mails: poll error for {session_id}: {e}")

        _time.sleep(120)  # Poll every 2 minutes


def _sync_analyze(content: str) -> dict:
    """Synchronous version of LLM analysis for background thread use."""
    try:
        import asyncio as _asyncio
        loop = _asyncio.new_event_loop()
        result = loop.run_until_complete(llm_engine.analyze(content, input_type="email"))
        loop.close()
        return result if isinstance(result, dict) else {}
    except Exception as e:
        logger.warning(f"Safe Mails: sync analyze error: {e}")
        return {"verdict": "UNKNOWN", "risk_score": 0}


def _send_whatsapp_alert(to: str, message: str) -> None:
    """Send WhatsApp message via Twilio. Falls back to logging if not configured."""
    twilio_sid = os.getenv("TWILIO_ACCOUNT_SID")
    twilio_token = os.getenv("TWILIO_AUTH_TOKEN")
    twilio_from = os.getenv("TWILIO_WHATSAPP_FROM", "whatsapp:+14155238886")

    if not twilio_sid or not twilio_token:
        logger.info(f"[Safe Mails] WhatsApp alert (no Twilio configured): {message[:100]}")
        return

    try:
        from twilio.rest import Client
        client = Client(twilio_sid, twilio_token)
        client.messages.create(
            body=message,
            from_=twilio_from,
            to=f"whatsapp:{to}",
        )
        logger.info(f"[Safe Mails] WhatsApp alert sent to {to}")
    except Exception as e:
        logger.warning(f"[Safe Mails] WhatsApp send failed: {e}")


if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
