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
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
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


# ── Safe Mails: Google OAuth + Gmail API + Telegram alerts ───────────────────

import base64
import email as emaillib
import threading
import urllib.parse
from email.header import decode_header as _decode_header

import random
import string as _string

_safe_mail_sessions: dict[str, dict] = {}   # session_id → config
_oauth_pending: dict[str, dict] = {}         # google-state → {code, chat_id}

# Verification code → chat_id mapping (set by Telegram webhook when user sends code)
_verify_codes: dict[str, int | None] = {}    # code → chat_id (None = pending)

_TG_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
_TG_API   = f"https://api.telegram.org/bot{_TG_TOKEN}"

GOOGLE_SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/userinfo.email",
    "openid",
]

_GOOGLE_CLIENT_ID     = os.getenv("GOOGLE_CLIENT_ID", "4979896833-m4ij85sn429q8uhe7qf7qtrtpi0skf81.apps.googleusercontent.com")
_GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
_GOOGLE_REDIRECT_URI  = os.getenv(
    "GOOGLE_REDIRECT_URI",
    "https://phishingo-production.up.railway.app/api/safe-mails/callback",
)
_FRONTEND_URL = os.getenv("FRONTEND_URL", "https://phishingo-zk3c.vercel.app")


def _generate_verify_code() -> str:
    """Generate a human-readable 6-char verification code like PFP-A3X9."""
    suffix = ''.join(random.choices(_string.ascii_uppercase + _string.digits, k=4))
    return f"PFP-{suffix}"


class SafeMailGenerateCodeRequest(BaseModel):
    phone: str  # user's phone number (for their reference only)


class SafeMailAuthRequest(BaseModel):
    code: str   # verification code user sent to the bot


class SafeMailDisconnectRequest(BaseModel):
    session_id: str


@app.post("/api/safe-mails/generate-code")
async def safe_mails_generate_code(req: SafeMailGenerateCodeRequest) -> dict:
    """
    Step 1: User enters their phone number.
    We generate a short code. They send it to the Telegram bot.
    Returns: { code: 'PFP-XXXX' }
    """
    code = _generate_verify_code()
    _verify_codes[code] = None  # None = waiting for user to send it to bot
    return {"code": code, "bot": f"https://t.me/phishfilter_bot", "phone": req.phone}


@app.get("/api/safe-mails/code-status/{code}")
async def safe_mails_code_status(code: str) -> dict:
    """Frontend polls this every 2s. Returns linked=True once user has messaged the bot."""
    if code not in _verify_codes:
        raise HTTPException(status_code=404, detail="Code not found or expired")
    chat_id = _verify_codes.get(code)
    return {"linked": chat_id is not None, "chat_id": chat_id}


@app.post("/api/safe-mails/auth-url")
async def safe_mails_auth_url(req: SafeMailAuthRequest) -> dict:
    """Step 2: User has verified Telegram. Now get Google OAuth URL."""
    if not _GOOGLE_CLIENT_ID:
        raise HTTPException(status_code=503, detail="Google OAuth not configured on this server.")

    chat_id = _verify_codes.get(req.code)
    if chat_id is None:
        raise HTTPException(status_code=400, detail="Telegram not yet verified. Send the code to the bot first.")

    state = str(uuid.uuid4())
    _oauth_pending[state] = {"code": req.code, "chat_id": chat_id}

    params = {
        "client_id":     _GOOGLE_CLIENT_ID,
        "redirect_uri":  _GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope":         " ".join(GOOGLE_SCOPES),
        "access_type":   "offline",
        "prompt":        "consent",
        "state":         state,
    }
    auth_url = "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode(params)
    return {"auth_url": auth_url}


@app.get("/api/safe-mails/oauth-debug")
async def safe_mails_oauth_debug() -> dict:
    """Debug endpoint — confirms which OAuth credentials are deployed."""
    return {
        "client_id_set":      bool(_GOOGLE_CLIENT_ID),
        "client_id_preview":  _GOOGLE_CLIENT_ID[:30] + "..." if _GOOGLE_CLIENT_ID else "",
        "client_secret_set":  bool(_GOOGLE_CLIENT_SECRET),
        "client_secret_len":  len(_GOOGLE_CLIENT_SECRET),
        "redirect_uri":       _GOOGLE_REDIRECT_URI,
        "frontend_url":       _FRONTEND_URL,
    }


@app.get("/api/safe-mails/callback")
async def safe_mails_callback(code: str = "", state: str = "", error: str = "") -> Any:
    """Step 2: Google redirects here after user consents. Exchange code for tokens."""
    from fastapi.responses import RedirectResponse

    pending = _oauth_pending.pop(state, None)
    if error or not code:
        return RedirectResponse(f"{_FRONTEND_URL}/safe-mails?error={error or 'cancelled'}")
    if not pending:
        return RedirectResponse(f"{_FRONTEND_URL}/safe-mails?error=invalid_state")

    if not _GOOGLE_CLIENT_SECRET:
        logger.error("Safe Mails: GOOGLE_CLIENT_SECRET is not set in environment!")
        return RedirectResponse(f"{_FRONTEND_URL}/safe-mails?error=missing_client_secret")

    # Exchange code for access + refresh tokens
    import httpx as _httpx
    try:
        token_resp = await _httpx.AsyncClient().post(
            "https://oauth2.googleapis.com/token",
            data={
                "code":          code,
                "client_id":     _GOOGLE_CLIENT_ID,
                "client_secret": _GOOGLE_CLIENT_SECRET,
                "redirect_uri":  _GOOGLE_REDIRECT_URI,
                "grant_type":    "authorization_code",
            },
        )
        tokens = token_resp.json()
        if "error" in tokens:
            err_desc = tokens.get("error_description", "")
            err_code = tokens.get("error", "unknown")
            logger.error(f"Safe Mails: Google rejected token exchange: {err_code} — {err_desc}")
            return RedirectResponse(
                f"{_FRONTEND_URL}/safe-mails?error={urllib.parse.quote(err_code + ': ' + err_desc[:80])}"
            )
    except Exception as e:
        logger.error(f"Safe Mails: token exchange failed: {type(e).__name__}: {e}")
        return RedirectResponse(f"{_FRONTEND_URL}/safe-mails?error={urllib.parse.quote('token_exchange: ' + str(e)[:80])}")

    # Get user's email — try userinfo first, then Gmail profile API as fallback
    gmail = "connected"
    access_token = tokens.get("access_token", "")
    try:
        info_resp = await _httpx.AsyncClient().get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        info = info_resp.json()
        if info.get("email"):
            gmail = info["email"]
    except Exception as e:
        logger.warning(f"Safe Mails: userinfo failed: {e}")

    # Fallback: Gmail profile endpoint (works with just gmail.readonly scope)
    if gmail in ("connected", "unknown"):
        try:
            prof_resp = await _httpx.AsyncClient().get(
                "https://gmail.googleapis.com/gmail/v1/users/me/profile",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            prof = prof_resp.json()
            if prof.get("emailAddress"):
                gmail = prof["emailAddress"]
        except Exception as e:
            logger.warning(f"Safe Mails: gmail profile failed: {e}")

    verify_code = pending.get("code", "")
    telegram_chat_id = pending.get("chat_id")

    session_id = str(uuid.uuid4())
    _safe_mail_sessions[session_id] = {
        "email":            gmail,
        "verify_code":      verify_code,
        "telegram_chat_id": telegram_chat_id,
        "access_token":     tokens.get("access_token", ""),
        "refresh_token":    tokens.get("refresh_token", ""),
        "active":           True,
        "alerts_sent":      0,
        "emails_scanned":   0,
        "seen_ids":         set(),
    }

    # Start background polling
    threading.Thread(target=_gmail_poll_loop, args=(session_id,), daemon=True).start()
    logger.info(f"Safe Mails: Google OAuth connected {gmail} (code={verify_code}, chat_id={telegram_chat_id})")

    # Send Telegram welcome
    if telegram_chat_id:
        _send_telegram_message(
            telegram_chat_id,
            f"✅ *Gmail connected!*\n\nNow monitoring *{gmail}*\n\nI'll message you here whenever a suspicious email arrives. Stay safe! 🛡",
        )

    redirect = (
        f"{_FRONTEND_URL}/safe-mails"
        f"?status=connected&session={session_id}&email={urllib.parse.quote(gmail)}"
        f"&code={urllib.parse.quote(verify_code)}"
    )
    return RedirectResponse(redirect)


@app.post("/api/safe-mails/disconnect")
async def safe_mails_disconnect(req: SafeMailDisconnectRequest) -> dict:
    s = _safe_mail_sessions.get(req.session_id)
    if s:
        s["active"] = False
        del _safe_mail_sessions[req.session_id]
    return {"status": "disconnected"}


@app.get("/api/safe-mails/status/{session_id}")
async def safe_mails_status(session_id: str) -> dict:
    s = _safe_mail_sessions.get(session_id)
    if not s:
        raise HTTPException(status_code=404, detail="Session not found")
    return {
        "active":          s["active"],
        "email":           s["email"],
        "alerts_sent":     s["alerts_sent"],
        "emails_scanned":  s["emails_scanned"],
    }


@app.get("/api/safe-mails/debug/{session_id}")
async def safe_mails_debug(session_id: str) -> dict:
    """Diagnostic endpoint — see exactly what's happening for a session."""
    s = _safe_mail_sessions.get(session_id)
    if not s:
        raise HTTPException(status_code=404, detail="Session not found")

    # Try a Gmail profile lookup right now to update email if it's unknown
    if s.get("email") in ("unknown", "connected"):
        try:
            import urllib.request as _req, json as _json
            req = _req.Request(
                "https://gmail.googleapis.com/gmail/v1/users/me/profile",
                headers={"Authorization": f"Bearer {s['access_token']}"},
            )
            with _req.urlopen(req, timeout=10) as r:
                prof = _json.loads(r.read())
                if prof.get("emailAddress"):
                    s["email"] = prof["emailAddress"]
        except Exception as e:
            logger.warning(f"profile fetch err: {e}")

    return {
        "session_id":         session_id,
        "email":              s.get("email"),
        "telegram_chat_id":   s.get("telegram_chat_id"),
        "active":             s.get("active"),
        "alerts_sent":        s.get("alerts_sent"),
        "emails_scanned":     s.get("emails_scanned"),
        "seen_ids_count":     len(s.get("seen_ids", set())),
        "has_access_token":   bool(s.get("access_token")),
        "has_refresh_token":  bool(s.get("refresh_token")),
    }


@app.post("/api/safe-mails/test-alert/{session_id}")
async def safe_mails_test_alert(session_id: str) -> dict:
    """Send a test Telegram alert RIGHT NOW based on the latest email in the inbox.
    Proves: Gmail API works, message extraction works, LLM works, Telegram delivery works."""
    s = _safe_mail_sessions.get(session_id)
    if not s:
        raise HTTPException(status_code=404, detail="Session not found")

    chat_id = s.get("telegram_chat_id")
    if not chat_id:
        raise HTTPException(status_code=400, detail="No Telegram chat ID linked to this session")

    # Fetch most recent message (any state)
    msgs_data = _gmail_api_get(s, "/users/me/messages", {"maxResults": "1"})
    messages = (msgs_data or {}).get("messages", [])
    if not messages:
        _send_telegram_message(
            chat_id,
            "🧪 *PhishFilter Test*\n\nGmail connected but inbox is empty. The bot pipeline works! "
            "I'll alert you here as soon as a suspicious email arrives.",
        )
        return {"sent": True, "note": "inbox empty — sent generic test"}

    msg_data = _gmail_api_get(s, f"/users/me/messages/{messages[0]['id']}", {"format": "full"})
    if not msg_data:
        raise HTTPException(status_code=500, detail="Gmail API failed to fetch message")

    headers = {h["name"]: h["value"] for h in msg_data.get("payload", {}).get("headers", [])}
    sender  = headers.get("From", "unknown")
    subject = headers.get("Subject", "(no subject)")
    body    = _extract_email_body(msg_data.get("payload", {}))

    content = f"From: {sender}\nSubject: {subject}\n\n{body[:3000]}"
    result  = _sync_analyze_email(content)
    verdict = result.get("verdict", "UNKNOWN")
    score   = result.get("risk_score", 0)
    summary = result.get("summary", "")

    emoji = "🚨" if verdict == "DANGEROUS" else "⚠️" if verdict == "SUSPICIOUS" else "✅"
    msg = (
        f"🧪 *PhishFilter Test Alert*\n\n"
        f"Most recent email in your inbox:\n\n"
        f"{emoji} *{verdict}* — *{score}/100*\n\n"
        f"📧 From: `{sender[:60]}`\n"
        f"📌 Subject: _{subject[:80]}_\n\n"
        f"{summary[:200]}\n\n"
        f"_This is a one-time test. Real alerts will only trigger on suspicious mails._"
    )
    ok = _send_telegram_message(chat_id, msg)
    return {"sent": ok, "verdict": verdict, "score": score, "sender": sender[:60]}


# ── Telegram webhook ─────────────────────────────────────────────────────────

@app.post("/api/telegram/webhook")
async def telegram_webhook(update: dict) -> dict:
    """
    Handles all Telegram bot messages.
    - /start → greeting
    - PFP-XXXX code → link chat_id to pending verification
    """
    data = update or {}
    message = data.get("message") or data.get("edited_message") or {}
    text    = (message.get("text") or "").strip()
    chat    = message.get("chat", {})
    chat_id = chat.get("id")
    name    = chat.get("first_name", "there")

    if not chat_id:
        return {"ok": True}

    # Check if message is a verification code (format: PFP-XXXX)
    import re as _re
    code_match = _re.match(r'^(PFP-[A-Z0-9]{4})$', text.upper())
    if code_match:
        code = code_match.group(1)
        if code in _verify_codes:
            _verify_codes[code] = chat_id  # mark as verified
            _send_telegram_message(
                chat_id,
                f"✅ *Verified, {name}!*\n\n"
                "Your Telegram is linked to PhishFilter Pro.\n\n"
                "Now go back to the Safe Mails page and click *Connect Gmail* to finish setup.\n\n"
                "I'll alert you here whenever a suspicious email arrives. 🛡",
            )
        else:
            _send_telegram_message(
                chat_id,
                "❌ That code wasn't recognised. It may have expired.\n\n"
                f"Go to {_FRONTEND_URL}/safe-mails to generate a new one.",
            )
        return {"ok": True}

    if text.startswith("/start"):
        _send_telegram_message(
            chat_id,
            f"👋 Hi {name}! I'm *PhishFilter Pro Bot*.\n\n"
            "I scan your Gmail for phishing emails and alert you instantly.\n\n"
            f"To get started, visit:\n{_FRONTEND_URL}/safe-mails\n\n"
            "You'll get a 6-character code to send me here.",
        )
        return {"ok": True}

    # Any other message
    _send_telegram_message(
        chat_id,
        f"Send me your *PFP-XXXX* verification code from the Safe Mails page, or visit:\n{_FRONTEND_URL}/safe-mails",
    )
    return {"ok": True}


def _send_telegram_message(chat_id: int, text: str) -> bool:
    """Send a Telegram message via Bot API (no external dependencies). Returns success bool."""
    if not _TG_TOKEN:
        logger.warning(f"[Telegram] Bot token NOT SET — would send to {chat_id}: {text[:80]}")
        return False
    if not chat_id:
        logger.warning(f"[Telegram] No chat_id provided — message dropped: {text[:80]}")
        return False
    import json as _json, urllib.request as _req, urllib.error as _err
    url     = f"{_TG_API}/sendMessage"
    payload = _json.dumps({"chat_id": chat_id, "text": text, "parse_mode": "Markdown"}).encode()
    request = _req.Request(url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with _req.urlopen(request, timeout=10) as r:
            resp = _json.loads(r.read())
            if resp.get("ok"):
                logger.info(f"[Telegram] ✓ sent to {chat_id} ({len(text)} chars)")
                return True
            logger.warning(f"[Telegram] API returned not-ok: {resp}")
            return False
    except _err.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        logger.warning(f"[Telegram] HTTP {e.code} sending to {chat_id}: {body[:200]}")
        # If markdown parse error, retry without markdown
        if "can't parse" in body.lower() or "parse_mode" in body.lower():
            try:
                payload2 = _json.dumps({"chat_id": chat_id, "text": text}).encode()
                req2 = _req.Request(url, data=payload2, headers={"Content-Type": "application/json"}, method="POST")
                with _req.urlopen(req2, timeout=10) as r:
                    logger.info(f"[Telegram] ✓ sent to {chat_id} (plain text retry)")
                    return True
            except Exception as e2:
                logger.warning(f"[Telegram] plain retry failed: {e2}")
        return False
    except Exception as e:
        logger.warning(f"[Telegram] sendMessage failed for {chat_id}: {e}")
        return False


# ── Background Gmail polling ──────────────────────────────────────────────────

def _refresh_access_token(sess: dict) -> bool:
    """Refresh the access token using the refresh token."""
    if not sess.get("refresh_token"):
        return False
    try:
        import urllib.request, json as _json
        data = urllib.parse.urlencode({
            "client_id":     _GOOGLE_CLIENT_ID,
            "client_secret": _GOOGLE_CLIENT_SECRET,
            "refresh_token": sess["refresh_token"],
            "grant_type":    "refresh_token",
        }).encode()
        req = urllib.request.Request("https://oauth2.googleapis.com/token", data=data, method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            tokens = _json.loads(r.read())
        if "access_token" in tokens:
            sess["access_token"] = tokens["access_token"]
            return True
    except Exception as e:
        logger.warning(f"Safe Mails: token refresh failed: {e}")
    return False


def _gmail_api_get(sess: dict, path: str, params: dict | None = None) -> dict | None:
    """Make a Gmail API request with automatic token refresh."""
    import urllib.request, json as _json
    base = "https://gmail.googleapis.com/gmail/v1"
    qs = ("?" + urllib.parse.urlencode(params)) if params else ""
    url = f"{base}{path}{qs}"

    for attempt in range(2):
        try:
            req = urllib.request.Request(url, headers={"Authorization": f"Bearer {sess['access_token']}"})
            with urllib.request.urlopen(req, timeout=15) as r:
                return _json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code == 401 and attempt == 0:
                if _refresh_access_token(sess):
                    continue
            logger.warning(f"Safe Mails: Gmail API error {e.code} for {path}")
            return None
        except Exception as ex:
            logger.warning(f"Safe Mails: Gmail API exception: {ex}")
            return None
    return None


def _extract_email_body(payload: dict) -> str:
    """Recursively extract plain-text body from Gmail message payload."""
    mime = payload.get("mimeType", "")
    if mime == "text/plain":
        data = payload.get("body", {}).get("data", "")
        try:
            return base64.urlsafe_b64decode(data + "==").decode("utf-8", errors="ignore")
        except Exception:
            return ""
    if "parts" in payload:
        for part in payload["parts"]:
            text = _extract_email_body(part)
            if text:
                return text
    return ""


def _gmail_poll_loop(session_id: str) -> None:
    import time as _time

    logger.info(f"Safe Mails: polling loop STARTED for session {session_id}")
    iteration = 0

    while True:
        sess = _safe_mail_sessions.get(session_id)
        if not sess or not sess.get("active"):
            logger.info(f"Safe Mails: polling loop EXIT for {session_id}")
            break

        iteration += 1
        try:
            # First few iterations: scan last 30 mins (in case mail arrived during connection setup)
            # After that: tight 5-minute window to avoid re-alerting
            window = "newer_than:30m" if iteration <= 3 else "newer_than:5m"

            msgs_data = _gmail_api_get(
                sess,
                f"/users/me/messages",
                {"q": f"is:unread {window} -in:spam -in:trash", "maxResults": "20"},
            )
            messages = (msgs_data or {}).get("messages", [])
            logger.info(
                f"Safe Mails [{sess.get('email','?')}]: poll #{iteration} — "
                f"found {len(messages)} unread in {window}, seen={len(sess.get('seen_ids',set()))}"
            )

            for msg_ref in messages:
                msg_id = msg_ref.get("id", "")
                if not msg_id or msg_id in sess["seen_ids"]:
                    continue
                sess["seen_ids"].add(msg_id)

                # Fetch full message
                msg_data = _gmail_api_get(sess, f"/users/me/messages/{msg_id}", {"format": "full"})
                if not msg_data:
                    continue

                headers = {h["name"]: h["value"] for h in msg_data.get("payload", {}).get("headers", [])}
                sender  = headers.get("From", "")
                subject = headers.get("Subject", "(no subject)")
                body    = _extract_email_body(msg_data.get("payload", {}))

                sess["emails_scanned"] += 1
                content = f"From: {sender}\nSubject: {subject}\n\n{body[:3000]}"

                result  = _sync_analyze_email(content)
                verdict = result.get("verdict", "UNKNOWN")
                score   = result.get("risk_score", 0)
                summary = result.get("summary", "")

                logger.info(
                    f"Safe Mails [{sess['email']}]: scanned {sender[:40]} subj={subject[:40]} "
                    f"→ {verdict} ({score})"
                )

                chat_id = sess.get("telegram_chat_id")
                if not chat_id:
                    logger.warning(f"Safe Mails [{sess['email']}]: NO chat_id linked — skipping alert")
                    continue

                if score >= 25 and verdict in ("SUSPICIOUS", "DANGEROUS"):
                    sess["alerts_sent"] += 1
                    flags = result.get("red_flags", [])
                    flag_lines = "\n".join(
                        f"• {f if isinstance(f, str) else f.get('description', '')}"
                        for f in flags[:3]
                    )
                    emoji  = "🚨" if verdict == "DANGEROUS" else "⚠️"
                    verdict_label = "DANGEROUS — DO NOT open" if verdict == "DANGEROUS" else "SUSPICIOUS — be careful"

                    msg = (
                        f"{emoji} *PhishFilter Pro*\n\n"
                        f"*{verdict_label}*\n\n"
                        f"📧 From: `{sender[:60]}`\n"
                        f"📌 Subject: _{subject[:80]}_\n\n"
                        f"🔴 Risk score: *{score}/100*\n\n"
                    )
                    if summary:
                        # Keep summary short and plain
                        short = summary[:200].rstrip()
                        msg += f"📝 _{short}_\n\n"
                    if flag_lines:
                        msg += f"Red flags:\n{flag_lines}\n\n"
                    msg += "❌ Do NOT click any links in this email."

                    _send_telegram_message(chat_id, msg)
        except Exception as e:
            logger.warning(f"Safe Mails: poll error for {session_id}: {e}", exc_info=True)

        _time.sleep(60)


def _sync_analyze_email(content: str) -> dict:
    try:
        import asyncio as _asyncio
        loop = _asyncio.new_event_loop()
        result = loop.run_until_complete(llm_engine.analyze(content, input_type="email"))
        loop.close()
        return result if isinstance(result, dict) else {}
    except Exception as e:
        logger.warning(f"Safe Mails: sync analyze error: {e}")
        return {"verdict": "UNKNOWN", "risk_score": 0}




if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
