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
# Production: replace with Redis or a proper task queue.
_jobs: dict[str, dict[str, Any]] = {}

_BRANDS_PATH = os.path.join(os.path.dirname(__file__), "data", "top_brands.json")
_SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "samples")
_BRANDS: list[str] = []


def _load_brands() -> list[str]:
    with open(_BRANDS_PATH) as f:
        return json.load(f)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup: load brands list + warm the OpenPhish feed.
    Shutdown: nothing special required.
    """
    global _BRANDS
    logger.info("PhishFilter Pro starting up")
    try:
        _BRANDS = _load_brands()
        logger.info("Loaded %d brand domains", len(_BRANDS))
    except Exception as exc:
        logger.error("Failed to load brands: %s", exc)
        _BRANDS = []

    asyncio.create_task(threat_engine.refresh_openphish_loop())
    yield
    logger.info("PhishFilter Pro shutting down")


# ── App ────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="PhishFilter Pro",
    version="1.0.0",
    description="Multi-engine email + URL phishing forensics API",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
    ],
    allow_origin_regex=r"https://.*\.vercel\.app",
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
    logger.info(
        "Job %s complete — verdict=%s score=%s",
        job_id,
        score_result.get("verdict"),
        score_result.get("score"),
    )


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


if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
