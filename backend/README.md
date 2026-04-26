# PhishFilter Pro — Backend

Multi-engine phishing forensics API built with FastAPI. Analyzes emails, URLs, and raw text using 8 parallel detection engines and an LLM ensemble, then streams results live over WebSocket.

## Architecture

```
POST /api/analyze
       │
       ▼
  Job created (UUID)
       │
       ├── parser.py      — email headers, body, URL extraction
       ├── headers.py     — SPF/DKIM/DMARC (live DNS), domain mismatches, display-name spoof
       ├── urls.py        — redirect chain analysis (up to 10 hops), shortener detection
       ├── homograph.py   — Unicode lookalike / IDN / Cyrillic attacks
       ├── typosquat.py   — Levenshtein, digit substitution, TLD swap, hyphen injection
       ├── domain_intel.py — WHOIS age, SSL cert, NS records, TLD reputation
       ├── llm.py         — 3-model ensemble (Hack Club AI proxy), majority vote
       ├── threat_intel.py — GSB v4 + URLhaus + PhishTank + OpenPhish (in-memory)
       └── sandbox.py     — Playwright headless screenshot, login form detection
              │
              ▼
        scoring.py  — weighted aggregate → score 0-100, verdict, breakdown
              │
              ▼
      GET /api/report/{job_id}
```

## Setup

```bash
cd backend
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
playwright install chromium    # Required for sandbox engine
cp .env.example .env
# Edit .env — add your API keys
```

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `HACKCLUB_API_KEY` | Optional | Hack Club AI proxy key — enables LLM ensemble engine |
| `GSB_API_KEY` | Optional | Google Safe Browsing API v4 key — enables GSB threat feed |
| `PORT` | Optional | Server port (default: `8000`) |

Both keys are optional — the corresponding engines degrade gracefully when absent.

**Get a Hack Club API key:** https://ai.hackclub.com  
**Get a GSB key:** https://console.developers.google.com/apis/api/safebrowsing.googleapis.com

## Running

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

API docs are auto-generated at http://localhost:8000/docs

## API Reference

### `POST /api/analyze`

Submit content for analysis. Returns immediately with a `job_id`.

```bash
# Analyze a URL
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"input_type": "url", "content": "http://paypa1-secure-login.tk/verify"}'

# Analyze a raw email (paste entire .eml content)
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "input_type": "email",
    "content": "From: PayPal <noreply@gmail.com>\nSubject: Account Limited\n\nClick here: http://evil.tk"
  }'

# Analyze free-form text
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"input_type": "text", "content": "Your account has been suspended. Verify at http://bit.ly/xyz123"}'
```

**Response:**
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued",
  "ws_url": "/ws/analyze/550e8400-e29b-41d4-a716-446655440000"
}
```

---

### `GET /ws/analyze/{job_id}` (WebSocket)

Stream engine results live. Connect immediately after receiving `job_id`.

Each message is one of:
```json
{ "engine": "headers",  "status": "running", "result": {} }
{ "engine": "headers",  "status": "done",    "result": { "spf": "fail", ... } }
{ "engine": "aggregator","status": "done",   "result": { "score": 87, "verdict": "DANGEROUS", ... } }
```

**JavaScript example:**
```js
const ws = new WebSocket('ws://localhost:8000/ws/analyze/' + jobId);
ws.onmessage = (e) => {
  const msg = JSON.parse(e.data);
  console.log(`[${msg.engine}] ${msg.status}`, msg.result);
};
```

---

### `GET /api/report/{job_id}`

Retrieve the complete forensic report after analysis is done.

```bash
curl http://localhost:8000/api/report/550e8400-e29b-41d4-a716-446655440000
```

**Response shape:**
```json
{
  "job_id": "...",
  "timestamp": 1714000000.0,
  "input_type": "email",
  "parsed": {
    "headers": { "From": "...", "Return-Path": "..." },
    "body": "...",
    "urls": ["http://evil.tk/..."],
    "attachments": [],
    "attachment_hashes": []
  },
  "engines": {
    "headers":     { "spf": "fail", "dkim": "none", "dmarc": "none", "mismatches": [...], "red_flags": [...] },
    "urls":        { "urls": [{ "original": "...", "redirect_chain": [...], "num_hops": 3 }] },
    "homograph":   { "homographs": [{ "url": "...", "brand_imitated": "paypal", "attack_type": "digit_substitution" }] },
    "typosquat":   { "typosquats": [{ "url": "...", "closest_brand": "paypal.com", "technique": "digit_substitution" }] },
    "domain_intel":{ "paypa1-secure-login.tk": { "age_days": 2, "suspicious_tld": true, "ssl_valid": false } },
    "llm":         { "risk_score": 96, "verdict": "DANGEROUS", "red_flags": [...], "confidence": 100 },
    "threat_intel":{ "results": { "http://...": { "gsb_match": true, "sources": ["google_safe_browsing"] } } },
    "sandbox":     { "http://...": { "has_login_form": true, "brand_logos_detected": ["paypal"] } }
  },
  "score": {
    "score": 94,
    "verdict": "DANGEROUS",
    "confidence": 82,
    "breakdown": [
      { "signal": "SPF/DKIM/DMARC failures", "weight": 20, "reasoning": "SPF=fail, DKIM=none, DMARC=none" },
      { "signal": "Typosquat detected",       "weight": 20, "reasoning": "digit_substitution of paypal.com" },
      { "signal": "Threat feed match",        "weight": 30, "reasoning": "Matched google_safe_browsing" }
    ]
  }
}
```

---

### `GET /api/health`

```bash
curl http://localhost:8000/api/health
# {"status":"ok","service":"phishfilter-pro","brands_loaded":500,"openphish_urls":42109,"active_jobs":0}
```

### `GET /api/test`

Runs analysis on the bundled `samples/phish1.eml` and returns the full report. Useful for deployment smoke-tests.

```bash
curl http://localhost:8000/api/test
```

## Scoring Weights

| Signal | Max Points |
|---|---|
| SPF + DKIM + DMARC failures | 20 |
| From/Return-Path domain mismatch | 15 |
| Display name spoofing | 10 |
| Homograph attack | 25 |
| Typosquat detected | 20 |
| Domain age < 7 days | 20 |
| Domain age < 30 days | 10 |
| Suspicious TLD | 5 |
| Threat feed match (any source) | 30 |
| LLM ensemble risk × 0.30 | up to 30 |
| Sandbox login form on suspicious page | 15 |

**Verdict thresholds:** `0–29 = SAFE` · `30–64 = SUSPICIOUS` · `65–100 = DANGEROUS`

## Engine Details

| Engine | Dependencies | Notes |
|---|---|---|
| `parser` | stdlib `email` | Handles MIME multipart, extracts hidden hrefs |
| `headers` | `dnspython` | Live SPF/DMARC DNS queries |
| `urls` | `httpx` | Async redirect chain, shortener detection |
| `homograph` | `unicodedata` | Cyrillic/Greek/zero-width/punycode |
| `typosquat` | `python-Levenshtein` | 6 detection techniques |
| `domain_intel` | `python-whois`, `ssl` | WHOIS age, SSL cert, NS records |
| `llm` | `httpx` + Hack Club AI | 3 models, majority vote |
| `threat_intel` | `httpx` | GSB v4, URLhaus, PhishTank, OpenPhish |
| `sandbox` | `playwright` | Headless Chromium, login form detection |

## Development

```bash
# Run with auto-reload
uvicorn main:app --reload

# Run smoke test against sample phish email
curl -s http://localhost:8000/api/test | python3 -m json.tool | head -60
```
