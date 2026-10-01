#!/usr/bin/env python3
"""Satark HTTP API + demo UI (aiKart Method 2: API endpoint submission).

Endpoints
  GET  /                 demo web UI
  GET  /health           liveness probe
  POST /api/analyze      JSON in → {"format", "response", "result"}
  POST /run              aiKart-style: form answers in → {"format", "response"}
  POST /invoke, /api/run aliases of /run
Docs at /docs (OpenAPI).

Run:  uvicorn server:app --host 0.0.0.0 --port ${PORT:-7860}
"""

from __future__ import annotations

import os
import time
from collections import defaultdict, deque
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

from satark import __version__
from satark.agent import analyze
from satark.config import get_settings
from satark.kb.i18n import LANGUAGES
from satark.report_html import render_html
from satark.report_md import render_markdown

app = FastAPI(
    title="Satark — cyber-fraud first-responder agent",
    version=__version__,
    description="Paste a suspicious message or describe a fraud; Satark investigates with forensic tools, scores the risk, plans the golden-hour response and drafts the complaint pack.",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET", "POST", "OPTIONS"], allow_headers=["*"])

WEB = Path(__file__).parent / "web"
TOKEN = os.environ.get("SATARK_API_TOKEN", "").strip()
RATE = int(os.environ.get("SATARK_RATE_PER_MIN", "20"))
_hits: dict[str, deque] = defaultdict(deque)


def _guard(request: Request) -> None:
    if TOKEN:
        auth = request.headers.get("authorization", "")
        if auth != f"Bearer {TOKEN}" and request.headers.get("x-api-key") != TOKEN:
            raise HTTPException(status_code=401, detail="missing or invalid token")
    ip = request.client.host if request.client else "?"
    now = time.time()
    q = _hits[ip]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= RATE:
        raise HTTPException(status_code=429, detail="rate limit — try again in a minute")
    q.append(now)


def _payload(body) -> dict:
    if isinstance(body, dict):
        # Accept {"inputs": {...}} / {"input": {...}} wrappers as well as flat payloads.
        for key in ("inputs", "input", "data", "payload"):
            if isinstance(body.get(key), dict):
                return body[key]
        if isinstance(body.get("input"), str) and not body.get("situation"):
            return {**body, "situation": body["input"]}
        return body
    if isinstance(body, str):
        return {"situation": body}
    return {}


def _render(result: dict, fmt: str) -> str:
    if fmt == "markdown" or fmt == "text":
        return render_markdown(result)
    if fmt == "json":
        import json

        return json.dumps(result, ensure_ascii=False, default=str)
    return render_html(result)


@app.get("/health")
def health():
    s = get_settings()
    return {"status": "ok", "version": __version__, "llm": s.resolved_provider()}


@app.get("/", response_class=HTMLResponse)
def home():
    index = WEB / "index.html"
    if index.exists():
        return FileResponse(index)
    return HTMLResponse("<h1>Satark API</h1><p>POST /api/analyze</p>")


@app.get("/api/meta")
def meta():
    return {"languages": list(LANGUAGES.keys()), "version": __version__}


@app.post("/api/analyze")
async def api_analyze(request: Request):
    _guard(request)
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        body = (await request.body()).decode("utf-8", "replace")
    payload = _payload(body)
    if not str(payload.get("situation") or payload.get("message") or payload.get("text") or "").strip():
        raise HTTPException(status_code=422, detail="Provide 'situation': the suspicious message or what happened.")
    fmt = str(payload.get("output_format") or request.query_params.get("format") or "html").lower()
    result = analyze(payload)
    return JSONResponse({"format": fmt if fmt in {"html", "markdown", "json", "text"} else "html", "response": _render(result, fmt), "result": result})


async def _run(request: Request):
    _guard(request)
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        body = (await request.body()).decode("utf-8", "replace")
    payload = _payload(body)
    fmt = str(payload.get("output_format") or request.query_params.get("format") or os.environ.get("SATARK_OUTPUT_FORMAT", "html")).lower()
    if not str(payload.get("situation") or payload.get("message") or payload.get("text") or "").strip():
        return {"format": "markdown", "response": "Please paste the suspicious message or describe what happened."}
    result = analyze(payload)
    return {"format": fmt, "response": _render(result, fmt)}


app.add_api_route("/run", _run, methods=["POST"])
app.add_api_route("/invoke", _run, methods=["POST"])
app.add_api_route("/api/run", _run, methods=["POST"])


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "7860")))
