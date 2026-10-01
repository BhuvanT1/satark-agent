#!/usr/bin/env python3
"""aiKart container entrypoint ("Try Me Now").

Contract (aiKart Agent Manifest Guide):
  input : /aikart/input.json  (also the AIKART_INPUT env var) — the buyer's form answers
  output: /aikart/output.json — {"format": "markdown|text|json|html", "response": "..."}
  exit 0 on success; non-zero = failure.

Satark always tries to produce a useful report: if anything unexpected fails,
it still writes a safety-first fallback report and exits 0.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import traceback
import urllib.request

INPUT_PATH = os.environ.get("AIKART_INPUT_PATH", "/aikart/input.json")
OUTPUT_PATH = os.environ.get("AIKART_OUTPUT_PATH", "/aikart/output.json")


def log(msg: str) -> None:
    print(f"[satark] {msg}", file=sys.stderr, flush=True)


def read_input(path: str | None) -> dict:
    candidates = [path] if path else [INPUT_PATH]
    for p in candidates:
        if p and os.path.exists(p):
            with open(p, encoding="utf-8") as fh:
                raw = fh.read().strip()
            if raw:
                return json.loads(raw)
    env = os.environ.get("AIKART_INPUT", "").strip()
    if env:
        return json.loads(env)
    return {}


def try_remote(payload: dict, fmt: str) -> str | None:
    """Optional: call a hosted Satark API that keeps the LLM key server-side."""
    from satark.config import get_settings

    s = get_settings()
    if not s.remote_url:
        return None
    try:
        body = json.dumps({**payload, "output_format": fmt}).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if s.remote_token:
            headers["Authorization"] = f"Bearer {s.remote_token}"
        req = urllib.request.Request(s.remote_url + "/api/analyze", data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=s.remote_timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        if data.get("response"):
            log("served by remote Satark API")
            return data["response"]
    except Exception as exc:  # noqa: BLE001
        log(f"remote API unavailable ({exc.__class__.__name__}); running locally")
    return None


def fallback_report(fmt: str, err: str) -> str:
    text = (
        "Satark could not complete the full analysis, but here is what to do right now:\n"
        "1. Do not pay, click links, install apps or share OTP/UPI PIN.\n"
        "2. If money was lost, call 1930 immediately and file a complaint at cybercrime.gov.in.\n"
        "3. Call your bank on the number printed on your card to block cards/UPI.\n"
        "4. Report fraud calls/SMS on sancharsaathi.gov.in → Chakshu.\n"
    )
    if fmt == "html":
        items = "".join(f"<li>{line[3:]}</li>" for line in text.splitlines()[1:])
        return (
            "<!doctype html><html><head><meta charset='utf-8'><style>body{font:15px/1.6 system-ui,sans-serif;margin:16px;color:#101828;background:#fff}"
            "h1{color:#b42318}</style></head><body><h1>Satark — stay safe</h1><p>" + text.splitlines()[0] + "</p><ol>" + items + "</ol>"
            f"<p style='color:#667085;font-size:12px'>Reference: {err}</p></body></html>"
        )
    if fmt == "json":
        return json.dumps({"error": err, "advice": text})
    return "# Satark — stay safe\n\n" + text + f"\n_Reference: {err}_"


def main() -> int:
    if os.environ.get("SATARK_MODE", "").lower() == "server":
        # Same image, hosted mode (Hugging Face Spaces / Render / Cloud Run): serve the API + demo UI.
        import uvicorn

        uvicorn.run("server:app", host="0.0.0.0", port=int(os.environ.get("PORT", "7860")))
        return 0
    ap = argparse.ArgumentParser(description="Satark aiKart runner")
    ap.add_argument("--input", help="path to input JSON (default /aikart/input.json or $AIKART_INPUT)")
    ap.add_argument("--output", help="path to output JSON (default /aikart/output.json)")
    ap.add_argument("--format", choices=["html", "markdown", "json", "text"], default=None)
    ap.add_argument("--offline", action="store_true", help="no network at all: no LLM, no RDAP, no remote relay")
    args = ap.parse_args()
    if args.offline:
        os.environ["SATARK_LLM_PROVIDER"] = "none"
        os.environ["SATARK_ENABLE_RDAP"] = "0"
        os.environ["SATARK_REMOTE_URL"] = ""

    fmt = (args.format or os.environ.get("SATARK_OUTPUT_FORMAT", "html")).lower()
    out_path = args.output or OUTPUT_PATH
    t0 = time.monotonic()
    response = None
    try:
        payload = read_input(args.input)
        log(f"input fields: {sorted(payload.keys())}")
        if not str(payload.get("situation") or payload.get("message") or payload.get("text") or "").strip():
            payload.setdefault("situation", "")
        response = try_remote(payload, fmt)
        if response is None:
            from satark.agent import analyze
            from satark.report_html import render_html
            from satark.report_md import render_markdown

            if not str(payload.get("situation") or payload.get("message") or payload.get("text") or "").strip():
                raise ValueError("Please paste the suspicious message or describe what happened.")
            result = analyze(payload)
            if fmt == "html":
                response = render_html(result)
            elif fmt == "json":
                result_copy = dict(result)
                response = json.dumps(result_copy, ensure_ascii=False, default=str)
            else:
                response = render_markdown(result)
            log(f"verdict={result['verdict']['tier']} score={result['verdict']['score']} mode={result['mode']} llm_calls={result['llm_calls']} in {time.monotonic() - t0:.1f}s")
    except ValueError as exc:
        response = fallback_report(fmt, str(exc))
    except Exception as exc:  # noqa: BLE001
        traceback.print_exc()
        response = fallback_report(fmt, f"{exc.__class__.__name__}")

    payload_out = {"format": fmt, "response": response}
    try:
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(payload_out, fh, ensure_ascii=False)
    except OSError as exc:
        log(f"could not write output: {exc}")
        return 1
    log(f"wrote {out_path} ({len(response)} chars)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
