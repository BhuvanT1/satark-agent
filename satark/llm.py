"""Provider-agnostic LLM client (stdlib only).

Supports Google Gemini (REST) and any OpenAI-compatible chat endpoint
(OpenAI, Groq, Together, local vLLM/Ollama, ...). Every call asks for JSON,
is time-boxed, retried once, and falls back across models. Any failure raises
LLMError so the agent can continue in deterministic mode.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request

from .config import Settings


class LLMError(Exception):
    pass


def parse_json_loose(text: str) -> dict:
    if not text:
        raise LLMError("empty response")
    t = text.strip()
    t = re.sub(r"^```(?:json)?\s*", "", t)
    t = re.sub(r"\s*```$", "", t)
    try:
        val = json.loads(t)
        if isinstance(val, dict):
            return val
    except json.JSONDecodeError:
        pass
    start = t.find("{")
    end = t.rfind("}")
    if start != -1 and end > start:
        try:
            val = json.loads(t[start : end + 1])
            if isinstance(val, dict):
                return val
        except json.JSONDecodeError as exc:
            raise LLMError(f"invalid JSON: {exc}") from exc
    raise LLMError("no JSON object in response")


def _post(url: str, body: dict, headers: dict, timeout: float) -> dict:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", **headers}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8", "replace")[:400]
        except Exception:  # noqa: BLE001
            pass
        raise LLMError(f"HTTP {exc.code}: {detail}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise LLMError(f"network: {exc}") from exc


class LLMClient:
    def __init__(self, settings: Settings):
        self.s = settings
        self.provider = settings.resolved_provider()
        self.model_used: str | None = None
        self.calls = 0
        self.tokens_in = 0
        self.tokens_out = 0
        self._bad_models: set[str] = set()
        self._no_thinking_cfg: set[str] = set()

    @property
    def available(self) -> bool:
        return self.provider in {"gemini", "openai", "mock"}

    def describe(self) -> str:
        if self.provider == "gemini":
            return f"Gemini ({self.model_used or self.s.gemini_models[0]})"
        if self.provider == "openai":
            return f"{self.s.openai_model} via {self.s.openai_base_url.split('//')[-1].split('/')[0]}"
        if self.provider == "mock":
            return "mock-llm (tests)"
        return "offline engine"

    # ------------------------------------------------------------------
    def chat_json(self, system: str, messages: list[dict], timeout: float | None = None, max_tokens: int = 4096) -> dict:
        timeout = max(5.0, timeout or self.s.llm_call_timeout_s)
        if getattr(self, "down", False):
            raise LLMError("LLM unreachable earlier in this run — skipping")
        self.calls += 1
        self._deadline = time.monotonic() + timeout
        try:
            if self.provider == "gemini":
                return self._gemini(system, messages, timeout, max_tokens)
            if self.provider == "openai":
                return self._openai(system, messages, timeout, max_tokens)
        except LLMError as exc:
            if "network:" in str(exc):
                self.down = True  # circuit breaker: no egress / DNS failure → stop trying this run
            raise
        if self.provider == "mock":
            from .mock_llm import mock_response

            return mock_response(system, messages)
        raise LLMError("no LLM configured")

    # ------------------------------------------------------------------
    def _gemini(self, system: str, messages: list[dict], timeout: float, max_tokens: int) -> dict:
        contents = [
            {"role": "model" if m["role"] == "assistant" else "user", "parts": [{"text": m["content"]}]}
            for m in messages
        ]
        last_err: Exception | None = None
        for model in [m for m in self.s.gemini_models if m not in self._bad_models]:
            gen_cfg = {"temperature": 0.2, "responseMimeType": "application/json", "maxOutputTokens": max_tokens}
            if model not in self._no_thinking_cfg:
                gen_cfg["thinkingConfig"] = {"thinkingLevel": "low"}
            body = {"systemInstruction": {"parts": [{"text": system}]}, "contents": contents, "generationConfig": gen_cfg}
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
            for attempt in range(3):
                left = self._deadline - time.monotonic()
                if left < 3:
                    raise LLMError(f"time budget exhausted ({last_err})")
                try:
                    resp = _post(url, body, {"x-goog-api-key": self.s.gemini_api_key}, min(timeout, left))
                    usage = resp.get("usageMetadata", {})
                    self.tokens_in += int(usage.get("promptTokenCount", 0) or 0)
                    self.tokens_out += int(usage.get("candidatesTokenCount", 0) or 0)
                    cands = resp.get("candidates") or []
                    if not cands:
                        raise LLMError(f"no candidates: {str(resp.get('promptFeedback'))[:200]}")
                    parts = (cands[0].get("content") or {}).get("parts") or []
                    text = "".join(p.get("text", "") for p in parts if not p.get("thought"))
                    self.model_used = model
                    return parse_json_loose(text)
                except LLMError as exc:
                    last_err = exc
                    msg = str(exc)
                    if msg.startswith("HTTP 400") and "thinking" in msg.lower() and "thinkingConfig" in gen_cfg:
                        self._no_thinking_cfg.add(model)
                        gen_cfg.pop("thinkingConfig", None)
                        continue
                    if msg.startswith("HTTP 404") or ("not found" in msg.lower() and msg.startswith("HTTP 400")):
                        self._bad_models.add(model)
                        break
                    if msg.startswith("network"):
                        raise LLMError(msg) from exc  # no egress → don't burn the budget on other models
                    if msg.startswith(("HTTP 429", "HTTP 500", "HTTP 502", "HTTP 503", "HTTP 504")) and attempt < 1:
                        time.sleep(1.5)
                        continue
                    if msg.startswith(("invalid JSON", "no JSON", "empty response")) and attempt < 1:
                        continue
                    break
        raise LLMError(f"Gemini failed: {last_err}")

    def _openai(self, system: str, messages: list[dict], timeout: float, max_tokens: int) -> dict:
        url = self.s.openai_base_url.rstrip("/") + "/chat/completions"
        body = {
            "model": self.s.openai_model,
            "messages": [{"role": "system", "content": system}] + messages,
            "temperature": 0.2,
            "max_tokens": max_tokens,
            "response_format": {"type": "json_object"},
        }
        last_err: Exception | None = None
        for attempt in range(3):
            left = self._deadline - time.monotonic()
            if left < 3:
                raise LLMError(f"time budget exhausted ({last_err})")
            try:
                resp = _post(url, body, {"Authorization": f"Bearer {self.s.openai_api_key}"}, min(timeout, left))
                usage = resp.get("usage", {})
                self.tokens_in += int(usage.get("prompt_tokens", 0) or 0)
                self.tokens_out += int(usage.get("completion_tokens", 0) or 0)
                text = resp["choices"][0]["message"]["content"]
                self.model_used = self.s.openai_model
                return parse_json_loose(text)
            except (LLMError, KeyError, IndexError, TypeError) as exc:
                last_err = exc
                msg = str(exc)
                if "response_format" in msg and "response_format" in body:
                    body.pop("response_format")
                    continue
                if msg.startswith("network"):
                    raise LLMError(msg) from exc
                if msg.startswith(("HTTP 429", "HTTP 500", "HTTP 502", "HTTP 503")) and attempt < 1:
                    time.sleep(1.5)
                    continue
                if attempt < 1 and msg.startswith(("invalid JSON", "no JSON")):
                    continue
                break
        raise LLMError(f"OpenAI-compatible call failed: {last_err}")
