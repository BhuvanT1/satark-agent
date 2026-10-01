"""Runtime configuration, read from environment variables.

Nothing here is required: with no keys set, Satark runs fully offline using its
deterministic forensic engine. Setting an LLM key upgrades the reasoning,
multilingual explanations and drafting.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import timedelta, timezone

IST = timezone(timedelta(hours=5, minutes=30), name="IST")


def _env(name: str, default: str = "") -> str:
    value = os.environ.get(name, default)
    return value.strip() if isinstance(value, str) else default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


@dataclass
class Settings:
    # "auto" picks gemini if a Gemini key is present, else an OpenAI-compatible
    # provider if its key is present, else runs offline.
    llm_provider: str = field(default_factory=lambda: _env("SATARK_LLM_PROVIDER", "auto").lower())

    gemini_api_key: str = field(default_factory=lambda: _env("GEMINI_API_KEY") or _env("GOOGLE_API_KEY"))
    gemini_models: list[str] = field(
        default_factory=lambda: [
            m
            for m in [_env("GEMINI_MODEL"), "gemini-flash-latest", "gemini-3.5-flash", "gemini-2.5-flash"]
            if m
        ]
    )

    openai_api_key: str = field(
        default_factory=lambda: _env("LLM_API_KEY") or _env("OPENAI_API_KEY") or _env("GROQ_API_KEY")
    )
    openai_base_url: str = field(
        default_factory=lambda: _env("LLM_BASE_URL")
        or ("https://api.groq.com/openai/v1" if _env("GROQ_API_KEY") and not _env("LLM_API_KEY") else "https://api.openai.com/v1")
    )
    openai_model: str = field(
        default_factory=lambda: _env("LLM_MODEL")
        or ("llama-3.3-70b-versatile" if _env("GROQ_API_KEY") and not _env("LLM_API_KEY") else "gpt-4o-mini")
    )

    # Optional relay: a hosted Satark API that holds the LLM key server-side.
    remote_url: str = field(default_factory=lambda: _env("SATARK_REMOTE_URL").rstrip("/"))
    remote_token: str = field(default_factory=lambda: _env("SATARK_REMOTE_TOKEN"))
    remote_timeout: float = field(default_factory=lambda: _env_float("SATARK_REMOTE_TIMEOUT", 90))

    # Network tools (domain-age lookup via RDAP). Fails gracefully when offline.
    enable_rdap: bool = field(default_factory=lambda: _env_bool("SATARK_ENABLE_RDAP", True))
    rdap_timeout: float = field(default_factory=lambda: _env_float("SATARK_RDAP_TIMEOUT", 3.5))

    # Total wall-clock budget for one run (aiKart allows up to 280 s).
    time_budget_s: float = field(default_factory=lambda: _env_float("SATARK_TIME_BUDGET", 170))
    llm_call_timeout_s: float = field(default_factory=lambda: _env_float("SATARK_LLM_TIMEOUT", 55))
    max_react_steps: int = field(default_factory=lambda: int(_env_float("SATARK_MAX_STEPS", 3)))

    output_format: str = field(default_factory=lambda: _env("SATARK_OUTPUT_FORMAT", "html").lower())
    # Adversarial robustness layer (disable only for ablation experiments)
    deobfuscate: bool = field(default_factory=lambda: _env_bool("SATARK_DEOBFUSCATE", True))

    def resolved_provider(self) -> str:
        p = self.llm_provider
        if p in {"none", "offline", "off"}:
            return "none"
        if p == "mock":
            return "mock"
        if p == "gemini":
            return "gemini" if self.gemini_api_key else "none"
        if p in {"openai", "openai_compat", "groq"}:
            return "openai" if self.openai_api_key else "none"
        # auto
        if self.gemini_api_key:
            return "gemini"
        if self.openai_api_key:
            return "openai"
        return "none"


def get_settings() -> Settings:
    return Settings()
