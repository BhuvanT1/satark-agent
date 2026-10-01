"""PII pseudonymisation.

Before any text is sent to an LLM, personal identifiers are replaced with
stable placeholders ([PHONE_1], [UPI_1], ...). Tools run locally on the real
values; the LLM only ever sees placeholders. Outputs are re-hydrated locally.
URLs keep their host (needed for reasoning, not personal) but lose path/query.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .extract import Entities


@dataclass
class Redactor:
    mapping: dict[str, str] = field(default_factory=dict)  # placeholder -> real value
    reverse: dict[str, str] = field(default_factory=dict)  # real value -> placeholder
    counts: dict[str, int] = field(default_factory=dict)

    def _ph(self, kind: str, value: str) -> str:
        if value in self.reverse:
            return self.reverse[value]
        self.counts[kind] = self.counts.get(kind, 0) + 1
        ph = f"[{kind}_{self.counts[kind]}]"
        self.mapping[ph] = value
        self.reverse[value] = ph
        return ph

    def register(self, ent: Entities) -> None:
        for p in ent.phones:
            self._ph("PHONE", p["raw"])
        for v in ent.upi_ids:
            self._ph("UPI", v)
        for e in ent.emails:
            self._ph("EMAIL", e)
        for a in ent.accounts:
            self._ph("ACCOUNT", a)
        for c in ent.cards:
            self._ph("CARD", c)
        for a in ent.aadhaar:
            self._ph("AADHAAR", a)
        for p in ent.pan:
            self._ph("PAN", p)
        for t in ent.txn_ids:
            self._ph("TXN", t)
        for u in ent.urls:
            try:
                parts = urlsplit(u if "://" in u else "http://" + u)
                if parts.path not in ("", "/") or parts.query:
                    safe = f"{parts.scheme + '://' if '://' in u else ''}{parts.netloc}/[path]"
                    self.mapping[f"<<URL:{safe}>>"] = u
                    self.reverse[u] = safe
            except ValueError:
                continue

    def redact(self, text: str) -> str:
        if not text:
            return text
        out = text
        # Longest values first so substrings don't clobber longer matches
        for real in sorted(self.reverse, key=len, reverse=True):
            out = out.replace(real, self.reverse[real])
        # Belt and braces: mask any remaining long digit runs and Aadhaar-like groups
        out = re.sub(r"(?<!\d)[2-9]\d{3}[\s\-]\d{4}[\s\-]\d{4}(?!\d)", "[AADHAAR]", out)
        out = re.sub(r"(?<![\d\[_])\d{11,19}(?!\d)", "[NUMBER]", out)
        return out

    def rehydrate(self, text: str) -> str:
        if not text:
            return text
        out = text
        for ph, real in self.mapping.items():
            if ph.startswith("<<URL:"):
                continue
            out = out.replace(ph, real)
        return out

    def resolve(self, value: str) -> str:
        """Map a placeholder used by the LLM back to the real value (tools run locally)."""
        if not isinstance(value, str):
            return value
        v = value.strip()
        if v in self.mapping:
            return self.mapping[v]
        for real, safe in self.reverse.items():
            if v == safe:
                return real
        return v

    def stats(self) -> dict[str, int]:
        return dict(self.counts)
