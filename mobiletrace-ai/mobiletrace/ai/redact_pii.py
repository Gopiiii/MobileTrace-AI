"""PII minimization and redaction utilities for cloud-assisted forensic analysis."""

from __future__ import annotations

import re
from typing import Any

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE_RE = re.compile(r"(?<!\w)(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)|\d{2,4})[\s.-]?\d{3,4}[\s.-]?\d{4}(?!\w)")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_IMEI_RE = re.compile(r"\b\d{15}\b")
_TOKEN_RE = re.compile(r"\b(?:eyJ[A-Za-z0-9_-]{10,}|Bearer\s+[A-Za-z0-9._-]{12,}|[A-Fa-f0-9]{40,})\b")


def redact_text(text: str) -> tuple[str, dict[str, int]]:
    """Redact common PII and credential tokens from text, returning redacted string and counts."""
    counts = {"emails": 0, "phones": 0, "ips": 0, "ssns": 0, "imeis": 0, "tokens": 0}
    out = text

    out, n = _EMAIL_RE.subn("[REDACTED_EMAIL]", out)
    counts["emails"] += n
    out, n = _SSN_RE.subn("[REDACTED_SSN]", out)
    counts["ssns"] += n
    out, n = _TOKEN_RE.subn("[REDACTED_TOKEN]", out)
    counts["tokens"] += n
    out, n = _IPV4_RE.subn("[REDACTED_IP]", out)
    counts["ips"] += n
    out, n = _IMEI_RE.subn("[REDACTED_IMEI]", out)
    counts["imeis"] += n
    out, n = _PHONE_RE.subn("[REDACTED_PHONE]", out)
    counts["phones"] += n

    return out, counts


def redact_payload(value: Any, aggregate_counts: dict[str, int] | None = None) -> tuple[Any, dict[str, int]]:
    totals = aggregate_counts if aggregate_counts is not None else {
        "emails": 0,
        "phones": 0,
        "ips": 0,
        "ssns": 0,
        "imeis": 0,
        "tokens": 0,
    }
    if isinstance(value, str):
        redacted, counts = redact_text(value)
        for k, v in counts.items():
            totals[k] = totals.get(k, 0) + v
        return redacted, totals
    if isinstance(value, list):
        return [redact_payload(item, totals)[0] for item in value], totals
    if isinstance(value, dict):
        return {k: redact_payload(v, totals)[0] for k, v in value.items()}, totals
    return value, totals
