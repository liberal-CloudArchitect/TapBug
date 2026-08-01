"""Deterministic evidence redaction before persistent hashes or handoffs."""

from __future__ import annotations

import hashlib
import re

from pydantic import BaseModel, Field

_SECRET_PATTERNS = (
    re.compile(r"(?im)^(authorization\s*:\s*bearer\s+)[^\s]+"),
    re.compile(r"(?im)\b(password|token|api[_-]?key)\s*=\s*[^&\s]+"),
    re.compile(r"(?im)^(cookie\s*:\s*)[^\r\n]+"),
)


class RedactedEvidence(BaseModel):
    text: str
    sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    redacted: bool = True


def redact_evidence(value: str) -> RedactedEvidence:
    text = value
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(lambda match: f"{match.group(1)}[REDACTED]", text)
    return RedactedEvidence(text=text, sha256="sha256:" + hashlib.sha256(text.encode()).hexdigest())
