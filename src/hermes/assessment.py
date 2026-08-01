"""Offline, conservative candidate detectors with explicit counterexamples."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from pydantic import BaseModel, Field

from .contracts import Candidate


class Observation(BaseModel):
    target: str
    status_code: int = Field(ge=100, le=599)
    content_type: str = ""
    body: str = ""
    headers: dict[str, str] = Field(default_factory=dict)


class AccessSample(BaseModel):
    identity: str
    object_owner: str
    object_id: str
    status_code: int = Field(ge=100, le=599)


def _candidate_id(prefix: str, target: str) -> str:
    return f"{prefix}-{hashlib.sha256(target.encode()).hexdigest()[:12]}"


@dataclass(frozen=True)
class SafeCandidateDetector:
    """Produces hypotheses only; it cannot upgrade a response into a finding."""

    def api_access(self, observation: Observation) -> Candidate:
        is_json = (
            "application/json" in observation.content_type.lower()
            or observation.body.lstrip().startswith(("{", "["))
        )
        if observation.status_code == 200 and is_json:
            rationale = (
                "An anonymous JSON 200 may be an intentionally public API; it does not "
                "prove missing authorization without private-data classification and an "
                "authorized control."
            )
        else:
            rationale = (
                "The API response is insufficient to infer an authentication or "
                "authorization defect."
            )
        return Candidate(
            id=_candidate_id("api-access", observation.target),
            title="API access requires authorization evidence review",
            target=observation.target,
            rationale=rationale,
            required_evidence=[
                "data classification",
                "authorized negative control",
                "review decision",
            ],
        )

    def sensitive_path(self, observation: Observation) -> Candidate:
        looks_like_spa = (
            "text/html" in observation.content_type.lower() or "<html" in observation.body.lower()
        )
        if looks_like_spa:
            rationale = (
                "A 200 HTML response can be an SPA fallback, not exposure of the requested "
                "sensitive path."
            )
        else:
            rationale = (
                "A path response is only a candidate until format-specific secret indicators and a "
                "negative fallback control are recorded."
            )
        return Candidate(
            id=_candidate_id("sensitive-path", observation.target),
            title="Sensitive-path response requires format and fallback controls",
            target=observation.target,
            rationale=rationale,
            required_evidence=["format signature", "fallback control", "redacted response hash"],
        )

    def idor(self, first: AccessSample, second: AccessSample) -> Candidate:
        distinct = first.identity != second.identity
        cross_owned = second.object_owner != second.identity
        if not distinct or not cross_owned:
            rationale = (
                "IDOR/BOLA validation requires two distinct authorized identities and an "
                "object owned by the other identity; the supplied samples do not establish "
                "that control."
            )
        else:
            rationale = (
                "Cross-owner access is a candidate until an approved verifier captures the "
                "authorized positive and negative controls with redacted evidence."
            )
        target = f"object:{first.object_id}->{second.object_id}"
        return Candidate(
            id=_candidate_id("idor", target),
            title="Authorization object-access comparison requires approved verification",
            target=target,
            rationale=rationale,
            required_evidence=[
                "identity ownership attestations",
                "positive control",
                "negative control",
            ],
        )
