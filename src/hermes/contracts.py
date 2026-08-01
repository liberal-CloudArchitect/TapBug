"""Versioned, evidence-first domain contracts for the Hermes core."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field, field_validator


class FindingStatus(StrEnum):
    CANDIDATE = "candidate"
    BLOCKED = "blocked"
    APPROVED = "approved"
    VALIDATED = "validated"
    INCONCLUSIVE = "inconclusive"


class Candidate(BaseModel):
    """A hypothesis. It is never a reportable security finding by itself."""

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,119}$")
    title: str = Field(min_length=1, max_length=240)
    target: str
    status: FindingStatus = FindingStatus.CANDIDATE
    rationale: str = Field(min_length=1, max_length=4_000)
    required_evidence: list[str] = Field(default_factory=list)
    proposed_action_id: str | None = None

    @field_validator("status")
    @classmethod
    def candidate_status_only(cls, status: FindingStatus) -> FindingStatus:
        if status is not FindingStatus.CANDIDATE:
            raise ValueError("Candidate records must retain candidate status")
        return status


class FindingEvidence(BaseModel):
    """A redacted, hash-bound request/response record retained by one run."""

    request_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    response_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    path: str = Field(pattern=r"^evidence/[A-Za-z0-9._/-]+$")
    captured_at: datetime
    redacted: bool = True


class HumanReview(BaseModel):
    reviewer: str = Field(min_length=1, max_length=200)
    reviewed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    verdict: str = Field(default="accepted", pattern=r"^(accepted|rejected)$")
    rationale: str = Field(default="", max_length=2_000)


class ValidatedFinding(BaseModel):
    """Reportable finding, backed by policy-bound evidence and human review."""

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,119}$")
    title: str = Field(min_length=1, max_length=240)
    target: str
    status: FindingStatus = FindingStatus.VALIDATED
    run_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    scope_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    approval_id: str = Field(min_length=1)
    evidence: list[FindingEvidence] = Field(min_length=1)
    review: HumanReview
    summary: str = ""
    prerequisites: list[str] = Field(default_factory=list)
    reproduction_steps: list[str] = Field(default_factory=list)
    impact: str = ""
    remediation: str = ""
    severity: str = Field(
        default="informational", pattern=r"^(informational|low|medium|high|critical)$"
    )
    coverage: str = ""
    local_teaching_fixture: bool = False
    vrt_snapshot: str | None = None
    cvss_vector: str | None = None

    @field_validator("status")
    @classmethod
    def finding_status_only(cls, status: FindingStatus) -> FindingStatus:
        if status is not FindingStatus.VALIDATED:
            raise ValueError("Only validated findings may use this contract")
        return status
