"""Closed contracts for the R2.5 governed learning loop."""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .domain_contracts import canonical_digest
from .evidence import EvidenceArtifactRef

_DIGEST = r"^sha256:[0-9a-f]{64}$"
_ID = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"


class LearningContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    @property
    def digest(self) -> str:
        return canonical_digest(self)


class RunBoundLearningContract(LearningContract):
    run_id: str = Field(pattern=_ID)
    scope_digest: str = Field(pattern=_DIGEST)
    generated_by_task_id: str = Field(pattern=_ID)


class LearningRequestV1(LearningContract):
    version: Literal["1"] = "1"
    run_id: str = Field(pattern=_ID)
    parent_run_id: str = Field(pattern=_ID)
    scope_digest: str = Field(pattern=_DIGEST)
    parent_run_plan_digest: str = Field(pattern=_DIGEST)
    parent_evidence_manifest_digest: str = Field(pattern=_DIGEST)
    parent_analysis_digest: str = Field(pattern=_DIGEST)
    evidence_ref: EvidenceArtifactRef
    observation: str = Field(min_length=1, max_length=4_000)
    risk_level: Literal["low", "medium", "high"]
    local_profile: str = Field(min_length=1, max_length=128)
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def aware_created_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("learning request time must be timezone-aware")
        return value


class ResearchSourceArtifactV1(RunBoundLearningContract):
    version: Literal["1"] = "1"
    source_id: str = Field(pattern=_ID)
    url: str = Field(min_length=8, max_length=2_048)
    license: str = Field(min_length=1, max_length=200)
    source_version: str | None = Field(default=None, max_length=200)
    content_sha256: str = Field(pattern=_DIGEST)
    projection_sha256: str = Field(pattern=_DIGEST)
    archived_path: str = Field(min_length=1, max_length=512)
    projection_path: str = Field(min_length=1, max_length=512)
    risk_flags: tuple[str, ...] = ()
    citations: tuple[str, ...] = ()
    captured_at: datetime

    @field_validator("captured_at")
    @classmethod
    def aware_captured_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("research source capture time must be timezone-aware")
        return value


class ResearchFactV1(RunBoundLearningContract):
    version: Literal["1"] = "1"
    fact_id: str = Field(pattern=_ID)
    claim: str = Field(min_length=1, max_length=2_000)
    rationale: str = Field(min_length=1, max_length=2_000)
    confidence: Literal["low", "medium", "high"]
    source_digests: tuple[str, ...] = Field(min_length=1)
    citations: tuple[str, ...] = ()

    @field_validator("source_digests")
    @classmethod
    def valid_source_digests(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)) or any(not item.startswith("sha256:") for item in value):
            raise ValueError("research fact source digests must be unique SHA-256 digests")
        return value


class CapabilitySpecV2(RunBoundLearningContract):
    version: Literal["2"] = "2"
    wheel_id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,63}$")
    template_id: Literal["line_kv_parser/v1"] = "line_kv_parser/v1"
    input_schema_id: Literal["learning.analysis_text/v1"] = "learning.analysis_text/v1"
    output_schema_id: Literal["learning.line_kv_observation/v1"] = "learning.line_kv_observation/v1"
    fixed_fields: tuple[str, ...] = Field(min_length=1)
    known_counterexamples: tuple[str, ...] = Field(min_length=1)
    revocation_conditions: tuple[str, ...] = Field(min_length=1)
    source_digests: tuple[str, ...] = Field(min_length=1)
    max_requests: int = Field(default=0, ge=0, le=0)
    network_policy: Literal["deny"] = "deny"
    command_policy: Literal["deny"] = "deny"
    filesystem_policy: Literal["read_only"] = "read_only"

    @field_validator(
        "fixed_fields", "known_counterexamples", "revocation_conditions", "source_digests"
    )
    @classmethod
    def unique_values(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("capability spec tuple values must be unique")
        return value


class WheelManifestV2(RunBoundLearningContract):
    version: Literal["2"] = "2"
    wheel_id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,63}$")
    wheel_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    capability_spec_digest: str = Field(pattern=_DIGEST)
    artifact_root_sha256: str = Field(pattern=_DIGEST)
    distribution_sha256: str = Field(pattern=_DIGEST)
    entrypoint: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_.]*:[A-Za-z_][A-Za-z0-9_]*$")
    sandbox_image: str = Field(min_length=1, max_length=512)
    profile: str = Field(min_length=1, max_length=128)
    status: Literal[
        "draft",
        "researched",
        "specified",
        "generated",
        "validated",
        "candidate",
        "approved",
        "active",
        "quarantined",
        "revoked",
    ]


class ValidationReceiptV2(LearningContract):
    version: Literal["2"] = "2"
    run_id: str = Field(pattern=_ID)
    scope_digest: str = Field(pattern=_DIGEST)
    wheel_manifest_digest: str = Field(pattern=_DIGEST)
    validator_key_id: str = Field(pattern=_ID)
    static_passed: bool
    sandbox_tests_passed: bool
    positive_execution_passed: bool
    negative_execution_passed: bool
    violations: tuple[str, ...] = ()
    positive_output_sha256: str | None = Field(default=None, pattern=_DIGEST)
    negative_output_sha256: str | None = Field(default=None, pattern=_DIGEST)
    validated_at: datetime

    @field_validator("validated_at")
    @classmethod
    def aware_validated_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("validation time must be timezone-aware")
        return value


class WheelApprovalV2(LearningContract):
    version: Literal["2"] = "2"
    run_id: str = Field(pattern=_ID)
    scope_digest: str = Field(pattern=_DIGEST)
    wheel_manifest_digest: str = Field(pattern=_DIGEST)
    validation_receipt_digest: str = Field(pattern=_DIGEST)
    verdict: Literal["approved", "rejected"]
    approver_key_id: str = Field(pattern=_ID)
    rationale: str = Field(min_length=1, max_length=2_000)
    signed_at: datetime
    signature: str = Field(min_length=16, max_length=1024)

    @field_validator("signed_at")
    @classmethod
    def aware_signed_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("approval time must be timezone-aware")
        return value


class WheelActivationReceiptV2(LearningContract):
    version: Literal["2"] = "2"
    run_id: str = Field(pattern=_ID)
    scope_digest: str = Field(pattern=_DIGEST)
    wheel_manifest_digest: str = Field(pattern=_DIGEST)
    approval_digest: str = Field(pattern=_DIGEST)
    operator_key_id: str = Field(pattern=_ID)
    activated_at: datetime
    signature: str = Field(min_length=16, max_length=1024)

    @field_validator("activated_at")
    @classmethod
    def aware_activated_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("activation time must be timezone-aware")
        return value


class CapabilityExecutionReceiptV2(LearningContract):
    version: Literal["2"] = "2"
    continuation_run_id: str = Field(pattern=_ID)
    parent_learning_run_id: str = Field(pattern=_ID)
    scope_digest: str = Field(pattern=_DIGEST)
    wheel_manifest_digest: str = Field(pattern=_DIGEST)
    activation_digest: str = Field(pattern=_DIGEST)
    input_sha256: str = Field(pattern=_DIGEST)
    output_sha256: str = Field(pattern=_DIGEST)
    outcome: Literal["resolved", "inconclusive", "failed", "quarantined"]
    executed_at: datetime

    @field_validator("executed_at")
    @classmethod
    def aware_executed_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("execution time must be timezone-aware")
        return value


class ParsedLineObservation(LearningContract):
    line_number: int = Field(ge=1)
    key: str = Field(min_length=1, max_length=128)
    value: str = Field(min_length=1, max_length=512)


class ContinuationOutcomeV1(LearningContract):
    version: Literal["1"] = "1"
    continuation_run_id: str = Field(pattern=_ID)
    parent_learning_run_id: str = Field(pattern=_ID)
    parent_run_id: str = Field(pattern=_ID)
    scope_digest: str = Field(pattern=_DIGEST)
    wheel_manifest_digest: str = Field(pattern=_DIGEST)
    execution_receipt_digest: str = Field(pattern=_DIGEST)
    status: Literal["resolved", "inconclusive", "failed", "quarantined"]
    observations: tuple[ParsedLineObservation, ...] = ()
    summary: str = Field(min_length=1, max_length=2_000)
    produced_at: datetime

    @field_validator("produced_at")
    @classmethod
    def aware_produced_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("continuation outcome time must be timezone-aware")
        return value

    @model_validator(mode="after")
    def coherent_status(self) -> Self:
        if self.status == "resolved" and not self.observations:
            raise ValueError("resolved continuation outcomes require observations")
        if self.status != "resolved" and self.observations:
            raise ValueError("only resolved continuation outcomes may carry observations")
        return self


class ResearchFactsEnvelopeV1(RunBoundLearningContract):
    version: Literal["1"] = "1"
    facts: tuple[ResearchFactV1, ...] = Field(min_length=1)

    @field_validator("facts")
    @classmethod
    def unique_fact_ids(cls, value: tuple[ResearchFactV1, ...]) -> tuple[ResearchFactV1, ...]:
        ids = tuple(item.fact_id for item in value)
        if len(ids) != len(set(ids)):
            raise ValueError("research fact IDs must be unique")
        return value


class LearningStatusV1(LearningContract):
    version: Literal["1"] = "1"
    run_id: str = Field(pattern=_ID)
    parent_run_id: str = Field(pattern=_ID)
    scope_digest: str = Field(pattern=_DIGEST)
    state: Literal[
        "draft",
        "started",
        "researched",
        "planned",
        "generated",
        "validated",
        "candidate",
        "approved",
        "active",
        "continued",
        "quarantined",
        "revoked",
    ]
    wheel_manifest_digest: str | None = Field(default=None, pattern=_DIGEST)
    latest_continuation_digest: str | None = Field(default=None, pattern=_DIGEST)
    updated_at: datetime

    @field_validator("updated_at")
    @classmethod
    def aware_updated_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("learning status time must be timezone-aware")
        return value
