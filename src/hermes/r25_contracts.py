"""Isolated contracts for the R2.5 governed-learning workflow.

These records are intentionally separate from V2/V3 security assessment
contracts. They describe only the learning, publication, activation, and
continuation artifacts for passive parser wheels.
"""

from __future__ import annotations

from datetime import datetime
from typing import Final, Literal, Self
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .domain_contracts import canonical_digest

_DIGEST = r"^sha256:[0-9a-f]{64}$"
_ID = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_SEMVER = r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$"

RiskLevel = Literal["low", "medium", "high"]
LearningProfile = Literal["local-lab"]
LearningOutcome = Literal["resolved", "inconclusive", "failed", "quarantined"]
ConfidenceLevel = Literal["low", "medium", "high"]
R25ContractId = Literal["hermes.r25.research_facts/v1", "hermes.r25.capability_spec/v2"]
WheelLifecycleV2 = Literal[
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


def _aware(value: datetime, label: str) -> datetime:
    if value.tzinfo is None:
        raise ValueError(f"{label} must be timezone-aware")
    return value


def _https_url(value: str, label: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError(f"{label} must be an absolute HTTPS URL")
    return value


class R25Contract(BaseModel):
    """Frozen base model shared by all R2.5 artifacts."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    @property
    def digest(self) -> str:
        return canonical_digest(self)


class LineFieldRuleV1(R25Contract):
    version: Literal["1"] = "1"
    field_name: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    source_key: str = Field(pattern=r"^[A-Za-z0-9._/-]{1,64}$")
    required: bool = True
    normalizer: Literal["strip", "lower", "upper", "none"] = "strip"


class LearningRequestV1(R25Contract):
    version: Literal["1"] = "1"
    learning_run_id: str = Field(pattern=_ID)
    parent_run_id: str = Field(pattern=_ID)
    scope_digest: str = Field(pattern=_DIGEST)
    parent_run_plan_digest: str = Field(pattern=_DIGEST)
    evidence_manifest_digest: str = Field(pattern=_DIGEST)
    analysis_digest: str = Field(pattern=_DIGEST)
    generated_by_task_id: str = Field(pattern=_ID)
    operator_observation: str = Field(min_length=1, max_length=4_000)
    risk_level: RiskLevel = "low"
    profile: LearningProfile = "local-lab"
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def aware_created_at(cls, value: datetime) -> datetime:
        return _aware(value, "learning request created_at")


class ResearchSourceArtifactV1(R25Contract):
    version: Literal["1"] = "1"
    source_id: str = Field(pattern=_ID)
    learning_run_id: str = Field(pattern=_ID)
    source_url: str = Field(min_length=8, max_length=2_048)
    license: str = Field(min_length=1, max_length=200)
    source_version: str | None = Field(default=None, max_length=200)
    content_digest: str = Field(pattern=_DIGEST)
    projection_digest: str = Field(pattern=_DIGEST)
    source_bundle_digest: str = Field(pattern=_DIGEST)
    retrieved_at: datetime
    risk_flags: tuple[str, ...] = ()

    @field_validator("source_url")
    @classmethod
    def https_url(cls, value: str) -> str:
        return _https_url(value, "research source URL")

    @field_validator("retrieved_at")
    @classmethod
    def aware_retrieved_at(cls, value: datetime) -> datetime:
        return _aware(value, "research source retrieved_at")

    @field_validator("risk_flags")
    @classmethod
    def unique_risk_flags(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("research source risk flags must be unique")
        return value


class ResearchFactV1(R25Contract):
    version: Literal["1"] = "1"
    fact_id: str = Field(pattern=_ID)
    learning_run_id: str = Field(pattern=_ID)
    source_id: str = Field(pattern=_ID)
    statement: str = Field(min_length=1, max_length=4_000)
    citation_ranges: tuple[str, ...] = Field(min_length=1)
    confidence: ConfidenceLevel
    created_at: datetime

    @field_validator("citation_ranges")
    @classmethod
    def unique_citations(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("research fact citation ranges must be unique")
        return value

    @field_validator("created_at")
    @classmethod
    def aware_created_at(cls, value: datetime) -> datetime:
        return _aware(value, "research fact created_at")


class ResearchFactsOutputV1(R25Contract):
    version: Literal["1"] = "1"
    learning_run_id: str = Field(pattern=_ID)
    generated_by_task_id: str = Field(pattern=_ID)
    source_digests: tuple[str, ...] = Field(min_length=1)
    facts: tuple[ResearchFactV1, ...] = Field(min_length=1)

    @field_validator("source_digests")
    @classmethod
    def unique_source_digests(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("research output source digests must be unique")
        return value

    @model_validator(mode="after")
    def consistent_learning_run(self) -> Self:
        if any(item.learning_run_id != self.learning_run_id for item in self.facts):
            raise ValueError("research facts output must bind one learning run")
        return self


class CapabilitySpecV2(R25Contract):
    version: Literal["2"] = "2"
    capability_id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,63}$")
    wheel_kind: Literal["passive_parser"] = "passive_parser"
    template_id: Literal["line_kv_parser/v1"] = "line_kv_parser/v1"
    input_schema_id: str = Field(min_length=1, max_length=200)
    output_schema_id: str = Field(min_length=1, max_length=200)
    field_rules: tuple[LineFieldRuleV1, ...] = Field(min_length=1)
    delimiter: Literal[":", "="] = ":"
    required_output_fields: tuple[str, ...] = Field(min_length=1)
    counterexamples: tuple[str, ...] = Field(min_length=1)
    revocation_conditions: tuple[str, ...] = Field(min_length=1)
    source_digests: tuple[str, ...] = Field(min_length=1)
    max_requests: Literal[0] = 0
    network_policy: Literal["deny"] = "deny"
    host_filesystem_policy: Literal["no-write"] = "no-write"
    command_execution: Literal["forbidden"] = "forbidden"

    @field_validator("required_output_fields")
    @classmethod
    def unique_output_fields(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("required output fields must be unique")
        return value

    @field_validator("source_digests")
    @classmethod
    def unique_source_digests(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("source digests must be unique")
        return value

    @model_validator(mode="after")
    def rules_match_required_fields(self) -> Self:
        rule_fields = tuple(rule.field_name for rule in self.field_rules)
        if len(rule_fields) != len(set(rule_fields)):
            raise ValueError("field rules must target unique output fields")
        if tuple(sorted(rule_fields)) != tuple(sorted(self.required_output_fields)):
            raise ValueError("field rules must exactly match required output fields")
        return self


class WheelManifestV2(R25Contract):
    version: Literal["2"] = "2"
    wheel_id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,63}$")
    manifest_version: str = Field(pattern=_SEMVER)
    capability_spec_digest: str = Field(pattern=_DIGEST)
    wheel_kind: Literal["passive_parser"] = "passive_parser"
    template_id: Literal["line_kv_parser/v1"] = "line_kv_parser/v1"
    profile: LearningProfile = "local-lab"
    lifecycle: WheelLifecycleV2 = "draft"
    entrypoint: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_.]*:[A-Za-z_][A-Za-z0-9_]*$")
    artifact_digest: str = Field(pattern=_DIGEST)
    sbom_digest: str = Field(pattern=_DIGEST)
    readme_digest: str = Field(pattern=_DIGEST)
    lock_digest: str = Field(pattern=_DIGEST)
    generated_at: datetime

    @field_validator("generated_at")
    @classmethod
    def aware_generated_at(cls, value: datetime) -> datetime:
        return _aware(value, "wheel manifest generated_at")


class ValidationReceiptV2(R25Contract):
    version: Literal["2"] = "2"
    receipt_id: str = Field(pattern=_ID)
    learning_run_id: str = Field(pattern=_ID)
    wheel_manifest_digest: str = Field(pattern=_DIGEST)
    validator_key_id: str = Field(pattern=_ID)
    static_checks: tuple[str, ...] = Field(min_length=1)
    docker_checks: tuple[str, ...] = Field(min_length=1)
    sandbox_image: str = Field(min_length=1, max_length=512)
    sandbox_image_digest: str = Field(pattern=_DIGEST)
    fixture_positive_digest: str = Field(pattern=_DIGEST)
    fixture_negative_digest: str = Field(pattern=_DIGEST)
    validated_at: datetime
    signature_b64: str = Field(min_length=16, max_length=4_096)

    @field_validator("validated_at")
    @classmethod
    def aware_validated_at(cls, value: datetime) -> datetime:
        return _aware(value, "validation receipt validated_at")


class WheelApprovalV2(R25Contract):
    version: Literal["2"] = "2"
    approval_id: str = Field(pattern=_ID)
    learning_run_id: str = Field(pattern=_ID)
    wheel_manifest_digest: str = Field(pattern=_DIGEST)
    validation_receipt_digest: str = Field(pattern=_DIGEST)
    approver_key_id: str = Field(pattern=_ID)
    verdict: Literal["approved"] = "approved"
    approved_at: datetime
    expires_at: datetime
    signature_b64: str = Field(min_length=16, max_length=4_096)

    @field_validator("approved_at", "expires_at")
    @classmethod
    def aware_instants(cls, value: datetime) -> datetime:
        return _aware(value, "wheel approval instant")

    @model_validator(mode="after")
    def expiry_follows_approval(self) -> Self:
        if self.expires_at <= self.approved_at:
            raise ValueError("wheel approval expires_at must follow approved_at")
        return self


class WheelActivationReceiptV2(R25Contract):
    version: Literal["2"] = "2"
    activation_id: str = Field(pattern=_ID)
    learning_run_id: str = Field(pattern=_ID)
    wheel_manifest_digest: str = Field(pattern=_DIGEST)
    wheel_approval_digest: str = Field(pattern=_DIGEST)
    operator_key_id: str = Field(pattern=_ID)
    activated_at: datetime
    profile: LearningProfile = "local-lab"
    signature_b64: str = Field(min_length=16, max_length=4_096)

    @field_validator("activated_at")
    @classmethod
    def aware_activated_at(cls, value: datetime) -> datetime:
        return _aware(value, "wheel activation activated_at")


class CapabilityExecutionReceiptV2(R25Contract):
    version: Literal["2"] = "2"
    execution_id: str = Field(pattern=_ID)
    continuation_run_id: str = Field(pattern=_ID)
    learning_run_id: str = Field(pattern=_ID)
    wheel_manifest_digest: str = Field(pattern=_DIGEST)
    wheel_activation_digest: str = Field(pattern=_DIGEST)
    input_digest: str = Field(pattern=_DIGEST)
    output_digest: str = Field(pattern=_DIGEST)
    outcome: LearningOutcome
    executed_at: datetime

    @field_validator("executed_at")
    @classmethod
    def aware_executed_at(cls, value: datetime) -> datetime:
        return _aware(value, "capability execution executed_at")


class ContinuationOutcomeV1(R25Contract):
    version: Literal["1"] = "1"
    continuation_run_id: str = Field(pattern=_ID)
    learning_run_id: str = Field(pattern=_ID)
    parent_run_id: str = Field(pattern=_ID)
    scope_digest: str = Field(pattern=_DIGEST)
    wheel_manifest_digest: str = Field(pattern=_DIGEST)
    wheel_activation_digest: str = Field(pattern=_DIGEST)
    execution_receipt_digest: str = Field(pattern=_DIGEST)
    structured_observation_digest: str = Field(pattern=_DIGEST)
    outcome: LearningOutcome
    generated_at: datetime

    @field_validator("generated_at")
    @classmethod
    def aware_generated_at(cls, value: datetime) -> datetime:
        return _aware(value, "continuation outcome generated_at")


RESEARCH_FACTS_CONTRACT_ID: Final[R25ContractId] = "hermes.r25.research_facts/v1"
CAPABILITY_SPEC_CONTRACT_ID: Final[R25ContractId] = "hermes.r25.capability_spec/v2"


class ContractEnvelopeR25(R25Contract):
    """Typed handoff envelope for Researcher and Capability Planner outputs."""

    contract_id: R25ContractId
    contract_version: Literal["1", "2"]
    payload: ResearchFactsOutputV1 | CapabilitySpecV2
    payload_sha256: str = Field(pattern=_DIGEST)

    @model_validator(mode="after")
    def coherent_payload(self) -> Self:
        expected = {
            RESEARCH_FACTS_CONTRACT_ID: (ResearchFactsOutputV1, "1"),
            CAPABILITY_SPEC_CONTRACT_ID: (CapabilitySpecV2, "2"),
        }[self.contract_id]
        payload_type, version = expected
        if not isinstance(self.payload, payload_type):
            raise ValueError("contract envelope payload type does not match contract_id")
        if self.contract_version != version:
            raise ValueError("contract envelope version does not match contract_id")
        if self.payload_sha256 != self.payload.digest:
            raise ValueError("contract envelope payload digest does not match payload")
        return self

    @classmethod
    def for_payload(cls, payload: ResearchFactsOutputV1 | CapabilitySpecV2) -> ContractEnvelopeR25:
        if isinstance(payload, ResearchFactsOutputV1):
            return cls(
                contract_id=RESEARCH_FACTS_CONTRACT_ID,
                contract_version="1",
                payload=payload,
                payload_sha256=payload.digest,
            )
        return cls(
            contract_id=CAPABILITY_SPEC_CONTRACT_ID,
            contract_version="2",
            payload=payload,
            payload_sha256=payload.digest,
        )
