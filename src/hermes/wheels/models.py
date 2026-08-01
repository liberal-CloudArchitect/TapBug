"""Data models for reviewable, low-risk Hermes capability wheels."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class WheelKind(StrEnum):
    PASSIVE_PARSER = "passive_parser"
    NORMALIZER = "normalizer"
    ENDPOINT_EXTRACTOR = "endpoint_extractor"
    EVIDENCE_REDACTOR = "evidence_redactor"
    REPORT_CLASSIFIER = "report_classifier"
    PASSIVE_DETECTOR = "passive_detector"
    LOCAL_FIXTURE_VALIDATOR = "local_fixture_validator"


class WheelStatus(StrEnum):
    DRAFT = "draft"
    RESEARCHED = "researched"
    SPECIFIED = "specified"
    GENERATED = "generated"
    VALIDATED = "validated"
    CANDIDATE = "candidate"
    APPROVED = "approved"
    ACTIVE = "active"
    QUARANTINED = "quarantined"
    REVOKED = "revoked"


class ProblemCardStatus(StrEnum):
    """Lifecycle for an unknown observation before it can become a capability."""

    DRAFT = "draft"
    RESEARCHED = "researched"
    SPECIFIED = "specified"
    GENERATED = "generated"
    VALIDATED = "validated"
    CANDIDATE = "candidate"
    APPROVED = "approved"
    ACTIVE = "active"
    QUARANTINED = "quarantined"
    REVOKED = "revoked"
    REQUIRES_HUMAN_SPEC = "requires_human_spec"


ALLOWED_WHEEL_KINDS = frozenset(WheelKind)
FORBIDDEN_CAPABILITIES = frozenset(
    {
        "exploit",
        "credential_attack",
        "exfiltration",
        "persistence",
        "active_validator",
        "network",
        "command_execution",
        "filesystem_write",
    }
)


class SourceRecord(BaseModel):
    """Provenance for a fact used to create a wheel, not untrusted page content."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    url: str = Field(min_length=8, max_length=2048)
    retrieved_at: datetime
    content_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    license: str = Field(min_length=1, max_length=200)
    version: str | None = Field(default=None, max_length=200)
    applicability: str = Field(min_length=1, max_length=1000)
    risk_flags: tuple[str, ...] = ()


class CapabilitySpec(BaseModel):
    """The reviewable capability contract that must exist before code generation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,63}$")
    kind: WheelKind
    input_schema: str = Field(min_length=1, max_length=512)
    output_schema: str = Field(min_length=1, max_length=512)
    capabilities: tuple[str, ...] = Field(min_length=1)
    profiles: tuple[str, ...] = Field(min_length=1)
    max_requests: int = Field(default=0, ge=0, le=1)
    side_effects: Literal["none"] = "none"
    evidence_assertions: tuple[str, ...] = Field(min_length=1)
    known_counterexamples: tuple[str, ...] = Field(min_length=1)
    failure_mode: str = Field(min_length=1, max_length=1000)
    revocation_conditions: tuple[str, ...] = Field(min_length=1)
    sources: tuple[SourceRecord, ...] = Field(min_length=1)

    @field_validator("capabilities")
    @classmethod
    def _no_forbidden_capabilities(cls, capabilities: tuple[str, ...]) -> tuple[str, ...]:
        forbidden = FORBIDDEN_CAPABILITIES.intersection(capabilities)
        if forbidden:
            raise ValueError(f"forbidden wheel capabilities: {', '.join(sorted(forbidden))}")
        return capabilities

    @field_validator("profiles")
    @classmethod
    def _fixture_validator_is_local_only(
        cls, profiles: tuple[str, ...], info: object
    ) -> tuple[str, ...]:
        # ``info`` is intentionally untyped to keep this model portable across Pydantic v2 minors.
        kind = getattr(info, "data", {}).get("kind")
        if kind == WheelKind.LOCAL_FIXTURE_VALIDATOR and any(
            profile != "local-lab" for profile in profiles
        ):
            raise ValueError("local_fixture_validator may only target the local-lab profile")
        return profiles


class WheelManifest(BaseModel):
    """A signed artifact descriptor.  It is policy input, not a documentation file."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,63}$")
    version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$")
    kind: WheelKind
    entrypoint: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_.]*:[A-Za-z_][A-Za-z0-9_]*$")
    input_schema: str = Field(min_length=1, max_length=512)
    output_schema: str = Field(min_length=1, max_length=512)
    capabilities: tuple[str, ...] = Field(min_length=1)
    profiles: tuple[str, ...] = Field(min_length=1)
    sources: tuple[SourceRecord, ...] = Field(min_length=1)
    tests: tuple[str, ...] = Field(min_length=1)
    dependencies: tuple[str, ...] = ()
    artifact_sha256: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    status: WheelStatus = WheelStatus.DRAFT
    approved_by: str | None = Field(default=None, max_length=200)
    signature: str | None = Field(default=None, min_length=16, max_length=4096)
    expires_at: datetime | None = None

    @field_validator("capabilities")
    @classmethod
    def _manifest_capabilities_are_passive(cls, capabilities: tuple[str, ...]) -> tuple[str, ...]:
        forbidden = FORBIDDEN_CAPABILITIES.intersection(capabilities)
        if forbidden:
            raise ValueError(f"forbidden wheel capabilities: {', '.join(sorted(forbidden))}")
        return capabilities

    @field_validator("profiles")
    @classmethod
    def _manifest_fixture_local_only(
        cls, profiles: tuple[str, ...], info: object
    ) -> tuple[str, ...]:
        kind = getattr(info, "data", {}).get("kind")
        if kind == WheelKind.LOCAL_FIXTURE_VALIDATOR and any(
            profile != "local-lab" for profile in profiles
        ):
            raise ValueError("local_fixture_validator may only target the local-lab profile")
        return profiles


class ValidationReport(BaseModel):
    """Immutable output from the offline validator; failures are first-class evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    wheel_id: str
    wheel_version: str
    artifact_sha256: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    passed: bool
    violations: tuple[str, ...] = ()
    checked_files: tuple[str, ...] = ()
    imports: tuple[str, ...] = ()
    sbom: tuple[str, ...] = ()
    validated_at: datetime


class SandboxExecutionResult(BaseModel):
    """Evidence from a candidate execution in the mandatory Docker boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    image: str
    image_digest: str
    command: tuple[str, ...]
    passed: bool
    exit_code: int | None = None
    timed_out: bool = False
    failure_reason: str | None = None
    stdout_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    stderr_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    stdout_preview: str = Field(default="", max_length=4096)
    stderr_preview: str = Field(default="", max_length=4096)
    executed_at: datetime


class SandboxJsonExecutionResult(SandboxExecutionResult):
    """Bounded JSON result from the fixed, isolated capability host protocol."""

    output_json: str = Field(default="", max_length=65_536)
