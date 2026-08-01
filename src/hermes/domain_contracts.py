"""Strict V2 domain contracts for the fixed localhost vertical slice.

These models deliberately describe facts and references only.  They do not
perform network access, consume approvals, verify signatures, or promote a
candidate into a finding; those remain host-runtime responsibilities.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime
from typing import ClassVar, Literal, Self
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .evidence import EvidenceArtifactRef
from .runtime.actions import ActionKind, ProposedAction
from .security import canonical_json

_DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"
_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_CANDIDATE_ID_PATTERN = r"^[a-z0-9][a-z0-9._-]{0,119}$"
_FIXED_CANDIDATE: Literal["missing_x_content_type_options"] = "missing_x_content_type_options"


def canonical_digest(value: object) -> str:
    """Return the canonical digest used by every V2 contract."""

    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def _require_local_http_url(value: str, *, label: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname != "localhost"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError(f"{label} must be an absolute localhost HTTP URL")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"{label} contains an invalid port") from exc
    if port is None:
        raise ValueError(f"{label} must declare its loopback fixture port")
    return value


class V2Contract(BaseModel):
    """Frozen, closed-world base shared by every V2 domain record."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["2"] = "2"

    @property
    def digest(self) -> str:
        return canonical_digest(self)


class RunBoundV2Contract(V2Contract):
    run_id: str = Field(pattern=_ID_PATTERN)
    scope_digest: str = Field(pattern=_DIGEST_PATTERN)
    generated_by_task_id: str = Field(pattern=_ID_PATTERN)


class AssetRecord(V2Contract):
    asset_id: str = Field(pattern=_ID_PATTERN)
    kind: Literal["web"] = "web"
    canonical_host: Literal["localhost"] = "localhost"
    resolved_ips: tuple[str, ...] = Field(min_length=1)
    scheme: Literal["http", "https"]
    port: int = Field(ge=1, le=65_535)
    service: Literal["http", "https"]
    status_code: int = Field(ge=100, le=599)
    header_projection: dict[str, str] = Field(default_factory=dict)

    @field_validator("resolved_ips")
    @classmethod
    def loopback_addresses_only(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("asset resolved IPs must be unique")
        for item in value:
            try:
                address = ipaddress.ip_address(item)
            except ValueError as exc:
                raise ValueError("asset resolved IPs must be canonical IP addresses") from exc
            if not address.is_loopback or str(address) != item:
                raise ValueError("the fixed chain only permits canonical loopback IPs")
        return value

    @field_validator("header_projection")
    @classmethod
    def restricted_headers(cls, value: dict[str, str]) -> dict[str, str]:
        allowed = {"content-type", "link", "x-content-type-options"}
        if any(name != name.lower() or name not in allowed for name in value):
            raise ValueError("asset header projection contains an unrestricted header")
        return value

    @model_validator(mode="after")
    def coherent_service(self) -> Self:
        if self.service != self.scheme:
            raise ValueError("asset service must match its URL scheme")
        return self


class AssetInventory(RunBoundV2Contract):
    inventory_id: str = Field(pattern=_ID_PATTERN)
    target: str = Field(min_length=1, max_length=2_048)
    assets: tuple[AssetRecord, ...] = Field(min_length=1, max_length=1)
    source_evidence: tuple[EvidenceArtifactRef, ...] = Field(min_length=1, max_length=1)

    @field_validator("target")
    @classmethod
    def local_target(cls, value: str) -> str:
        return _require_local_http_url(value, label="asset inventory target")

    @model_validator(mode="after")
    def fixed_asset_matches_target(self) -> Self:
        parsed = urlsplit(self.target)
        asset = self.assets[0]
        if (parsed.hostname, parsed.scheme, parsed.port) != (
            asset.canonical_host,
            asset.scheme,
            asset.port,
        ):
            raise ValueError("the fixed asset must match the inventory target")
        return self


class EndpointRecord(V2Contract):
    endpoint_id: str = Field(pattern=_ID_PATTERN)
    asset_id: str = Field(pattern=_ID_PATTERN)
    canonical_url: str = Field(min_length=1, max_length=2_048)
    method: Literal["GET"] = "GET"
    relation: Literal["candidate", "negative_control"]
    content_types: tuple[str, ...] = ()
    parameters: tuple[str, ...] = ()
    auth_context: Literal["anonymous"] = "anonymous"
    evidence: tuple[EvidenceArtifactRef, ...] = Field(min_length=1)

    @field_validator("canonical_url")
    @classmethod
    def local_endpoint(cls, value: str) -> str:
        return _require_local_http_url(value, label="endpoint")

    @field_validator("content_types", "parameters")
    @classmethod
    def unique_strings(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("endpoint string collections must be unique")
        return value


class EndpointInventory(RunBoundV2Contract):
    inventory_id: str = Field(pattern=_ID_PATTERN)
    asset_inventory_digest: str = Field(pattern=_DIGEST_PATTERN)
    endpoints: tuple[EndpointRecord, ...] = Field(min_length=2, max_length=2)
    unresolved: tuple[str, ...] = ()

    @model_validator(mode="after")
    def exact_candidate_control_pair(self) -> Self:
        if len(self.endpoints) != 2:
            raise ValueError("the fixed chain requires exactly two endpoints")
        if tuple(endpoint.relation for endpoint in self.endpoints) != (
            "candidate",
            "negative_control",
        ):
            raise ValueError("endpoints must contain one candidate and one negative control")
        ids = [endpoint.endpoint_id for endpoint in self.endpoints]
        urls = [endpoint.canonical_url for endpoint in self.endpoints]
        if len(set(ids)) != 2 or len(set(urls)) != 2:
            raise ValueError("candidate and control endpoints must be unique")
        if len({endpoint.asset_id for endpoint in self.endpoints}) != 1:
            raise ValueError("candidate and control must belong to one asset")
        origins = {
            (
                urlsplit(endpoint.canonical_url).scheme,
                urlsplit(endpoint.canonical_url).hostname,
                urlsplit(endpoint.canonical_url).port,
            )
            for endpoint in self.endpoints
        }
        if len(origins) != 1:
            raise ValueError("candidate and control must share one localhost origin")
        return self


class CandidateRecord(V2Contract):
    candidate_id: str = Field(pattern=_CANDIDATE_ID_PATTERN)
    candidate_type: Literal["missing_x_content_type_options"] = _FIXED_CANDIDATE
    status: Literal["candidate", "blocked", "inconclusive"] = "candidate"
    target_endpoint_id: str = Field(pattern=_ID_PATTERN)
    control_endpoint_id: str = Field(pattern=_ID_PATTERN)
    rationale: str = Field(min_length=1, max_length=4_000)
    counterexamples: tuple[str, ...] = Field(min_length=1)
    required_evidence: tuple[EvidenceArtifactRef, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def distinct_endpoints(self) -> Self:
        if self.target_endpoint_id == self.control_endpoint_id:
            raise ValueError("candidate target and control endpoints must differ")
        return self


class CandidateSet(RunBoundV2Contract):
    set_id: str = Field(pattern=_ID_PATTERN)
    endpoint_inventory_digest: str = Field(pattern=_DIGEST_PATTERN)
    prompt_id: str = Field(pattern=r"^[a-z][a-z0-9._/-]{0,127}$")
    prompt_version: Literal["2.0"] = "2.0"
    prompt_sha256: str = Field(pattern=_DIGEST_PATTERN)
    candidates: tuple[CandidateRecord, ...] = Field(min_length=1, max_length=1)
    dedup_decisions: tuple[str, ...] = ()

    @model_validator(mode="after")
    def exactly_one_fixed_candidate(self) -> Self:
        if len(self.candidates) != 1:
            raise ValueError("the fixed chain requires exactly one candidate")
        ids = [candidate.candidate_id for candidate in self.candidates]
        if len(ids) != len(set(ids)):
            raise ValueError("candidate IDs must be unique")
        return self


class VerificationStep(V2Contract):
    action_id: str = Field(pattern=_ID_PATTERN)
    endpoint_id: str = Field(pattern=_ID_PATTERN)
    purpose: Literal["candidate", "negative_control"]
    action_kind: Literal["validation_http_get"] = "validation_http_get"
    target_url: str = Field(min_length=1, max_length=2_048)
    method: Literal["GET"] = "GET"
    request_budget: Literal[1] = 1
    evidence_prerequisites: tuple[EvidenceArtifactRef, ...] = ()
    expected_assertion: str = Field(min_length=1, max_length=2_000)
    stop_conditions: tuple[str, ...] = ()

    @field_validator("target_url")
    @classmethod
    def local_target(cls, value: str) -> str:
        return _require_local_http_url(value, label="verification target")

    @property
    def action_digest(self) -> str:
        return ProposedAction(
            kind=ActionKind.VALIDATION_HTTP_GET,
            target=self.target_url,
            method=self.method,
            max_requests=self.request_budget,
        ).digest


class VerificationPlan(RunBoundV2Contract):
    plan_id: str = Field(pattern=_ID_PATTERN)
    candidate_set_digest: str = Field(pattern=_DIGEST_PATTERN)
    endpoint_inventory_digest: str = Field(pattern=_DIGEST_PATTERN)
    candidate_id: str = Field(pattern=_CANDIDATE_ID_PATTERN)
    steps: tuple[VerificationStep, ...] = Field(min_length=2, max_length=2)
    request_budget: Literal[2] = 2
    created_at: datetime
    expires_at: datetime

    @field_validator("created_at", "expires_at")
    @classmethod
    def timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("verification plan timestamps must be timezone-aware")
        return value

    @model_validator(mode="after")
    def exact_ordered_pair(self) -> Self:
        if self.expires_at <= self.created_at:
            raise ValueError("verification plan must expire after creation")
        if len(self.steps) != 2 or tuple(step.purpose for step in self.steps) != (
            "candidate",
            "negative_control",
        ):
            raise ValueError("verification plan requires an ordered candidate/control pair")
        if len({step.action_id for step in self.steps}) != 2:
            raise ValueError("verification action IDs must be unique")
        if len({step.endpoint_id for step in self.steps}) != 2:
            raise ValueError("verification endpoints must be unique")
        if len({step.action_digest for step in self.steps}) != 2:
            raise ValueError("verification action digests must be unique")
        if sum(int(step.request_budget) for step in self.steps) != int(self.request_budget):
            raise ValueError("verification request budget must equal its step budgets")
        return self


class VerificationStepOutcome(V2Contract):
    action_id: str = Field(pattern=_ID_PATTERN)
    action_digest: str = Field(pattern=_DIGEST_PATTERN)
    consumption_digest: str = Field(pattern=_DIGEST_PATTERN)
    evidence: EvidenceArtifactRef
    status: Literal["passed", "failed", "blocked", "inconclusive"]
    assertion: str = Field(min_length=1, max_length=2_000)


class VerificationOutcome(RunBoundV2Contract):
    outcome_id: str = Field(pattern=_ID_PATTERN)
    candidate_id: str = Field(pattern=_CANDIDATE_ID_PATTERN)
    verification_plan_digest: str = Field(pattern=_DIGEST_PATTERN)
    approval_bundle_id: str = Field(pattern=_ID_PATTERN)
    approval_bundle_digest: str = Field(pattern=_DIGEST_PATTERN)
    step_outcomes: tuple[VerificationStepOutcome, ...] = Field(min_length=2, max_length=2)
    status: Literal["validated", "inconclusive", "blocked"]
    differential_assertion: bool
    assertion_summary: str = Field(min_length=1, max_length=4_000)

    @model_validator(mode="after")
    def coherent_outcome(self) -> Self:
        if len(self.step_outcomes) != 2:
            raise ValueError("verification outcome requires exactly two step outcomes")
        if len({step.action_id for step in self.step_outcomes}) != 2:
            raise ValueError("verification outcome action IDs must be unique")
        evidence_ids = [step.evidence.evidence_id for step in self.step_outcomes]
        if len(set(evidence_ids)) != 2:
            raise ValueError("verification outcome evidence must be unique")
        if self.status == "validated" and (
            not self.differential_assertion
            or any(step.status != "passed" for step in self.step_outcomes)
        ):
            raise ValueError("validated outcome requires two passed steps and a true differential")
        if self.status != "validated" and self.differential_assertion:
            raise ValueError("non-validated outcome cannot assert a successful differential")
        return self

    @property
    def evidence(self) -> tuple[EvidenceArtifactRef, ...]:
        return tuple(step.evidence for step in self.step_outcomes)


class ValidatedFinding(RunBoundV2Contract):
    finding_id: str = Field(pattern=_CANDIDATE_ID_PATTERN)
    candidate_id: str = Field(pattern=_CANDIDATE_ID_PATTERN)
    candidate_set_digest: str = Field(pattern=_DIGEST_PATTERN)
    verification_plan_digest: str = Field(pattern=_DIGEST_PATTERN)
    verification_outcome_digest: str = Field(pattern=_DIGEST_PATTERN)
    approval_bundle_id: str = Field(pattern=_ID_PATTERN)
    approval_bundle_digest: str = Field(pattern=_DIGEST_PATTERN)
    approval_consumption_digests: tuple[str, ...] = Field(min_length=2, max_length=2)
    signed_review_id: str = Field(pattern=_ID_PATTERN)
    signed_review_digest: str = Field(pattern=_DIGEST_PATTERN)
    evidence: tuple[EvidenceArtifactRef, ...] = Field(min_length=3, max_length=3)
    title: str = Field(min_length=1, max_length=240)
    target: str = Field(min_length=1, max_length=2_048)
    summary: str = Field(min_length=1, max_length=4_000)
    prerequisites: tuple[str, ...] = ()
    reproduction_steps: tuple[str, ...] = Field(min_length=1)
    impact: str = Field(min_length=1, max_length=4_000)
    remediation: str = Field(min_length=1, max_length=4_000)
    severity: Literal["informational", "low", "medium", "high", "critical"]
    local_teaching_fixture: Literal[True] = True
    vrt_snapshot: str | None = None
    cvss_vector: str | None = None

    @field_validator("approval_consumption_digests")
    @classmethod
    def valid_unique_consumptions(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(re.fullmatch(_DIGEST_PATTERN, item) is None for item in value):
            raise ValueError("approval consumption digests must be SHA-256 values")
        if len(set(value)) != 2:
            raise ValueError("validated finding requires two unique approval consumptions")
        return value

    @field_validator("target")
    @classmethod
    def local_finding_target(cls, value: str) -> str:
        return _require_local_http_url(value, label="finding target")

    @model_validator(mode="after")
    def unique_evidence(self) -> Self:
        if self.finding_id != self.candidate_id:
            raise ValueError("the fixed finding ID must equal its candidate ID")
        if len({item.evidence_id for item in self.evidence}) != 3:
            raise ValueError("validated finding requires three unique evidence artifacts")
        return self


class CoverageReport(RunBoundV2Contract):
    report_id: str = Field(pattern=_ID_PATTERN)
    asset_inventory_digest: str = Field(pattern=_DIGEST_PATTERN)
    endpoint_inventory_digest: str = Field(pattern=_DIGEST_PATTERN)
    candidate_set_digest: str = Field(pattern=_DIGEST_PATTERN)
    verification_plan_digest: str = Field(pattern=_DIGEST_PATTERN)
    verification_outcome_digest: str = Field(pattern=_DIGEST_PATTERN)
    validated_finding_digest: str = Field(pattern=_DIGEST_PATTERN)
    assets_discovered: Literal[1] = 1
    endpoints_discovered: Literal[2] = 2
    candidates_discovered: Literal[1] = 1
    steps_planned: int = Field(ge=0)
    steps_tested: int = Field(ge=0)
    steps_blocked: int = Field(ge=0)
    steps_skipped: int = Field(ge=0)
    findings_validated: int = Field(ge=0)
    candidates_inconclusive: int = Field(ge=0)
    candidates_disproved: int = Field(ge=0)
    untested_reasons: tuple[str, ...] = ()
    requests_planned: Literal[3] = 3
    requests_used: Literal[3] = 3
    model_calls: int = Field(ge=1)
    elapsed_ms: int = Field(ge=1)
    cost_microusd: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def conserved_counts(self) -> Self:
        if self.steps_planned != self.steps_tested + self.steps_blocked + self.steps_skipped:
            raise ValueError("planned steps must equal tested, blocked, and skipped steps")
        if self.candidates_discovered != (
            self.findings_validated + self.candidates_inconclusive + self.candidates_disproved
        ):
            raise ValueError("candidate counts must be conserved")
        if self.steps_skipped and not self.untested_reasons:
            raise ValueError("skipped steps require an untested reason")
        if self.requests_used > self.requests_planned:
            raise ValueError("used requests cannot exceed planned requests")
        return self


class GateDecisionV2(RunBoundV2Contract):
    decision: Literal["allowed", "blocked"]
    target: str = Field(min_length=1, max_length=2_048)
    resolved_ip: str
    reason: str = Field(min_length=1, max_length=2_000)

    @field_validator("target")
    @classmethod
    def local_target(cls, value: str) -> str:
        return _require_local_http_url(value, label="gate target")

    @field_validator("resolved_ip")
    @classmethod
    def loopback_ip(cls, value: str) -> str:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("gate decision must contain a canonical IP") from exc
        if not address.is_loopback or str(address) != value:
            raise ValueError("gate decision must bind a canonical loopback IP")
        return value


class ReporterAcknowledgement(RunBoundV2Contract):
    finding_id: str = Field(pattern=_CANDIDATE_ID_PATTERN)
    coverage_report_digest: str = Field(pattern=_DIGEST_PATTERN)
    authorization_receipt_digest: str = Field(pattern=_DIGEST_PATTERN)
    accepted: Literal[True] = True


ContractPayload = (
    GateDecisionV2
    | AssetInventory
    | EndpointInventory
    | CandidateSet
    | VerificationOutcome
    | ReporterAcknowledgement
)
ContractId = Literal[
    "hermes.gate_decision/v2",
    "hermes.asset_inventory/v2",
    "hermes.endpoint_inventory/v2",
    "hermes.candidate_set/v2",
    "hermes.verification_outcome/v2",
    "hermes.reporter_acknowledgement/v2",
]


class ContractEnvelope(V2Contract):
    """Hash-bound V2 role output with a closed contract-ID registry."""

    contract_version: Literal["2"] = "2"
    contract_id: ContractId
    payload: ContractPayload
    payload_sha256: str = Field(pattern=_DIGEST_PATTERN)

    _CONTRACT_IDS: ClassVar[dict[type[V2Contract], ContractId]] = {
        GateDecisionV2: "hermes.gate_decision/v2",
        AssetInventory: "hermes.asset_inventory/v2",
        EndpointInventory: "hermes.endpoint_inventory/v2",
        CandidateSet: "hermes.candidate_set/v2",
        VerificationOutcome: "hermes.verification_outcome/v2",
        ReporterAcknowledgement: "hermes.reporter_acknowledgement/v2",
    }

    @model_validator(mode="after")
    def bound_id_and_hash(self) -> Self:
        expected = self._CONTRACT_IDS.get(type(self.payload))
        if expected != self.contract_id:
            raise ValueError("contract ID does not match its typed payload")
        if self.payload_sha256 != self.payload.digest:
            raise ValueError("contract payload hash does not match the canonical payload")
        return self

    @classmethod
    def for_payload(cls, payload: ContractPayload) -> ContractEnvelope:
        contract_id = cls._CONTRACT_IDS.get(type(payload))
        if contract_id is None:  # pragma: no cover - guarded by the public type
            raise TypeError(f"unsupported V2 contract payload: {type(payload).__name__}")
        return cls(
            contract_id=contract_id,
            payload=payload,
            payload_sha256=payload.digest,
        )


__all__ = [
    "AssetInventory",
    "AssetRecord",
    "CandidateRecord",
    "CandidateSet",
    "ContractEnvelope",
    "ContractPayload",
    "CoverageReport",
    "EndpointInventory",
    "EndpointRecord",
    "GateDecisionV2",
    "ReporterAcknowledgement",
    "ValidatedFinding",
    "VerificationOutcome",
    "VerificationPlan",
    "VerificationStep",
    "VerificationStepOutcome",
    "canonical_digest",
]
