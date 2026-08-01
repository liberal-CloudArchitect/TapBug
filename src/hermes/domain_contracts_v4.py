"""Closed V4 contracts for Phase 5 reporting, quality, and formal output.

The V4 execution engine remains independent from V3.  This module defines only
the records needed by V4 reporting/preflight and leaves V3 governance records
unchanged.  V4 may still reference V3-style approval/consumption/evidence
artifacts, but its promoted findings and report authorization are versioned
separately.
"""

from __future__ import annotations

from datetime import datetime
from typing import ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .domain_contracts import canonical_digest
from .evidence import EvidenceArtifactRef

_DIGEST = r"^sha256:[0-9a-f]{64}$"
_ID = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$"
_ROLE = r"^[a-z][a-z0-9-]{0,63}$"
_URL = r"^https?://localhost:[0-9]+(?:/.*)?$"

CandidateTypeV4 = Literal[
    "missing_x_content_type_options",
    "exposed_debug_endpoint",
    "unauthorized_graphql_mutation",
    "privilege_escalation",
    "insecure_session_cookie",
    "cross_tenant_object_read",
    "unvalidated_redirect",
    "workflow_transition_bypass",
]
SeverityV4 = Literal["informational", "low", "medium", "high", "critical"]
CompletionV4 = Literal["completed", "completed_with_gaps"]
FamilyV4 = Literal["web", "api", "authz", "infra", "passive", "mapping", "workflow"]


def _unique(values: tuple[str, ...], label: str) -> tuple[str, ...]:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")
    return values


def _aware(value: datetime, label: str) -> datetime:
    if value.tzinfo is None:
        raise ValueError(f"{label} must be timezone-aware")
    return value


class V4Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["4"] = "4"

    @property
    def digest(self) -> str:
        return canonical_digest(self)


class RunBoundV4Contract(V4Contract):
    run_id: str = Field(pattern=_ID)
    scope_digest: str = Field(pattern=_DIGEST)
    generated_by_task_id: str = Field(pattern=_ID)


class ExecutionBudgetV4(V4Contract):
    max_concurrency: int = Field(default=4, ge=1, le=4)
    # This is a provisional local-lab stability envelope.  It is deliberately
    # recorded in every RunPlan and will be recalibrated from real E2E data.
    max_model_attempts: int = Field(default=64, ge=1, le=64)
    reservation_per_attempt_microusd: int = Field(default=250_000, ge=1)
    max_estimated_cost_microusd: int = Field(default=16_000_000, ge=1, le=16_000_000)
    max_active_seconds: int = Field(default=2_700, ge=1)
    max_role_seconds: int = Field(default=300, ge=1)
    max_requests: int = Field(default=32, ge=1, le=32)

    @model_validator(mode="after")
    def coherent_limits(self) -> ExecutionBudgetV4:
        if self.max_model_attempts * self.reservation_per_attempt_microusd > (
            self.max_estimated_cost_microusd
        ):
            raise ValueError("cost cap must reserve every allowed model attempt")
        if self.max_role_seconds > self.max_active_seconds:
            raise ValueError("role timeout cannot exceed active execution time")
        return self


class RunPlanV4(V4Contract):
    run_id: str = Field(pattern=_ID)
    target: str = Field(pattern=_URL)
    scope_digest: str = Field(pattern=_DIGEST)
    provider_id: str = Field(pattern=_ID)
    model_id: str = Field(min_length=1, max_length=256)
    prompt_registry_digest: str = Field(pattern=_DIGEST)
    role_manifest_set_digest: str = Field(pattern=_DIGEST)
    roles: tuple[str, ...] = Field(min_length=9, max_length=9)
    identity_binding_digests: dict[str, str] = Field(default_factory=dict)
    budget: ExecutionBudgetV4 = Field(default_factory=ExecutionBudgetV4)
    created_at: datetime

    @field_validator("roles")
    @classmethod
    def expected_roles(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        _unique(value, "run-plan roles")
        required = {
            "gatekeeper",
            "recon",
            "mapper",
            "web-vuln",
            "api",
            "authz",
            "infra",
            "verifier",
            "reporter",
        }
        if set(value) != required:
            raise ValueError("V4 run plan must declare the exact nine-role set")
        return value

    @field_validator("identity_binding_digests")
    @classmethod
    def valid_bindings(cls, value: dict[str, str]) -> dict[str, str]:
        if any(not alias or not digest.startswith("sha256:") for alias, digest in value.items()):
            raise ValueError("identity bindings require aliases and SHA-256 digests")
        return value

    @field_validator("created_at")
    @classmethod
    def aware_created_at(cls, value: datetime) -> datetime:
        return _aware(value, "run-plan created_at")


class PassiveTlsPostureV4(V4Contract):
    tls_enabled: bool = True
    version: Literal["4"] = "4"
    protocol: str = Field(min_length=1, max_length=64)
    cipher_suite: str = Field(min_length=1, max_length=128)
    certificate_chain_sha256: tuple[str, ...] = Field(min_length=1)

    @field_validator("certificate_chain_sha256")
    @classmethod
    def valid_chain(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique(value, "certificate digests")


class PassiveCookiePostureV4(V4Contract):
    name: str = Field(min_length=1, max_length=128)
    secure: bool
    http_only: bool
    same_site: Literal["Strict", "Lax", "None", "Unset"] = "Unset"


class PassivePostureV4(RunBoundV4Contract):
    posture_id: str = Field(pattern=_ID)
    target_url: str = Field(pattern=_URL)
    fingerprint_labels: tuple[str, ...] = ()
    response_header_names: tuple[str, ...] = ()
    cookies: tuple[PassiveCookiePostureV4, ...] = ()
    tls: PassiveTlsPostureV4 | None = None
    schema_urls: tuple[str, ...] = ()
    evidence: tuple[EvidenceArtifactRef, ...] = Field(min_length=1)

    @field_validator("fingerprint_labels", "response_header_names", "schema_urls")
    @classmethod
    def unique_texts(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique(value, "passive posture collections")


class GateDecisionV4(RunBoundV4Contract):
    decision: Literal["allowed", "blocked"]
    target: str = Field(pattern=_URL)
    resolved_ips: tuple[str, ...] = Field(min_length=1)
    reason: str = Field(min_length=1, max_length=2_000)

    @field_validator("resolved_ips")
    @classmethod
    def unique_ips(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique(value, "resolved IPs")


class AssetInventoryV4(RunBoundV4Contract):
    inventory_id: str = Field(pattern=_ID)
    target: str = Field(pattern=_URL)
    passive_posture_digest: str | None = Field(default=None, pattern=_DIGEST)
    evidence: tuple[EvidenceArtifactRef, ...] = Field(min_length=1)


class SurfaceEndpointV4(V4Contract):
    endpoint_id: str = Field(pattern=_ID)
    url: str = Field(pattern=_URL)
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
    route_kind: Literal[
        "candidate",
        "control",
        "graphql",
        "authz",
        "workflow",
        "login",
        "public_api",
        "spa_fallback",
    ]
    path_parameters: tuple[str, ...] = ()
    query_parameters: tuple[str, ...] = ()
    auth_identity_aliases: tuple[str, ...] = ()
    source_evidence: tuple[EvidenceArtifactRef, ...] = Field(min_length=1)

    @field_validator("path_parameters", "query_parameters", "auth_identity_aliases")
    @classmethod
    def unique_fields(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique(value, "surface endpoint collections")


class SurfaceMapV4(RunBoundV4Contract):
    map_id: str = Field(pattern=_ID)
    passive_posture_digest: str = Field(pattern=_DIGEST)
    endpoints: tuple[SurfaceEndpointV4, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_endpoint_ids(self) -> SurfaceMapV4:
        _unique(tuple(item.endpoint_id for item in self.endpoints), "surface endpoint IDs")
        return self


class BranchCandidateV4(V4Contract):
    candidate_id: str = Field(pattern=_ID)
    candidate_type: CandidateTypeV4
    producer_branch: Literal["web", "api", "authz", "infra"]
    target_url: str = Field(pattern=_URL)
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
    rationale: str = Field(min_length=1, max_length=2_000)
    status: Literal["candidate", "blocked", "inconclusive"] = "candidate"


class BranchAssessmentV4(RunBoundV4Contract):
    assessment_id: str = Field(pattern=_ID)
    operation: Literal["assessment", "cross_review"] = "assessment"
    branch: Literal["web", "api", "authz", "infra"]
    surface_map_digest: str = Field(pattern=_DIGEST)
    candidates: tuple[BranchCandidateV4, ...] = ()

    @model_validator(mode="after")
    def branch_candidates(self) -> BranchAssessmentV4:
        _unique(tuple(item.candidate_id for item in self.candidates), "branch candidate IDs")
        if any(item.producer_branch != self.branch for item in self.candidates):
            raise ValueError("branch assessment may only emit its own branch candidates")
        return self


class CrossReviewV4(V4Contract):
    review_id: str = Field(pattern=_ID)
    candidate_id: str = Field(pattern=_ID)
    producer_branches: tuple[Literal["web", "api", "authz", "infra"], ...] = Field(min_length=1)
    reviewer_branch: Literal["web", "api", "authz", "infra"]
    verdict: Literal["concur", "reject", "needs_more_evidence"]
    rationale: str = Field(min_length=1, max_length=2_000)


class CrossReviewSetV4(RunBoundV4Contract):
    review_set_id: str = Field(pattern=_ID)
    surface_map_digest: str | None = Field(default=None, pattern=_DIGEST)
    reviews: tuple[CrossReviewV4, ...]

    @model_validator(mode="after")
    def unique_reviews(self) -> CrossReviewSetV4:
        _unique(tuple(item.review_id for item in self.reviews), "cross-review IDs")
        _unique(tuple(item.candidate_id for item in self.reviews), "cross-review candidate IDs")
        return self


class QualityFamilyMetricsV4(V4Contract):
    family: FamilyV4
    dataset_version: str = Field(min_length=1, max_length=128)
    dataset_digest: str = Field(pattern=_DIGEST)
    positives: int = Field(ge=0)
    negatives: int = Field(ge=0)
    candidate_recall: float | None = Field(default=None, ge=0.0, le=1.0)
    verified_precision: float | None = Field(default=None, ge=0.0, le=1.0)
    false_positive_candidates: int = Field(default=0, ge=0)
    false_negative_candidates: int = Field(default=0, ge=0)
    blocked_count: int = Field(default=0, ge=0)
    inconclusive_count: int = Field(default=0, ge=0)
    requests_used: int = Field(default=0, ge=0)
    elapsed_ms: int = Field(default=0, ge=0)
    model_attempts: int = Field(default=0, ge=0)
    # Providers may return token usage without a price, or no billing data at
    # all.  ``null`` is deliberately different from zero: writing zero for an
    # unknown cost would make a quality receipt look cheaper than it is.
    estimated_cost_microusd: int | None = Field(default=None, ge=0)
    passed: bool

    @model_validator(mode="after")
    def thresholds(self) -> QualityFamilyMetricsV4:
        if self.positives > 0 and self.candidate_recall is None:
            raise ValueError("positive datasets require candidate recall")
        if self.passed and self.positives > 0 and self.candidate_recall is None:
            raise ValueError("passing metrics must state recall")
        if self.passed and self.candidate_recall is not None and self.candidate_recall < 0.95:
            raise ValueError("passing metrics must keep candidate recall at or above 95%")
        if self.passed and self.verified_precision not in {None, 1.0}:
            raise ValueError("passing metrics must preserve perfect verified precision")
        return self


class QualityGateReceiptV4(RunBoundV4Contract):
    receipt_id: str = Field(pattern=_ID)
    families: tuple[QualityFamilyMetricsV4, ...] = Field(min_length=1)
    overall_passed: bool
    recorded_at: datetime

    @field_validator("recorded_at")
    @classmethod
    def aware_recorded_at(cls, value: datetime) -> datetime:
        return _aware(value, "quality receipt timestamp")

    @model_validator(mode="after")
    def coherent_families(self) -> QualityGateReceiptV4:
        _unique(tuple(item.family for item in self.families), "quality families")
        if self.overall_passed != all(item.passed for item in self.families):
            raise ValueError("overall quality gate must match family pass state")
        return self


class FindingV4(V4Contract):
    finding_id: str = Field(pattern=_ID)
    candidate_id: str = Field(pattern=_ID)
    candidate_type: CandidateTypeV4
    family: FamilyV4
    title: str = Field(min_length=1, max_length=240)
    summary: str = Field(min_length=1, max_length=4_000)
    reproduction_steps: tuple[str, ...] = Field(min_length=1)
    prerequisites: tuple[str, ...] = Field(default=())
    impact: str = Field(min_length=1, max_length=4_000)
    remediation: str = Field(min_length=1, max_length=4_000)
    severity: SeverityV4
    severity_rationale: str = Field(min_length=1, max_length=4_000)
    vrt_category: str = Field(min_length=1, max_length=240)
    cvss_vector: str = Field(min_length=1, max_length=240)
    passive_posture_digest: str | None = Field(default=None, pattern=_DIGEST)
    surface_map_digest: str | None = Field(default=None, pattern=_DIGEST)
    verification_outcome_digest: str = Field(pattern=_DIGEST)
    approval_batch_digests: tuple[str, ...] = ()
    approval_consumption_digests: tuple[str, ...] = ()
    evidence: tuple[EvidenceArtifactRef, ...] = Field(min_length=1)
    review_digest: str = Field(pattern=_DIGEST)
    local_teaching_fixture: Literal[True] = True

    @field_validator("approval_batch_digests", "approval_consumption_digests")
    @classmethod
    def digest_tuples(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique(value, "finding digest references")

    @model_validator(mode="after")
    def coherent_ids(self) -> FindingV4:
        if self.finding_id != self.candidate_id:
            raise ValueError("finding_id must equal candidate_id")
        _unique(tuple(item.evidence_id for item in self.evidence), "finding evidence")
        return self


class VerificationOutcomeV4(V4Contract):
    outcome_id: str = Field(pattern=_ID)
    candidate_id: str = Field(pattern=_ID)
    verifier_task_id: str = Field(pattern=_ID)
    status: Literal["validated", "disproved", "inconclusive", "blocked"]
    action_digests: tuple[str, ...] = ()
    evidence: tuple[EvidenceArtifactRef, ...] = ()
    assertion_summary: str = Field(min_length=1, max_length=4_000)

    @field_validator("action_digests")
    @classmethod
    def digest_actions(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique(value, "verification action digests")


class VerificationActionV4(V4Contract):
    action_id: str = Field(pattern=_ID)
    candidate_id: str = Field(pattern=_ID)
    purpose: Literal[
        "baseline",
        "candidate",
        "negative_control",
        "cleanup",
        "cleanup_check",
        "state_check",
    ]
    risk_group: Literal["readonly", "mutation", "cleanup"]
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
    target_url: str = Field(pattern=_URL)
    action_digest: str = Field(pattern=_DIGEST)
    candidate_consumers: tuple[str, ...] = Field(min_length=1)
    body_sha256: str | None = Field(default=None, pattern=_DIGEST)
    identity_binding_digest: str | None = Field(default=None, pattern=_DIGEST)
    depends_on: tuple[str, ...] = ()
    cleanup_of: str | None = Field(default=None, pattern=_ID)
    request_budget: Literal[1] = 1

    @field_validator("candidate_consumers", "depends_on")
    @classmethod
    def unique_refs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique(value, "verification action references")

    @model_validator(mode="after")
    def coherent_action(self) -> VerificationActionV4:
        if self.candidate_id not in self.candidate_consumers:
            raise ValueError("primary candidate must be an action consumer")
        if self.cleanup_of is not None and self.purpose != "cleanup":
            raise ValueError("only cleanup actions may reference cleanup_of")
        if self.purpose in {"cleanup", "cleanup_check"} and self.risk_group == "readonly":
            raise ValueError("cleanup actions cannot be read-only")
        return self


class VerificationCampaignPlanV4(RunBoundV4Contract):
    campaign_id: str = Field(pattern=_ID)
    quality_gate_digest: str | None = Field(default=None, pattern=_DIGEST)
    actions: tuple[VerificationActionV4, ...]
    request_budget: int = Field(ge=0, le=32)
    created_at: datetime
    expires_at: datetime

    @field_validator("created_at", "expires_at")
    @classmethod
    def aware_times(cls, value: datetime) -> datetime:
        return _aware(value, "campaign timestamp")

    @model_validator(mode="after")
    def coherent_graph(self) -> VerificationCampaignPlanV4:
        _unique(tuple(item.action_id for item in self.actions), "campaign action IDs")
        _unique(tuple(item.action_digest for item in self.actions), "campaign action digests")
        if self.request_budget != sum(item.request_budget for item in self.actions):
            raise ValueError("campaign request budget must equal action budgets")
        if self.expires_at <= self.created_at:
            raise ValueError("campaign must expire after creation")
        known = {item.action_id for item in self.actions}
        for action in self.actions:
            if any(item not in known for item in action.depends_on):
                raise ValueError("action dependency is outside the campaign")
        return self


class ApprovalBatchV4(RunBoundV4Contract):
    approval_id: str = Field(pattern=_ID)
    campaign_digest: str = Field(pattern=_DIGEST)
    risk_group: Literal["readonly", "mutation", "cleanup"]
    verdict: Literal["approved", "rejected"]
    candidate_ids: tuple[str, ...]
    action_digests: tuple[str, ...]
    key_id: str = Field(pattern=_ID)
    signed_at: datetime
    expires_at: datetime
    rationale: str = Field(min_length=1, max_length=2_000)
    signature_b64: str = Field(min_length=16)

    @field_validator("candidate_ids", "action_digests")
    @classmethod
    def unique_bindings(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique(value, "approval bindings")

    @field_validator("signed_at", "expires_at")
    @classmethod
    def aware_datetimes(cls, value: datetime) -> datetime:
        return _aware(value, "approval timestamp")

    @model_validator(mode="after")
    def coherent_approval(self) -> ApprovalBatchV4:
        if self.expires_at <= self.signed_at:
            raise ValueError("approval must expire after signature")
        if self.verdict == "approved" and (not self.candidate_ids or not self.action_digests):
            raise ValueError("approved batch requires candidates and actions")
        return self


class VerificationOutcomeSetV4(RunBoundV4Contract):
    outcome_set_id: str = Field(pattern=_ID)
    quality_gate_digest: str | None = Field(default=None, pattern=_DIGEST)
    campaign_digest: str | None = Field(default=None, pattern=_DIGEST)
    approval_batch_digests: tuple[str, ...] = ()
    outcomes: tuple[VerificationOutcomeV4, ...]

    @field_validator("approval_batch_digests")
    @classmethod
    def digest_batches(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique(value, "approval batch digests")

    @model_validator(mode="after")
    def unique_outcomes(self) -> VerificationOutcomeSetV4:
        _unique(tuple(item.outcome_id for item in self.outcomes), "verification outcome IDs")
        _unique(tuple(item.candidate_id for item in self.outcomes), "verification candidate IDs")
        return self


class FindingSetV4(RunBoundV4Contract):
    finding_set_id: str = Field(pattern=_ID)
    passive_posture_digest: str | None = Field(default=None, pattern=_DIGEST)
    surface_map_digest: str | None = Field(default=None, pattern=_DIGEST)
    quality_gate_digest: str = Field(pattern=_DIGEST)
    cleanup_receipt_digest: str | None = Field(default=None, pattern=_DIGEST)
    findings: tuple[FindingV4, ...]

    @model_validator(mode="after")
    def unique_findings(self) -> FindingSetV4:
        _unique(tuple(item.finding_id for item in self.findings), "finding IDs")
        return self


class CoverageFamilySummaryV4(V4Contract):
    family: FamilyV4
    routed: int = Field(ge=0)
    tested: int = Field(ge=0)
    validated: int = Field(ge=0)
    disproved: int = Field(default=0, ge=0)
    blocked: int = Field(default=0, ge=0)
    inconclusive: int = Field(default=0, ge=0)
    requests_used: int = Field(default=0, ge=0)
    elapsed_ms: int = Field(default=0, ge=0)
    estimated_cost_microusd: int = Field(default=0, ge=0)
    not_tested_reasons: tuple[str, ...] = ()


class CoverageAppendixV4(RunBoundV4Contract):
    appendix_id: str = Field(pattern=_ID)
    quality_gate_digest: str = Field(pattern=_DIGEST)
    finding_set_digest: str = Field(pattern=_DIGEST)
    cleanup_receipt_digest: str | None = Field(default=None, pattern=_DIGEST)
    families: tuple[CoverageFamilySummaryV4, ...] = Field(min_length=1)
    requests_planned: int = Field(ge=0, le=32)
    requests_used: int = Field(ge=0, le=32)
    model_attempts_reserved: int = Field(ge=0, le=64)
    model_attempts_used: int = Field(ge=0, le=64)
    estimated_cost_microusd: int = Field(ge=0, le=16_000_000)
    active_elapsed_ms: int = Field(ge=0, le=2_700_000)
    completion: CompletionV4
    gaps: tuple[str, ...] = ()

    @model_validator(mode="after")
    def coherent_appendix(self) -> CoverageAppendixV4:
        _unique(tuple(item.family for item in self.families), "coverage families")
        if self.requests_used > self.requests_planned:
            raise ValueError("used requests cannot exceed planned requests")
        if self.model_attempts_used > self.model_attempts_reserved:
            raise ValueError("used attempts cannot exceed reservations")
        if self.completion == "completed_with_gaps" and not self.gaps:
            raise ValueError("completed_with_gaps requires explicit gaps")
        if self.completion == "completed" and self.gaps:
            raise ValueError("completed coverage cannot carry gaps")
        return self


class SignedReviewBatchV4(RunBoundV4Contract):
    review_id: str = Field(pattern=_ID)
    finding_set_digest: str = Field(pattern=_DIGEST)
    coverage_appendix_digest: str = Field(pattern=_DIGEST)
    report_draft_digest: str = Field(pattern=_DIGEST)
    gap_digests: tuple[str, ...] = ()
    verdict: Literal["accepted", "accepted_with_gaps", "rejected"]
    reviewer_key_id: str = Field(pattern=_ID)
    reviewed_at: datetime
    rationale: str = Field(min_length=1, max_length=4_000)
    signature_b64: str = Field(min_length=16)

    @field_validator("gap_digests")
    @classmethod
    def unique_gap_digests(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique(value, "review gaps")

    @field_validator("reviewed_at")
    @classmethod
    def aware_reviewed_at(cls, value: datetime) -> datetime:
        return _aware(value, "review timestamp")

    @model_validator(mode="after")
    def coherent_verdict(self) -> SignedReviewBatchV4:
        if self.verdict == "accepted_with_gaps" and not self.gap_digests:
            raise ValueError("accepted_with_gaps requires exact gaps")
        if self.verdict == "accepted" and self.gap_digests:
            raise ValueError("accepted review cannot carry gaps")
        return self


class ReporterLaunchReceiptV4(RunBoundV4Contract):
    receipt_id: str = Field(pattern=_ID)
    quality_gate_digest: str = Field(pattern=_DIGEST)
    finding_set_digest: str = Field(pattern=_DIGEST)
    coverage_appendix_digest: str = Field(pattern=_DIGEST)
    signed_review_digest: str = Field(pattern=_DIGEST)
    launch_authority_digest: str = Field(pattern=_DIGEST)
    verifier_schema_version: Literal["4"] = "4"
    verified_at: datetime

    @field_validator("verified_at")
    @classmethod
    def aware_verified_at(cls, value: datetime) -> datetime:
        return _aware(value, "launch verified_at")


class ReporterAckV4(RunBoundV4Contract):
    launch_receipt_digest: str = Field(pattern=_DIGEST)
    quality_gate_digest: str = Field(pattern=_DIGEST)
    finding_set_digest: str = Field(pattern=_DIGEST)
    coverage_appendix_digest: str = Field(pattern=_DIGEST)
    provider_metadata_digest: str = Field(pattern=_DIGEST)
    accepted: Literal[True] = True


class ReportWriteReceiptV4(RunBoundV4Contract):
    receipt_id: str = Field(pattern=_ID)
    launch_receipt_digest: str = Field(pattern=_DIGEST)
    reporter_ack_digest: str = Field(pattern=_DIGEST)
    report_sha256: str = Field(pattern=_DIGEST)
    findings_sha256: str = Field(pattern=_DIGEST)
    written_at: datetime

    @field_validator("written_at")
    @classmethod
    def aware_written_at(cls, value: datetime) -> datetime:
        return _aware(value, "written_at")


ContractPayloadV4 = (
    GateDecisionV4
    | AssetInventoryV4
    | SurfaceMapV4
    | BranchAssessmentV4
    | CrossReviewSetV4
    | VerificationOutcomeSetV4
    | ReporterAckV4
)
ContractIdV4 = Literal[
    "hermes.gate_decision/v4",
    "hermes.asset_inventory/v4",
    "hermes.surface_map/v4",
    "hermes.branch_operation/v4",
    "hermes.cross_review_set/v4",
    "hermes.verification_outcome_set/v4",
    "hermes.reporter_acknowledgement/v4",
]
ContractOperationV4 = Literal[
    "gate",
    "recon",
    "map",
    "assessment",
    "cross_review",
    "verification",
    "reporting",
]


class ContractEnvelopeV4(V4Contract):
    contract_version: Literal["4"] = "4"
    contract_id: ContractIdV4
    operation: ContractOperationV4
    payload: ContractPayloadV4
    payload_sha256: str = Field(pattern=_DIGEST)

    _CONTRACTS: ClassVar[dict[type[V4Contract], tuple[ContractIdV4, ContractOperationV4]]] = {
        GateDecisionV4: ("hermes.gate_decision/v4", "gate"),
        AssetInventoryV4: ("hermes.asset_inventory/v4", "recon"),
        SurfaceMapV4: ("hermes.surface_map/v4", "map"),
        BranchAssessmentV4: ("hermes.branch_operation/v4", "assessment"),
        CrossReviewSetV4: ("hermes.cross_review_set/v4", "cross_review"),
        VerificationOutcomeSetV4: ("hermes.verification_outcome_set/v4", "verification"),
        ReporterAckV4: ("hermes.reporter_acknowledgement/v4", "reporting"),
    }

    @model_validator(mode="after")
    def bound_payload(self) -> ContractEnvelopeV4:
        expected = self._CONTRACTS.get(type(self.payload))
        if expected != (self.contract_id, self.operation):
            raise ValueError("V4 contract ID or operation does not match the payload")
        if self.payload_sha256 != self.payload.digest:
            raise ValueError("V4 payload digest does not match the canonical payload")
        return self

    @classmethod
    def for_payload(cls, payload: ContractPayloadV4) -> ContractEnvelopeV4:
        contract = cls._CONTRACTS.get(type(payload))
        if contract is None:
            raise TypeError(f"unsupported V4 contract payload: {type(payload).__name__}")
        contract_id, operation = contract
        return cls(
            contract_id=contract_id,
            operation=operation,
            payload=payload,
            payload_sha256=payload.digest,
        )


__all__ = [
    "ApprovalBatchV4",
    "AssetInventoryV4",
    "BranchAssessmentV4",
    "BranchCandidateV4",
    "CandidateTypeV4",
    "CompletionV4",
    "ContractEnvelopeV4",
    "CoverageAppendixV4",
    "CoverageFamilySummaryV4",
    "ExecutionBudgetV4",
    "FamilyV4",
    "GateDecisionV4",
    "FindingSetV4",
    "FindingV4",
    "CrossReviewSetV4",
    "PassiveCookiePostureV4",
    "PassivePostureV4",
    "PassiveTlsPostureV4",
    "QualityFamilyMetricsV4",
    "QualityGateReceiptV4",
    "ReporterAckV4",
    "ReporterLaunchReceiptV4",
    "ReportWriteReceiptV4",
    "RunPlanV4",
    "SeverityV4",
    "SignedReviewBatchV4",
    "SurfaceEndpointV4",
    "SurfaceMapV4",
    "VerificationActionV4",
    "VerificationCampaignPlanV4",
    "VerificationOutcomeV4",
    "VerificationOutcomeSetV4",
]
