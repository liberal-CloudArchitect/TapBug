"""Strict Phase 4 contracts for the parallel V3 collaboration workflow.

The records in this module are deliberately runtime-agnostic.  They bind the
facts needed by routing, fan-out/fan-in, approval, verification and reporting,
but they do not execute agents or network actions themselves.  V2 contracts
remain in :mod:`hermes.domain_contracts` and are never accepted by the V3
handoff envelope.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import ClassVar, Literal, Self
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .domain_contracts import canonical_digest
from .evidence import EvidenceArtifactRef

_DIGEST = r"^sha256:[0-9a-f]{64}$"
_ID = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_CANDIDATE_ID = r"^[a-z0-9][a-z0-9._-]{0,119}$"
_ROLE = r"^[a-z][a-z0-9-]{0,63}$"

Branch = Literal["web", "api", "authz", "infra"]
CandidateTypeV3 = Literal[
    "missing_x_content_type_options",
    "unauthorized_graphql_mutation",
    "privilege_escalation",
    "exposed_debug_endpoint",
    # A candidate whose evidence is a line_kv structure the parent cannot
    # interpret without a learned capability; the Verifier resolves it only via
    # an active, approved CAP-07 Wheel (see hermes.capability_verifier), and it is
    # a coverage gap otherwise. Never emitted by the fixed Phase 4 fixture.
    "line_kv_capability_gap",
]
RiskGroup = Literal["readonly", "mutation", "cleanup"]


def _unique(values: tuple[str, ...], label: str) -> tuple[str, ...]:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")
    return values


def _aware(value: datetime, label: str) -> datetime:
    if value.tzinfo is None:
        raise ValueError(f"{label} must be timezone-aware")
    return value


def _localhost_url(value: str, label: str) -> str:
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
        raise ValueError(f"{label} must declare a loopback fixture port")
    return value


def _loopback_ips(values: tuple[str, ...], label: str) -> tuple[str, ...]:
    _unique(values, label)
    for value in values:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError(f"{label} must contain canonical IP addresses") from exc
        if not address.is_loopback or str(address) != value:
            raise ValueError(f"{label} must contain canonical loopback IP addresses")
    return values


def _digest_tuple(values: tuple[str, ...], label: str) -> tuple[str, ...]:
    _unique(values, label)
    if any(not _is_digest(value) for value in values):
        raise ValueError(f"{label} must contain SHA-256 digests")
    return values


class V3Contract(BaseModel):
    """Closed, immutable base for every new Phase 4 record."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["3"] = "3"

    @property
    def digest(self) -> str:
        return canonical_digest(self)


class RunBoundV3Contract(V3Contract):
    run_id: str = Field(pattern=_ID)
    scope_digest: str = Field(pattern=_DIGEST)
    generated_by_task_id: str = Field(pattern=_ID)


class ExecutionBudgetV3(V3Contract):
    max_concurrency: int = Field(default=4, ge=1, le=4)
    max_model_attempts: int = Field(default=40, ge=1)
    reservation_per_attempt_microusd: int = Field(default=250_000, ge=1)
    max_estimated_cost_microusd: int = Field(default=10_000_000, ge=1)
    max_active_seconds: int = Field(default=1_800, ge=1)
    max_role_seconds: int = Field(default=180, ge=1)

    @model_validator(mode="after")
    def capacity_covers_all_attempts(self) -> Self:
        required = self.max_model_attempts * self.reservation_per_attempt_microusd
        if required > self.max_estimated_cost_microusd:
            raise ValueError("cost cap cannot reserve every permitted model attempt")
        if self.max_role_seconds > self.max_active_seconds:
            raise ValueError("role timeout cannot exceed the active execution deadline")
        return self


class RunPlanV3(V3Contract):
    run_id: str = Field(pattern=_ID)
    target: str = Field(min_length=1, max_length=2_048)
    scope_digest: str = Field(pattern=_DIGEST)
    provider_id: str = Field(pattern=_ID)
    model_id: str = Field(min_length=1, max_length=256)
    prompt_registry_digest: str = Field(pattern=_DIGEST)
    role_manifest_set_digest: str = Field(pattern=_DIGEST)
    roles: tuple[str, ...] = Field(min_length=9)
    identity_binding_digests: dict[str, str] = Field(default_factory=dict)
    budget: ExecutionBudgetV3 = Field(default_factory=ExecutionBudgetV3)
    created_at: datetime

    @field_validator("target")
    @classmethod
    def local_target(cls, value: str) -> str:
        return _localhost_url(value, "V3 target")

    @field_validator("roles")
    @classmethod
    def required_roles(cls, value: tuple[str, ...]) -> tuple[str, ...]:
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
            raise ValueError("V3 run plan must declare the exact nine-role set")
        return value

    @field_validator("identity_binding_digests")
    @classmethod
    def valid_identity_bindings(cls, value: dict[str, str]) -> dict[str, str]:
        if any(not key or not _is_digest(digest) for key, digest in value.items()):
            raise ValueError("identity bindings require non-empty aliases and SHA-256 digests")
        return value

    @field_validator("created_at")
    @classmethod
    def aware_created_at(cls, value: datetime) -> datetime:
        return _aware(value, "run-plan created_at")


def _is_digest(value: str) -> bool:
    return (
        len(value) == 71
        and value.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in value[7:])
    )


class GateDecisionV3(RunBoundV3Contract):
    decision: Literal["allowed", "blocked"]
    target: str = Field(min_length=1, max_length=2_048)
    resolved_ips: tuple[str, ...] = Field(min_length=1)
    reason: str = Field(min_length=1, max_length=2_000)

    @field_validator("target")
    @classmethod
    def local_target(cls, value: str) -> str:
        return _localhost_url(value, "gate target")

    @field_validator("resolved_ips")
    @classmethod
    def unique_ips(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _loopback_ips(value, "resolved IPs")


class AssetV3(V3Contract):
    asset_id: str = Field(pattern=_ID)
    canonical_host: Literal["localhost"] = "localhost"
    scheme: Literal["http", "https"]
    port: int = Field(ge=1, le=65_535)
    resolved_ips: tuple[str, ...] = Field(min_length=1)
    status_code: int = Field(ge=100, le=599)
    content_types: tuple[str, ...] = ()
    observed_relations: tuple[str, ...] = ()
    observed_links: tuple[ObservedLinkV3, ...]

    @field_validator("resolved_ips")
    @classmethod
    def loopback_ips(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _loopback_ips(value, "asset resolved IPs")

    @field_validator("content_types", "observed_relations")
    @classmethod
    def unique_values(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique(value, "asset collections")

    @field_validator("observed_links")
    @classmethod
    def unique_links(cls, value: tuple[ObservedLinkV3, ...]) -> tuple[ObservedLinkV3, ...]:
        _unique(tuple(item.relation for item in value), "observed link relations")
        _unique(tuple(item.canonical_url for item in value), "observed link targets")
        return value


class ObservedLinkV3(V3Contract):
    """A bounded relation target projected from Recon's trusted Link header."""

    relation: Literal["negative-control", "graphql", "role-state", "diagnostic"]
    canonical_url: str = Field(min_length=1, max_length=2_048)

    @field_validator("canonical_url")
    @classmethod
    def local_url(cls, value: str) -> str:
        return _localhost_url(value, "observed relation target")


class AssetInventoryV3(RunBoundV3Contract):
    inventory_id: str = Field(pattern=_ID)
    target: str = Field(min_length=1, max_length=2_048)
    assets: tuple[AssetV3, ...] = Field(min_length=1)
    source_evidence: tuple[EvidenceArtifactRef, ...] = Field(min_length=1)

    @field_validator("target")
    @classmethod
    def local_target(cls, value: str) -> str:
        return _localhost_url(value, "asset inventory target")

    @model_validator(mode="after")
    def unique_assets_and_evidence(self) -> Self:
        _unique(tuple(item.asset_id for item in self.assets), "asset IDs")
        _unique(tuple(item.evidence_id for item in self.source_evidence), "asset evidence IDs")
        return self


class EndpointV3(V3Contract):
    endpoint_id: str = Field(pattern=_ID)
    asset_id: str = Field(pattern=_ID)
    canonical_url: str = Field(min_length=1, max_length=2_048)
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
    relation: Literal[
        "candidate",
        "negative_control",
        "graphql",
        "role_change",
        "debug",
        "diagnostic",
        "cleanup",
        "cleanup_check",
        # A line_kv capability artifact the parent runtime cannot interpret
        # unaided; drives the additive CAP-07 line_kv_capability_gap candidate.
        "capability_config",
    ]
    content_types: tuple[str, ...] = ()
    auth_contexts: tuple[str, ...] = ()
    evidence: tuple[EvidenceArtifactRef, ...] = Field(min_length=1)

    @field_validator("canonical_url")
    @classmethod
    def local_url(cls, value: str) -> str:
        return _localhost_url(value, "endpoint")

    @field_validator("content_types", "auth_contexts")
    @classmethod
    def unique_strings(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique(value, "endpoint collections")


class EndpointInventoryV3(RunBoundV3Contract):
    inventory_id: str = Field(pattern=_ID)
    asset_inventory_digest: str = Field(pattern=_DIGEST)
    endpoints: tuple[EndpointV3, ...] = Field(min_length=1)
    unresolved: tuple[str, ...] = ()

    @model_validator(mode="after")
    def unique_endpoints(self) -> Self:
        _unique(tuple(item.endpoint_id for item in self.endpoints), "endpoint IDs")
        endpoint_keys = tuple(item.canonical_url + "#" + item.method for item in self.endpoints)
        _unique(endpoint_keys, "endpoints")
        return self


class RouteBranchDecision(V3Contract):
    branch: Branch
    routed: bool
    feature_ids: tuple[str, ...] = ()
    reason: str = Field(min_length=1, max_length=2_000)

    @model_validator(mode="after")
    def routed_branch_has_features(self) -> Self:
        _unique(self.feature_ids, "route feature IDs")
        if self.routed and not self.feature_ids:
            raise ValueError("a routed branch requires at least one trusted feature")
        return self


class RouteDecision(RunBoundV3Contract):
    decision_id: str = Field(pattern=_ID)
    endpoint_inventory_digest: str = Field(pattern=_DIGEST)
    available_identity_binding_digests: tuple[str, ...] = ()
    branches: tuple[RouteBranchDecision, ...] = Field(min_length=4, max_length=4)

    @field_validator("available_identity_binding_digests")
    @classmethod
    def unique_identity_digests(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        _unique(value, "identity binding digests")
        if any(not _is_digest(item) for item in value):
            raise ValueError("identity bindings must be SHA-256 digests")
        return value

    @model_validator(mode="after")
    def exact_branch_set(self) -> Self:
        branches = tuple(item.branch for item in self.branches)
        if branches != ("web", "api", "authz", "infra"):
            raise ValueError("route decisions must use canonical web/api/authz/infra order")
        if not any(item.routed for item in self.branches):
            raise ValueError("route decision must select at least one branch")
        return self

    @property
    def routed_branches(self) -> tuple[Branch, ...]:
        return tuple(item.branch for item in self.branches if item.routed)


class BranchCandidateV3(V3Contract):
    candidate_id: str = Field(pattern=_CANDIDATE_ID)
    candidate_type: CandidateTypeV3
    producer_branch: Branch
    target_endpoint_id: str = Field(pattern=_ID)
    control_endpoint_ids: tuple[str, ...] = ()
    target_url: str = Field(min_length=1, max_length=2_048)
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
    request_body_sha256: str | None = Field(default=None, pattern=_DIGEST)
    identity_binding_digest: str | None = Field(default=None, pattern=_DIGEST)
    expected_assertion: str = Field(min_length=1, max_length=2_000)
    rationale: str = Field(min_length=1, max_length=4_000)
    status: Literal["candidate", "blocked", "inconclusive"] = "candidate"
    semantic_fingerprint: str = Field(pattern=_DIGEST)

    @field_validator("target_url")
    @classmethod
    def local_url(cls, value: str) -> str:
        return _localhost_url(value, "candidate target")

    @field_validator("control_endpoint_ids")
    @classmethod
    def unique_controls(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique(value, "control endpoint IDs")

    @model_validator(mode="after")
    def mutation_binding(self) -> Self:
        if self.candidate_type in {"unauthorized_graphql_mutation", "privilege_escalation"}:
            if self.method not in {"POST", "PUT", "PATCH"}:
                raise ValueError("state-changing candidates require a mutation HTTP method")
            if self.request_body_sha256 is None or self.identity_binding_digest is None:
                raise ValueError("state-changing candidates require body and identity bindings")
        return self


class BranchCoverage(V3Contract):
    endpoints_considered: int = Field(ge=0)
    candidates_emitted: int = Field(ge=0)
    candidates_blocked: int = Field(default=0, ge=0)
    candidates_inconclusive: int = Field(default=0, ge=0)
    not_tested_reasons: tuple[str, ...] = ()

    @model_validator(mode="after")
    def explained_gaps(self) -> Self:
        has_gaps = self.candidates_blocked or self.candidates_inconclusive
        if has_gaps and not self.not_tested_reasons:
            raise ValueError("branch coverage gaps require reasons")
        return self


class BranchAssessment(RunBoundV3Contract):
    assessment_id: str = Field(pattern=_ID)
    operation: Literal["assessment"] = "assessment"
    branch: Branch
    endpoint_inventory_digest: str = Field(pattern=_DIGEST)
    prompt_id: str = Field(pattern=r"^[a-z][a-z0-9._/-]{0,127}$")
    prompt_version: str = Field(pattern=r"^3\.[0-9]+$")
    prompt_sha256: str = Field(pattern=_DIGEST)
    candidates: tuple[BranchCandidateV3, ...]
    coverage: BranchCoverage

    @model_validator(mode="after")
    def coherent_candidates(self) -> Self:
        _unique(tuple(item.candidate_id for item in self.candidates), "branch candidate IDs")
        if any(item.producer_branch != self.branch for item in self.candidates):
            raise ValueError("branch assessment may only emit its own branch candidates")
        if self.coverage.candidates_emitted != len(self.candidates):
            raise ValueError("branch coverage candidate count must match emitted candidates")
        if self.coverage.candidates_blocked != sum(
            item.status == "blocked" for item in self.candidates
        ):
            raise ValueError("branch coverage blocked count must match emitted candidates")
        if self.coverage.candidates_inconclusive != sum(
            item.status == "inconclusive" for item in self.candidates
        ):
            raise ValueError("branch coverage inconclusive count must match emitted candidates")
        return self


class BranchResult(RunBoundV3Contract):
    branch: Branch
    status: Literal["succeeded", "failed", "timed_out", "not_routed"]
    assessment_digest: str | None = Field(default=None, pattern=_DIGEST)
    provider_metadata_digest: str | None = Field(default=None, pattern=_DIGEST)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    reason: str | None = Field(default=None, max_length=2_000)

    @field_validator("started_at", "finished_at")
    @classmethod
    def aware_times(cls, value: datetime | None) -> datetime | None:
        return None if value is None else _aware(value, "branch timestamp")

    @model_validator(mode="after")
    def coherent_result(self) -> Self:
        if self.status == "succeeded":
            if self.assessment_digest is None or self.provider_metadata_digest is None:
                raise ValueError("successful branch requires assessment and provider metadata")
        elif self.assessment_digest is not None:
            raise ValueError("non-successful branch cannot publish an assessment")
        if self.status == "not_routed":
            if self.started_at is not None or self.finished_at is not None:
                raise ValueError("an unrouted branch cannot have execution timestamps")
        else:
            if self.started_at is None or self.finished_at is None:
                raise ValueError("an attempted branch requires start and finish timestamps")
            if self.finished_at < self.started_at:
                raise ValueError("branch finish cannot precede branch start")
        if self.status != "succeeded" and not self.reason:
            raise ValueError("non-successful branch requires a reason")
        return self


class DedupDecision(V3Contract):
    canonical_candidate_id: str = Field(pattern=_CANDIDATE_ID)
    semantic_fingerprint: str = Field(pattern=_DIGEST)
    merged_candidate_ids: tuple[str, ...] = Field(min_length=1)
    provenance: tuple[Branch, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def coherent_merge(self) -> Self:
        _unique(self.merged_candidate_ids, "merged candidate IDs")
        _unique(self.provenance, "candidate provenance")
        if self.canonical_candidate_id not in self.merged_candidate_ids:
            raise ValueError("canonical candidate must be one of the merged candidates")
        return self


class CanonicalCandidateV3(V3Contract):
    candidate_id: str = Field(pattern=_CANDIDATE_ID)
    candidate_type: CandidateTypeV3
    semantic_fingerprint: str = Field(pattern=_DIGEST)
    provenance: tuple[Branch, ...] = Field(min_length=1)
    source_candidate_ids: tuple[str, ...] = Field(min_length=1)
    status: Literal["candidate", "blocked", "inconclusive"] = "candidate"

    @model_validator(mode="after")
    def unique_sources(self) -> Self:
        _unique(self.provenance, "canonical candidate provenance")
        _unique(self.source_candidate_ids, "canonical candidate sources")
        return self


class CandidateCollection(RunBoundV3Contract):
    collection_id: str = Field(pattern=_ID)
    route_decision_digest: str = Field(pattern=_DIGEST)
    branch_result_digests: tuple[str, ...] = Field(min_length=4, max_length=4)
    raw_candidates: tuple[BranchCandidateV3, ...]
    canonical_candidates: tuple[CanonicalCandidateV3, ...]
    dedup_decisions: tuple[DedupDecision, ...]
    raw_blocked_or_inconclusive: int = Field(default=0, ge=0)

    @field_validator("branch_result_digests")
    @classmethod
    def valid_branch_result_digests(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _digest_tuple(value, "branch result digests")

    @model_validator(mode="after")
    def conserved_candidates(self) -> Self:
        _unique(tuple(item.candidate_id for item in self.raw_candidates), "raw candidate IDs")
        _unique(
            tuple(item.candidate_id for item in self.canonical_candidates),
            "canonical candidate IDs",
        )
        fingerprints = tuple(item.semantic_fingerprint for item in self.canonical_candidates)
        _unique(fingerprints, "canonical candidate fingerprints")
        observed_gaps = sum(item.status != "candidate" for item in self.raw_candidates)
        if self.raw_blocked_or_inconclusive != observed_gaps:
            raise ValueError("raw candidate gap count must match candidate statuses")
        merged = sum(len(item.merged_candidate_ids) - 1 for item in self.dedup_decisions)
        if len(self.raw_candidates) != (
            len(self.canonical_candidates) + merged + self.raw_blocked_or_inconclusive
        ):
            raise ValueError(
                "raw candidate count must conserve canonical, duplicate, and gap counts"
            )
        canonical_ids = {item.candidate_id for item in self.canonical_candidates}
        if {item.canonical_candidate_id for item in self.dedup_decisions} != canonical_ids:
            raise ValueError("every canonical candidate requires exactly one dedup decision")
        canonical_by_id = {item.candidate_id: item for item in self.canonical_candidates}
        raw_by_id = {item.candidate_id: item for item in self.raw_candidates}
        merged_ids: list[str] = []
        for decision in self.dedup_decisions:
            canonical = canonical_by_id[decision.canonical_candidate_id]
            if (
                canonical.semantic_fingerprint != decision.semantic_fingerprint
                or canonical.source_candidate_ids != decision.merged_candidate_ids
                or canonical.provenance != decision.provenance
            ):
                raise ValueError("dedup decision does not match its canonical candidate")
            for source_id in decision.merged_candidate_ids:
                source = raw_by_id.get(source_id)
                if source is None or source.status != "candidate":
                    raise ValueError("dedup source must identify an actionable raw candidate")
                if source.semantic_fingerprint != decision.semantic_fingerprint:
                    raise ValueError("dedup sources must share the canonical fingerprint")
                if source.producer_branch not in decision.provenance:
                    raise ValueError("dedup source branch must appear in provenance")
                merged_ids.append(source_id)
        actionable_ids = {
            item.candidate_id for item in self.raw_candidates if item.status == "candidate"
        }
        if len(merged_ids) != len(set(merged_ids)) or set(merged_ids) != actionable_ids:
            raise ValueError("dedup decisions must partition every actionable raw candidate")
        return self


class CrossReview(V3Contract):
    review_id: str = Field(pattern=_ID)
    candidate_id: str = Field(pattern=_CANDIDATE_ID)
    producer_branches: tuple[Branch, ...] = Field(min_length=1)
    reviewer_branch: Branch
    reviewer_task_id: str = Field(pattern=_ID)
    verdict: Literal["concur", "reject", "needs_more_evidence"]
    rationale: str = Field(min_length=1, max_length=4_000)

    @model_validator(mode="after")
    def independent_review(self) -> Self:
        _unique(self.producer_branches, "producer branches")
        if self.reviewer_branch in self.producer_branches:
            raise ValueError("cross review must not be performed by a producer branch")
        return self


class CrossReviewSet(RunBoundV3Contract):
    review_set_id: str = Field(pattern=_ID)
    operation: Literal["cross_review"] = "cross_review"
    candidate_collection_digest: str = Field(pattern=_DIGEST)
    reviews: tuple[CrossReview, ...]

    @model_validator(mode="after")
    def one_review_per_candidate(self) -> Self:
        _unique(tuple(item.review_id for item in self.reviews), "cross-review IDs")
        _unique(tuple(item.candidate_id for item in self.reviews), "cross-reviewed candidate IDs")
        _unique(tuple(item.reviewer_task_id for item in self.reviews), "cross-review task IDs")
        return self


class VerificationActionV3(V3Contract):
    action_id: str = Field(pattern=_ID)
    candidate_id: str = Field(pattern=_CANDIDATE_ID)
    candidate_consumers: tuple[str, ...] = Field(min_length=1)
    purpose: Literal["baseline", "candidate", "negative_control", "cleanup", "cleanup_check"]
    risk_group: RiskGroup
    action_kind: Literal["validation_http_get", "validation_http_request"]
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
    target_url: str = Field(min_length=1, max_length=2_048)
    body_sha256: str | None = Field(default=None, pattern=_DIGEST)
    identity_binding_digest: str | None = Field(default=None, pattern=_DIGEST)
    action_digest: str = Field(pattern=_DIGEST)
    depends_on: tuple[str, ...] = ()
    cleanup_of: str | None = Field(default=None, pattern=_ID)
    request_budget: Literal[1] = 1

    @field_validator("target_url")
    @classmethod
    def local_url(cls, value: str) -> str:
        return _localhost_url(value, "verification action target")

    @field_validator("candidate_consumers", "depends_on")
    @classmethod
    def unique_references(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique(value, "verification action references")

    @model_validator(mode="after")
    def coherent_action(self) -> Self:
        if self.candidate_id not in self.candidate_consumers:
            raise ValueError("primary candidate must be an action consumer")
        if self.purpose in {"cleanup", "cleanup_check"} and self.risk_group not in {
            "mutation",
            "cleanup",
        }:
            raise ValueError("cleanup actions cannot be read-only")
        if self.purpose == "cleanup" and self.cleanup_of is None:
            raise ValueError("cleanup action must identify the forward action")
        if self.risk_group in {"mutation", "cleanup"} and self.identity_binding_digest is None:
            raise ValueError("state-changing actions require an identity binding")
        expected_kind = "validation_http_get" if self.method == "GET" else "validation_http_request"
        if self.action_kind != expected_kind:
            raise ValueError("verification action kind must match its HTTP method")
        return self


class VerificationCampaignPlan(RunBoundV3Contract):
    campaign_id: str = Field(pattern=_ID)
    candidate_collection_digest: str = Field(pattern=_DIGEST)
    cross_review_set_digest: str = Field(pattern=_DIGEST)
    actions: tuple[VerificationActionV3, ...]
    request_budget: int = Field(ge=0, le=14)
    created_at: datetime
    expires_at: datetime

    @field_validator("created_at", "expires_at")
    @classmethod
    def aware_times(cls, value: datetime) -> datetime:
        return _aware(value, "campaign timestamp")

    @model_validator(mode="after")
    def valid_action_graph(self) -> Self:
        action_ids = tuple(item.action_id for item in self.actions)
        action_digests = tuple(item.action_digest for item in self.actions)
        _unique(action_ids, "campaign action IDs")
        _unique(action_digests, "campaign action digests")
        if self.request_budget != sum(item.request_budget for item in self.actions):
            raise ValueError("campaign request budget must equal action budgets")
        known = set(action_ids)
        for action in self.actions:
            if any(dependency not in known for dependency in action.depends_on):
                raise ValueError("action dependency is outside the campaign")
            if action.cleanup_of is not None and action.cleanup_of not in known:
                raise ValueError("cleanup target is outside the campaign")
            if action.action_id in action.depends_on:
                raise ValueError("action cannot depend on itself")
        if self.expires_at <= self.created_at:
            raise ValueError("campaign must expire after creation")
        return self


class ApprovalBatchV3(RunBoundV3Contract):
    approval_id: str = Field(pattern=_ID)
    campaign_digest: str = Field(pattern=_DIGEST)
    risk_group: RiskGroup
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
    def unique_items(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique(value, "approval batch bindings")

    @field_validator("signed_at", "expires_at")
    @classmethod
    def aware_times(cls, value: datetime) -> datetime:
        return _aware(value, "approval timestamp")

    @model_validator(mode="after")
    def coherent_approval(self) -> Self:
        if self.expires_at <= self.signed_at:
            raise ValueError("approval must expire after signature")
        if self.verdict == "approved" and (not self.candidate_ids or not self.action_digests):
            raise ValueError("approved batch requires candidates and actions")
        if any(not _is_digest(item) for item in self.action_digests):
            raise ValueError("approved actions must use SHA-256 digests")
        return self


class ActionLedgerEntry(RunBoundV3Contract):
    ledger_entry_id: str = Field(pattern=_ID)
    sequence: int = Field(ge=1)
    previous_entry_digest: str | None = Field(default=None, pattern=_DIGEST)
    action_id: str = Field(pattern=_ID)
    action_digest: str = Field(pattern=_DIGEST)
    action_fingerprint: str = Field(pattern=_DIGEST)
    candidate_consumers: tuple[str, ...] = Field(min_length=1)
    state: Literal[
        "planned",
        "reserved",
        "transport_started",
        "evidence_committed",
        "failed_before_transport",
        "failed_after_transport",
        "indeterminate",
        "cleanup_required",
        "cleaned",
    ]
    approval_batch_digest: str | None = Field(default=None, pattern=_DIGEST)
    consumption_digest: str | None = Field(default=None, pattern=_DIGEST)
    evidence: EvidenceArtifactRef | None = None
    occurred_at: datetime

    @field_validator("candidate_consumers")
    @classmethod
    def unique_consumers(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique(value, "action consumers")

    @field_validator("occurred_at")
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        return _aware(value, "ledger timestamp")

    @model_validator(mode="after")
    def state_bindings(self) -> Self:
        if self.sequence == 1 and self.previous_entry_digest is not None:
            raise ValueError("first ledger entry cannot have a predecessor")
        if self.sequence > 1 and self.previous_entry_digest is None:
            raise ValueError("non-first ledger entry requires a predecessor digest")
        if self.state == "evidence_committed" and self.evidence is None:
            raise ValueError("committed action requires evidence")
        if self.evidence is not None and self.state != "evidence_committed":
            raise ValueError("only evidence_committed entries may bind evidence")
        if (self.approval_batch_digest is None) != (self.consumption_digest is None):
            raise ValueError("approval and consumption ledger bindings are atomic")
        return self


class BudgetLedgerEntry(RunBoundV3Contract):
    ledger_entry_id: str = Field(pattern=_ID)
    sequence: int = Field(ge=1)
    previous_entry_digest: str | None = Field(default=None, pattern=_DIGEST)
    task_id: str = Field(pattern=_ID)
    role: str = Field(pattern=_ROLE)
    attempt_number: int = Field(ge=1, le=40)
    event: Literal["reserved", "reconciled", "released", "rejected"]
    reserved_microusd: int = Field(ge=0)
    actual_cost_microusd: int | None = Field(default=None, ge=0)
    token_usage: int | None = Field(default=None, ge=0)
    occurred_at: datetime

    @field_validator("occurred_at")
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        return _aware(value, "budget ledger timestamp")

    @model_validator(mode="after")
    def coherent_event(self) -> Self:
        if self.sequence == 1 and self.previous_entry_digest is not None:
            raise ValueError("first budget entry cannot have a predecessor")
        if self.sequence > 1 and self.previous_entry_digest is None:
            raise ValueError("non-first budget entry requires a predecessor")
        if self.event == "reserved" and self.reserved_microusd <= 0:
            raise ValueError("budget reservation must be positive")
        if self.event != "reconciled" and self.actual_cost_microusd is not None:
            raise ValueError("only reconciled entries may record actual cost")
        return self


class VerificationCandidateOutcome(V3Contract):
    outcome_id: str = Field(pattern=_ID)
    candidate_id: str = Field(pattern=_CANDIDATE_ID)
    verifier_task_id: str = Field(pattern=_ID)
    status: Literal["validated", "disproved", "inconclusive", "blocked"]
    action_digests: tuple[str, ...]
    action_ledger_entry_digests: tuple[str, ...]
    evidence: tuple[EvidenceArtifactRef, ...]
    assertion_summary: str = Field(min_length=1, max_length=4_000)

    @field_validator("action_digests", "action_ledger_entry_digests")
    @classmethod
    def valid_digest_collections(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _digest_tuple(value, "outcome digest references")

    @model_validator(mode="after")
    def aligned_execution_refs(self) -> Self:
        _unique(self.action_digests, "outcome action digests")
        _unique(self.action_ledger_entry_digests, "outcome ledger entries")
        _unique(tuple(item.evidence_id for item in self.evidence), "outcome evidence")
        counts = {
            len(self.action_digests),
            len(self.action_ledger_entry_digests),
            len(self.evidence),
        }
        if self.status in {"validated", "disproved"} and (len(counts) != 1 or not self.evidence):
            raise ValueError("tested outcome requires aligned action, ledger, and evidence refs")
        return self


class VerificationOutcomeSet(RunBoundV3Contract):
    outcome_set_id: str = Field(pattern=_ID)
    campaign_digest: str = Field(pattern=_DIGEST)
    approval_batch_digests: tuple[str, ...]
    outcomes: tuple[VerificationCandidateOutcome, ...]

    @field_validator("approval_batch_digests")
    @classmethod
    def valid_approval_digests(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _digest_tuple(value, "outcome approval batches")

    @model_validator(mode="after")
    def unique_outcomes(self) -> Self:
        _unique(self.approval_batch_digests, "outcome approval batches")
        _unique(tuple(item.outcome_id for item in self.outcomes), "outcome IDs")
        _unique(tuple(item.candidate_id for item in self.outcomes), "outcome candidate IDs")
        _unique(tuple(item.verifier_task_id for item in self.outcomes), "verifier task IDs")
        return self


class CleanupActionResult(V3Contract):
    forward_action_digest: str = Field(pattern=_DIGEST)
    cleanup_action_digest: str = Field(pattern=_DIGEST)
    cleanup_check_action_digest: str = Field(pattern=_DIGEST)
    status: Literal["cleaned", "cleanup_required", "indeterminate"]
    evidence: tuple[EvidenceArtifactRef, ...] = ()

    @model_validator(mode="after")
    def cleaned_has_evidence(self) -> Self:
        if self.status == "cleaned" and len(self.evidence) < 2:
            raise ValueError("cleaned mutation requires cleanup and cleanup-check evidence")
        return self


class CleanupReceipt(RunBoundV3Contract):
    receipt_id: str = Field(pattern=_ID)
    campaign_digest: str = Field(pattern=_DIGEST)
    results: tuple[CleanupActionResult, ...]
    initial_state_sha256: str = Field(pattern=_DIGEST)
    final_state_sha256: str | None = Field(default=None, pattern=_DIGEST)
    state_restored: bool
    completed_at: datetime

    @field_validator("completed_at")
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        return _aware(value, "cleanup completion")

    @model_validator(mode="after")
    def coherent_restoration(self) -> Self:
        if self.state_restored:
            if self.final_state_sha256 != self.initial_state_sha256:
                raise ValueError("restored cleanup must return to the initial state hash")
            if any(item.status != "cleaned" for item in self.results):
                raise ValueError("restored cleanup cannot contain unresolved actions")
        elif self.final_state_sha256 == self.initial_state_sha256:
            raise ValueError("matching state hashes must be marked restored")
        return self


class FindingV3(V3Contract):
    finding_id: str = Field(pattern=_CANDIDATE_ID)
    candidate_id: str = Field(pattern=_CANDIDATE_ID)
    candidate_type: CandidateTypeV3
    verification_outcome_digest: str = Field(pattern=_DIGEST)
    cross_review_digest: str = Field(pattern=_DIGEST)
    evidence: tuple[EvidenceArtifactRef, ...] = Field(min_length=1)
    title: str = Field(min_length=1, max_length=240)
    summary: str = Field(min_length=1, max_length=4_000)
    severity: Literal["informational", "low", "medium", "high", "critical"]
    local_teaching_fixture: Literal[True] = True

    @model_validator(mode="after")
    def finding_matches_candidate(self) -> Self:
        if self.finding_id != self.candidate_id:
            raise ValueError("finding ID must equal its canonical candidate ID")
        _unique(tuple(item.evidence_id for item in self.evidence), "finding evidence")
        return self


class FindingSet(RunBoundV3Contract):
    finding_set_id: str = Field(pattern=_ID)
    candidate_collection_digest: str = Field(pattern=_DIGEST)
    cross_review_set_digest: str = Field(pattern=_DIGEST)
    verification_outcome_set_digest: str = Field(pattern=_DIGEST)
    cleanup_receipt_digest: str | None = Field(default=None, pattern=_DIGEST)
    findings: tuple[FindingV3, ...]

    @model_validator(mode="after")
    def unique_findings(self) -> Self:
        _unique(tuple(item.finding_id for item in self.findings), "finding IDs")
        return self


class CoverageReportV3(RunBoundV3Contract):
    report_id: str = Field(pattern=_ID)
    route_decision_digest: str = Field(pattern=_DIGEST)
    candidate_collection_digest: str = Field(pattern=_DIGEST)
    cross_review_set_digest: str = Field(pattern=_DIGEST)
    campaign_digest: str = Field(pattern=_DIGEST)
    outcome_set_digest: str = Field(pattern=_DIGEST)
    finding_set_digest: str = Field(pattern=_DIGEST)
    cleanup_receipt_digest: str | None = Field(default=None, pattern=_DIGEST)
    branches_routed: int = Field(ge=1, le=4)
    branches_succeeded: int = Field(ge=0, le=4)
    branches_failed: int = Field(ge=0, le=4)
    branches_timed_out: int = Field(ge=0, le=4)
    raw_candidates: int = Field(ge=0)
    canonical_candidates: int = Field(ge=0)
    duplicate_candidates: int = Field(ge=0)
    raw_blocked_or_inconclusive: int = Field(ge=0)
    candidates_validated: int = Field(ge=0)
    candidates_disproved: int = Field(ge=0)
    candidates_inconclusive: int = Field(ge=0)
    candidates_blocked: int = Field(ge=0)
    actions_planned: int = Field(ge=0, le=14)
    actions_executed: int = Field(ge=0, le=14)
    actions_blocked: int = Field(ge=0, le=14)
    actions_skipped: int = Field(ge=0, le=14)
    requests_planned: int = Field(ge=1, le=15)
    requests_used: int = Field(ge=1, le=15)
    model_attempts_reserved: int = Field(ge=1, le=40)
    model_attempts_used: int = Field(ge=1, le=40)
    estimated_cost_microusd: int = Field(ge=0, le=10_000_000)
    actual_cost_microusd: int | None = Field(default=None, ge=0)
    active_elapsed_ms: int = Field(ge=1, le=1_800_000)
    completion: Literal["completed", "completed_with_gaps"]
    gaps: tuple[str, ...] = ()

    @model_validator(mode="after")
    def conserved_counts(self) -> Self:
        _unique(self.gaps, "coverage gaps")
        if self.branches_routed != (
            self.branches_succeeded + self.branches_failed + self.branches_timed_out
        ):
            raise ValueError("routed branches must conserve success, failure, and timeout counts")
        if self.raw_candidates != (
            self.canonical_candidates + self.duplicate_candidates + self.raw_blocked_or_inconclusive
        ):
            raise ValueError("raw candidates must conserve canonical, duplicate, and gap counts")
        if self.canonical_candidates != (
            self.candidates_validated
            + self.candidates_disproved
            + self.candidates_inconclusive
            + self.candidates_blocked
        ):
            raise ValueError("canonical candidate counts must be conserved")
        if self.actions_planned != (
            self.actions_executed + self.actions_blocked + self.actions_skipped
        ):
            raise ValueError("planned actions must conserve executed, blocked, and skipped counts")
        if self.requests_used > self.requests_planned:
            raise ValueError("used requests cannot exceed planned requests")
        if self.model_attempts_used > self.model_attempts_reserved:
            raise ValueError("used model attempts cannot exceed reservations")
        if self.candidates_validated < 1:
            raise ValueError("a completed V3 report requires at least one validated candidate")
        if self.completion == "completed_with_gaps" and not self.gaps:
            raise ValueError("completed_with_gaps requires exact coverage gaps")
        if self.completion == "completed" and self.gaps:
            raise ValueError("a fully completed report cannot contain coverage gaps")
        return self


class SignedReviewBatchV3(RunBoundV3Contract):
    review_id: str = Field(pattern=_ID)
    finding_set_digest: str = Field(pattern=_DIGEST)
    coverage_report_digest: str = Field(pattern=_DIGEST)
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
        _unique(value, "review gap digests")
        if any(not _is_digest(item) for item in value):
            raise ValueError("review gaps must be represented by SHA-256 digests")
        return value

    @field_validator("reviewed_at")
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        return _aware(value, "review timestamp")

    @model_validator(mode="after")
    def coherent_verdict(self) -> Self:
        if self.verdict == "accepted_with_gaps" and not self.gap_digests:
            raise ValueError("accepted_with_gaps requires exact gap digests")
        if self.verdict == "accepted" and self.gap_digests:
            raise ValueError("accepted review cannot carry gaps")
        return self


class ReporterLaunchReceiptV3(RunBoundV3Contract):
    receipt_id: str = Field(pattern=_ID)
    finding_set_digest: str = Field(pattern=_DIGEST)
    coverage_report_digest: str = Field(pattern=_DIGEST)
    signed_review_digest: str = Field(pattern=_DIGEST)
    action_ledger_head_digest: str = Field(pattern=_DIGEST)
    budget_ledger_head_digest: str = Field(pattern=_DIGEST)
    reporter_budget_reservation_digest: str = Field(pattern=_DIGEST)
    verifier_schema_version: Literal["3"] = "3"
    verified_at: datetime

    @field_validator("verified_at")
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        return _aware(value, "launch preflight timestamp")


class ReporterAckV3(RunBoundV3Contract):
    launch_receipt_digest: str = Field(pattern=_DIGEST)
    finding_set_digest: str = Field(pattern=_DIGEST)
    coverage_report_digest: str = Field(pattern=_DIGEST)
    provider_metadata_digest: str = Field(pattern=_DIGEST)
    accepted: Literal[True] = True


class ReportWriteReceiptV3(RunBoundV3Contract):
    receipt_id: str = Field(pattern=_ID)
    launch_receipt_digest: str = Field(pattern=_DIGEST)
    reporter_ack_digest: str = Field(pattern=_DIGEST)
    final_budget_ledger_head_digest: str = Field(pattern=_DIGEST)
    report_sha256: str = Field(pattern=_DIGEST)
    findings_sha256: str = Field(pattern=_DIGEST)
    written_at: datetime

    @field_validator("written_at")
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        return _aware(value, "report-write timestamp")


ContractPayloadV3 = (
    GateDecisionV3
    | AssetInventoryV3
    | EndpointInventoryV3
    | BranchAssessment
    | CrossReviewSet
    | VerificationOutcomeSet
    | ReporterAckV3
)
ContractIdV3 = Literal[
    "hermes.gate_decision/v3",
    "hermes.asset_inventory/v3",
    "hermes.endpoint_inventory/v3",
    "hermes.branch_assessment/v3",
    "hermes.cross_review_set/v3",
    "hermes.verification_outcome_set/v3",
    "hermes.reporter_acknowledgement/v3",
]
ContractOperationV3 = Literal[
    "gate",
    "recon",
    "map",
    "assessment",
    "cross_review",
    "verification",
    "reporting",
]


class ContractEnvelopeV3(V3Contract):
    """Hash-bound V3 role output; V2 payloads are outside its closed union."""

    contract_version: Literal["3"] = "3"
    contract_id: ContractIdV3
    operation: ContractOperationV3
    payload: ContractPayloadV3
    payload_sha256: str = Field(pattern=_DIGEST)

    _CONTRACTS: ClassVar[dict[type[V3Contract], tuple[ContractIdV3, ContractOperationV3]]] = {
        GateDecisionV3: ("hermes.gate_decision/v3", "gate"),
        AssetInventoryV3: ("hermes.asset_inventory/v3", "recon"),
        EndpointInventoryV3: ("hermes.endpoint_inventory/v3", "map"),
        BranchAssessment: ("hermes.branch_assessment/v3", "assessment"),
        CrossReviewSet: ("hermes.cross_review_set/v3", "cross_review"),
        VerificationOutcomeSet: ("hermes.verification_outcome_set/v3", "verification"),
        ReporterAckV3: ("hermes.reporter_acknowledgement/v3", "reporting"),
    }

    @model_validator(mode="after")
    def bound_payload(self) -> Self:
        expected = self._CONTRACTS.get(type(self.payload))
        if expected != (self.contract_id, self.operation):
            raise ValueError("V3 contract ID or operation does not match its typed payload")
        if self.payload_sha256 != self.payload.digest:
            raise ValueError("V3 contract payload hash does not match the canonical payload")
        return self

    @classmethod
    def for_payload(cls, payload: ContractPayloadV3) -> ContractEnvelopeV3:
        contract = cls._CONTRACTS.get(type(payload))
        if contract is None:  # pragma: no cover - guarded by the public type
            raise TypeError(f"unsupported V3 contract payload: {type(payload).__name__}")
        contract_id, operation = contract
        return cls(
            contract_id=contract_id,
            operation=operation,
            payload=payload,
            payload_sha256=payload.digest,
        )


# Readable migration alias for callers that place the version before the noun.
V3ContractEnvelope = ContractEnvelopeV3


__all__ = [
    "ActionLedgerEntry",
    "ApprovalBatchV3",
    "AssetInventoryV3",
    "AssetV3",
    "BranchAssessment",
    "BranchCandidateV3",
    "BranchCoverage",
    "BranchResult",
    "BudgetLedgerEntry",
    "CandidateCollection",
    "CanonicalCandidateV3",
    "CleanupActionResult",
    "CleanupReceipt",
    "ContractEnvelopeV3",
    "ContractPayloadV3",
    "CoverageReportV3",
    "CrossReview",
    "CrossReviewSet",
    "DedupDecision",
    "EndpointInventoryV3",
    "EndpointV3",
    "ExecutionBudgetV3",
    "FindingSet",
    "FindingV3",
    "GateDecisionV3",
    "ReportWriteReceiptV3",
    "ReporterAckV3",
    "ReporterLaunchReceiptV3",
    "RouteBranchDecision",
    "RouteDecision",
    "RunPlanV3",
    "SignedReviewBatchV3",
    "V3Contract",
    "V3ContractEnvelope",
    "VerificationActionV3",
    "VerificationCampaignPlan",
    "VerificationCandidateOutcome",
    "VerificationOutcomeSet",
]
