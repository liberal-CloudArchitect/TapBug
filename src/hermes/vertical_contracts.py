"""Signed Phase 2 validation, approval, consumption, and review contracts."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any, Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .domain_contracts import VerificationPlan
from .runtime.actions import ActionKind, ProposedAction
from .runtime.agents.contracts import EvidenceRef
from .security import KeyUsage, SecurityContractError, TrustStoreV2, canonical_json, sign_ed25519

_DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


class RunPlan(BaseModel):
    """Frozen input and supply-chain identity for one vertical run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1", "2"] = "2"
    run_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    target: str = Field(min_length=1, max_length=2048)
    scope_digest: str = Field(pattern=_DIGEST_PATTERN)
    provider: str = Field(min_length=1, max_length=128)
    model: str = Field(min_length=1, max_length=256)
    roles: tuple[str, ...] = Field(min_length=6, max_length=6)
    prompt_registry_digest: str = Field(pattern=_DIGEST_PATTERN)

    @model_validator(mode="after")
    def exact_roles(self) -> RunPlan:
        required = ("gatekeeper", "recon", "mapper", "web-vuln", "verifier", "reporter")
        if self.roles != required:
            raise ValueError("vertical run must bind the six roles in canonical order")
        return self

    @property
    def digest(self) -> str:
        return _digest(self.model_dump(mode="json"))


class GateDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    decision: Literal["allowed", "blocked"]
    target: str
    resolved_ip: str
    reason: str = Field(min_length=1, max_length=2_000)


class ReconObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    url: str
    status_code: int = Field(ge=100, le=599)
    headers: dict[str, str]
    evidence: EvidenceRef

    @field_validator("headers")
    @classmethod
    def restricted_headers(cls, value: dict[str, str]) -> dict[str, str]:
        allowed = {"content-type", "x-content-type-options", "link"}
        if any(name.lower() not in allowed for name in value):
            raise ValueError("recon observation contains an unrestricted response header")
        return value


class AttackSurface(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    target_url: str
    negative_control_url: str
    source_evidence: EvidenceRef


class WebCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    candidate_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,119}$")
    candidate_type: Literal["missing_x_content_type_options"]
    target_url: str
    negative_control_url: str
    rationale: str = Field(min_length=1, max_length=4_000)
    counterexample: str = Field(min_length=1, max_length=2_000)
    validation_plan: ValidationPlan

    @model_validator(mode="after")
    def plan_is_exact_pair(self) -> WebCandidate:
        actions = self.validation_plan.actions
        if len(actions) != 2:
            raise ValueError("the fixed candidate requires exactly two validation actions")
        targets = (self.target_url, self.negative_control_url)
        for planned, target in zip(actions, targets, strict=True):
            if (
                planned.action.kind is not ActionKind.VALIDATION_HTTP_GET
                or planned.action.method != "GET"
                or planned.action.target != target
                or planned.action.max_requests != 1
            ):
                raise ValueError("validation plan must contain ordered one-shot validation GETs")
        return self


class VerificationOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    outcome_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    candidate_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,119}$")
    run_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    scope_digest: str = Field(pattern=_DIGEST_PATTERN)
    status: Literal["validated", "inconclusive", "blocked"]
    target_evidence: EvidenceRef
    control_evidence: EvidenceRef
    differential_assertion: str = Field(min_length=1, max_length=4_000)
    details: dict[str, Any] = Field(default_factory=dict)

    @property
    def digest(self) -> str:
        return _digest(self.model_dump(mode="json"))


class PlannedAction(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    action_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    action: ProposedAction
    rationale: str = Field(min_length=1, max_length=2_000)


class ValidationPlan(BaseModel):
    """Immutable, run/scope-bound set of actions submitted for review."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"] = "1"
    plan_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    run_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    scope_digest: str = Field(pattern=_DIGEST_PATTERN)
    candidate_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    actions: tuple[PlannedAction, ...] = Field(min_length=1, max_length=100)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime

    @field_validator("created_at", "expires_at")
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("validation plan timestamps must be timezone-aware")
        return value

    @model_validator(mode="after")
    def coherent_plan(self) -> ValidationPlan:
        if self.expires_at <= self.created_at:
            raise ValueError("validation plan must expire after creation")
        ids = [item.action_id for item in self.actions]
        if len(ids) != len(set(ids)):
            raise ValueError("validation plan action IDs must be unique")
        return self

    @property
    def digest(self) -> str:
        return _digest(self.model_dump(mode="json"))


class ActionDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    action_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    decision: Literal["approved", "rejected"]
    rationale: str = Field(min_length=1, max_length=2_000)


class ApprovalBundle(BaseModel):
    """One signature covering an explicit decision for every planned action."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1", "2"] = "1"
    bundle_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    plan_digest: str = Field(pattern=_DIGEST_PATTERN)
    run_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    scope_digest: str = Field(pattern=_DIGEST_PATTERN)
    candidate_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9._-]{1,128}$")
    total_requests: int = Field(default=0, ge=0, le=100)
    approver: str | None = Field(default=None, min_length=1, max_length=200)
    reviewer: str = Field(min_length=1, max_length=200)
    decisions: tuple[ActionDecision, ...] = Field(min_length=1, max_length=100)
    issued_at: datetime
    expires_at: datetime
    key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    signature: str = Field(min_length=1, max_length=512)

    @field_validator("issued_at", "expires_at")
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("approval timestamps must be timezone-aware")
        return value

    @model_validator(mode="after")
    def coherent_bundle(self) -> ApprovalBundle:
        if self.expires_at <= self.issued_at:
            raise ValueError("approval bundle must expire after issuance")
        ids = [item.action_id for item in self.decisions]
        if len(ids) != len(set(ids)):
            raise ValueError("approval decisions must have unique action IDs")
        if self.version == "2" and (
            self.candidate_id is None or self.total_requests != 2 or self.approver is None
        ):
            raise ValueError(
                "version-2 approval requires candidate, approver, and exactly two requests"
            )
        return self

    def signing_payload(self) -> bytes:
        return canonical_json(self.model_dump(mode="json", exclude={"signature"}))

    @property
    def digest(self) -> str:
        return _digest(self.model_dump(mode="json"))


class ApprovalConsumption(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    bundle_id: str
    plan_digest: str = Field(pattern=_DIGEST_PATTERN)
    action_id: str
    action_digest: str = Field(pattern=_DIGEST_PATTERN)
    consumed_at: datetime


class ApprovalConsumptionLedger(BaseModel):
    """Immutable consumption state; callers persist the returned replacement model."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    consumptions: tuple[ApprovalConsumption, ...] = ()

    def contains(self, bundle_id: str, action_id: str) -> bool:
        return any(
            item.bundle_id == bundle_id and item.action_id == action_id
            for item in self.consumptions
        )


def sign_approval_bundle(bundle: ApprovalBundle, private_key: Ed25519PrivateKey) -> ApprovalBundle:
    unsigned = bundle.model_copy(update={"signature": "unsigned"})
    return unsigned.model_copy(
        update={"signature": sign_ed25519(private_key, unsigned.signing_payload())}
    )


def verify_approval_bundle(
    bundle: ApprovalBundle,
    plan: ValidationPlan | VerificationPlan,
    trust_store: TrustStoreV2,
    *,
    at: datetime | None = None,
) -> None:
    instant = at or datetime.now(UTC)
    if instant.tzinfo is None:
        raise SecurityContractError("verification time must be timezone-aware")
    if (
        bundle.plan_digest != plan.digest
        or bundle.run_id != plan.run_id
        or bundle.scope_digest != plan.scope_digest
    ):
        raise SecurityContractError("approval bundle is bound to a different plan, run, or scope")
    if bundle.candidate_id is not None and bundle.candidate_id != plan.candidate_id:
        raise SecurityContractError("approval bundle is bound to a different candidate")
    expected_requests: int
    if isinstance(plan, VerificationPlan):
        expected_requests = int(plan.request_budget)
        planned_ids = {item.action_id for item in plan.steps}
        if bundle.version != "2":
            raise SecurityContractError(
                "a version-2 verification plan requires a version-2 approval"
            )
    else:
        expected_requests = sum(item.action.max_requests for item in plan.actions)
        planned_ids = {item.action_id for item in plan.actions}
    if bundle.total_requests not in {0, expected_requests}:
        raise SecurityContractError("approval bundle request total does not match its plan")
    if instant > plan.expires_at or instant < bundle.issued_at or instant > bundle.expires_at:
        raise SecurityContractError("approval bundle or validation plan is not currently valid")
    decision_ids = {item.action_id for item in bundle.decisions}
    if decision_ids != planned_ids:
        raise SecurityContractError("approval bundle must decide every planned action exactly once")
    trust_store.verify(
        key_id=bundle.key_id,
        usage=KeyUsage.APPROVAL,
        payload=bundle.signing_payload(),
        signature=bundle.signature,
        at=bundle.issued_at,
    )


def consume_approved_action(
    *,
    bundle: ApprovalBundle,
    plan: ValidationPlan | VerificationPlan,
    action_id: str,
    ledger: ApprovalConsumptionLedger,
    trust_store: TrustStoreV2,
    at: datetime | None = None,
) -> ApprovalConsumptionLedger:
    instant = at or datetime.now(UTC)
    verify_approval_bundle(bundle, plan, trust_store, at=instant)
    decision = next((item for item in bundle.decisions if item.action_id == action_id), None)
    if isinstance(plan, VerificationPlan):
        verification_action = next(
            (item for item in plan.steps if item.action_id == action_id), None
        )
        if verification_action is None:
            raise SecurityContractError("action is not part of the signed validation plan")
        action_digest = verification_action.action_digest
    else:
        validation_action = next(
            (item for item in plan.actions if item.action_id == action_id), None
        )
        if validation_action is None:
            raise SecurityContractError("action is not part of the signed validation plan")
        action_digest = validation_action.action.digest
    if decision is None:
        raise SecurityContractError("action is not part of the signed validation plan")
    if decision.decision != "approved":
        raise SecurityContractError("action was rejected and cannot be consumed")
    if ledger.contains(bundle.bundle_id, action_id):
        raise SecurityContractError("approved action was already consumed")
    consumption = ApprovalConsumption(
        bundle_id=bundle.bundle_id,
        plan_digest=plan.digest,
        action_id=action_id,
        action_digest=action_digest,
        consumed_at=instant,
    )
    return ledger.model_copy(update={"consumptions": (*ledger.consumptions, consumption)})


class ApprovalConsumptionV2(BaseModel):
    """Direct link from one approved verification step to its Gateway evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["2"] = "2"
    bundle_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    bundle_digest: str = Field(pattern=_DIGEST_PATTERN)
    plan_digest: str = Field(pattern=_DIGEST_PATTERN)
    run_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    scope_digest: str = Field(pattern=_DIGEST_PATTERN)
    task_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    request_id: str = Field(pattern=r"^[A-Za-z0-9._:-]{1,128}$")
    evidence_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,160}$")
    action_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    action_digest: str = Field(pattern=_DIGEST_PATTERN)
    consumed_at: datetime

    @field_validator("consumed_at")
    @classmethod
    def consumed_at_is_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("approval consumption timestamp must be timezone-aware")
        return value

    @property
    def digest(self) -> str:
        return _digest(self.model_dump(mode="json"))


def consume_approved_action_v2(
    *,
    bundle: ApprovalBundle,
    plan: VerificationPlan,
    action_id: str,
    action: ProposedAction,
    task_id: str,
    request_id: str,
    evidence_id: str,
    prior_consumptions: tuple[ApprovalConsumptionV2, ...],
    trust_store: TrustStoreV2,
    at: datetime | None = None,
) -> ApprovalConsumptionV2:
    """Create the exact consumption a V2 Gateway must bind to its evidence ID."""
    instant = at or datetime.now(UTC)
    verify_approval_bundle(bundle, plan, trust_store, at=instant)
    step = next((item for item in plan.steps if item.action_id == action_id), None)
    decision = next((item for item in bundle.decisions if item.action_id == action_id), None)
    if step is None or decision is None:
        raise SecurityContractError("action is not part of the signed verification plan")
    if decision.decision != "approved":
        raise SecurityContractError("action was rejected and cannot be consumed")
    if step.action_digest != action.digest:
        raise SecurityContractError("Gateway action does not match the signed verification step")
    if any(
        item.bundle_id == bundle.bundle_id and item.action_id == action_id
        for item in prior_consumptions
    ):
        raise SecurityContractError("approved verification action was already consumed")
    if any(item.evidence_id == evidence_id for item in prior_consumptions):
        raise SecurityContractError("Gateway evidence ID was already bound to another consumption")
    return ApprovalConsumptionV2(
        bundle_id=bundle.bundle_id,
        bundle_digest=bundle.digest,
        plan_digest=plan.digest,
        run_id=plan.run_id,
        scope_digest=plan.scope_digest,
        task_id=task_id,
        request_id=request_id,
        evidence_id=evidence_id,
        action_id=action_id,
        action_digest=action.digest,
        consumed_at=instant,
    )


class SignedHumanReview(BaseModel):
    """Human verdict bound to one finding, run, scope, and evidence set."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1", "2"] = "1"
    review_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    finding_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    run_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    scope_digest: str = Field(pattern=_DIGEST_PATTERN)
    evidence_digest: str = Field(pattern=_DIGEST_PATTERN)
    outcome_digest: str | None = Field(default=None, pattern=_DIGEST_PATTERN)
    report_draft_digest: str | None = Field(default=None, pattern=_DIGEST_PATTERN)
    reviewer: str = Field(min_length=1, max_length=200)
    verdict: Literal["accepted", "rejected"]
    rationale: str = Field(min_length=1, max_length=4_000)
    reviewed_at: datetime
    key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    signature: str = Field(min_length=1, max_length=512)

    @field_validator("reviewed_at")
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("review timestamp must be timezone-aware")
        return value

    @model_validator(mode="after")
    def v2_binds_outcome_and_draft(self) -> SignedHumanReview:
        if self.version == "2" and (
            self.outcome_digest is None or self.report_draft_digest is None
        ):
            raise ValueError("version-2 review must bind the outcome and report draft")
        return self

    def signing_payload(self) -> bytes:
        return canonical_json(self.model_dump(mode="json", exclude={"signature"}))

    @property
    def digest(self) -> str:
        return _digest(self.model_dump(mode="json"))


def sign_human_review(
    review: SignedHumanReview, private_key: Ed25519PrivateKey
) -> SignedHumanReview:
    unsigned = review.model_copy(update={"signature": "unsigned"})
    return unsigned.model_copy(
        update={"signature": sign_ed25519(private_key, unsigned.signing_payload())}
    )


def verify_human_review(
    review: SignedHumanReview,
    trust_store: TrustStoreV2,
    *,
    run_id: str,
    scope_digest: str,
    finding_id: str,
    evidence_digest: str,
) -> None:
    if (review.run_id, review.scope_digest, review.finding_id, review.evidence_digest) != (
        run_id,
        scope_digest,
        finding_id,
        evidence_digest,
    ):
        raise SecurityContractError(
            "human review is bound to different evidence or finding context"
        )
    trust_store.verify(
        key_id=review.key_id,
        usage=KeyUsage.HUMAN_REVIEW,
        payload=review.signing_payload(),
        signature=review.signature,
        at=review.reviewed_at,
    )
