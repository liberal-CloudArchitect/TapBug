"""N4 — minimal, approved, negative-controlled verification of a candidate.

docs/19 node N4. An N3 ``AssetCandidateV1`` is only a hypothesis; it becomes a
``ValidatedFindingV1`` here, and only under Hermes' full discipline:

* **positive/negative control (正反对照).** Verification plans two minimal probes —
  the candidate target and a matched negative control — and a single, structured
  ``VerificationSignalV1``. The verdict is deterministic: *validated* only when the
  candidate exhibits the signal and the control does **not**; *disproved* when the
  candidate does not exhibit it; *inconclusive* when both do (the control is not
  clean, so nothing is distinguished).
* **per-action human approval.** A plan does nothing until a human signs it
  (Ed25519, ``KeyUsage.APPROVAL``); execution is refused otherwise.
* **read-many / write-little, never destructive.** ``DELETE`` is forbidden;
  read-only probes (GET/HEAD/OPTIONS) are the default, and a mutation probe is
  refused unless it carries an explicit compensation plan.
* **scope + budget bound.** Both probe URLs are re-authorized against the N1
  signed scope; the plan is a bounded two-request action.
* **finding only after review.** ``promote_to_finding`` yields a ValidatedFinding
  only from a *validated* outcome that a second human signs off
  (``KeyUsage.HUMAN_REVIEW``) — reviewer ≠ approver is enforceable by the caller.

Scope of this module: the frozen plan/approval/observation/outcome/finding
contracts, the deterministic signal evaluation and verdict, and the fail-closed
guards — fully unit-tested without network. **Actually issuing the two requests**
against a real asset is the live active step: it must go through the governed
Gateway under the approved plan's scope + rate limit, and for real assets the
GOV-02 command/credential broker is still only half-wired (docs/16 node B). This
module plans, gates, and judges; it does not itself make requests.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .candidate_source import AssetCandidateV1, ClaimedSeverity
from .domain_contracts import canonical_digest
from .evidence import EvidenceArtifactRef
from .scope_profile import ScopeProfileDraftV1, ScopeProfileError, authorize_target
from .security import (
    KeyUsage,
    SecurityContractError,
    TrustStoreV2,
    canonical_json,
    sign_ed25519,
)

_ID = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_SLUG = r"^[a-z0-9][a-z0-9._-]{0,119}$"
_DIGEST = r"^sha256:[0-9a-f]{64}$"

# DELETE is deliberately excluded — verification must never be destructive.
ProbeMethod = Literal["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"]
_READONLY_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
RiskGroup = Literal["readonly", "mutation"]
SignalKind = Literal["header_absent", "header_present", "status_equals", "body_contains"]
VerificationVerdict = Literal["validated", "disproved", "inconclusive"]


class VerificationError(RuntimeError):
    """A candidate could not be safely planned, approved, executed, or judged."""


class ProbeSpecV1(BaseModel):
    """One minimal request the verifier will issue (candidate or control)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    url: str = Field(min_length=1, max_length=2_048)
    method: ProbeMethod
    note: str = Field(default="", max_length=500)


class VerificationSignalV1(BaseModel):
    """The single structured observation that decides presence of the condition."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: SignalKind
    argument: str = Field(min_length=1, max_length=500)


class VerificationPlanV1(BaseModel):
    """A bounded, scope-bound, positive/negative-control verification plan."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"] = "1"
    plan_id: str = Field(pattern=_ID)
    candidate_id: str = Field(pattern=_ID)
    program_handle: str = Field(pattern=_ID)
    scope_profile_digest: str = Field(pattern=_DIGEST)
    candidate_type: str = Field(pattern=_SLUG)
    candidate_probe: ProbeSpecV1
    control_probe: ProbeSpecV1
    signal: VerificationSignalV1
    risk_group: RiskGroup
    compensation_plan: str = Field(default="", max_length=2_000)
    max_requests: Literal[2] = 2
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def _tz_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("created_at must be timezone-aware")
        return value

    @model_validator(mode="after")
    def _safe(self) -> VerificationPlanV1:
        for probe in (self.candidate_probe, self.control_probe):
            if probe.method not in _READONLY_METHODS and self.risk_group != "mutation":
                raise ValueError("a write method requires risk_group 'mutation'")
        if self.risk_group == "readonly" and (
            self.candidate_probe.method not in _READONLY_METHODS
            or self.control_probe.method not in _READONLY_METHODS
        ):
            raise ValueError("readonly plans may only use GET/HEAD/OPTIONS")
        if self.risk_group == "mutation" and not self.compensation_plan.strip():
            raise ValueError("mutation verification requires a compensation plan")
        return self

    def digest(self) -> str:
        return canonical_digest(self)


class SignedVerificationApprovalV1(BaseModel):
    """A human's per-action approval of exactly one verification plan."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    plan_digest: str = Field(pattern=_DIGEST)
    approver_key_id: str = Field(pattern=_ID)
    signed_at: datetime
    expires_at: datetime
    signature_b64: str = Field(min_length=16)

    @field_validator("signed_at", "expires_at")
    @classmethod
    def _tz_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("approval timestamps must be timezone-aware")
        return value

    @model_validator(mode="after")
    def _expiry(self) -> SignedVerificationApprovalV1:
        if self.expires_at <= self.signed_at:
            raise ValueError("approval must expire after signature")
        return self


class ProbeObservationV1(BaseModel):
    """What one probe actually returned — the evidence a verdict is computed from."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status_code: int = Field(ge=100, le=599)
    headers: tuple[tuple[str, str], ...] = ()
    body_sha256: str | None = Field(default=None, pattern=_DIGEST)
    body_excerpt: str = Field(default="", max_length=4_000)
    evidence: tuple[EvidenceArtifactRef, ...] = Field(min_length=1)

    def header(self, name: str) -> str | None:
        lname = name.lower()
        for key, value in self.headers:
            if key.lower() == lname:
                return value
        return None


class VerificationOutcomeV1(BaseModel):
    """The deterministic positive/negative-control verdict, bound to its plan."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    verdict: VerificationVerdict
    candidate_id: str = Field(pattern=_ID)
    plan_digest: str = Field(pattern=_DIGEST)
    candidate_exhibits: bool
    control_exhibits: bool
    candidate_evidence: tuple[EvidenceArtifactRef, ...] = Field(min_length=1)
    control_evidence: tuple[EvidenceArtifactRef, ...] = Field(min_length=1)
    rationale: str = Field(min_length=1, max_length=2_000)
    decided_at: datetime

    def digest(self) -> str:
        return canonical_digest(self)


class ValidatedFindingV1(BaseModel):
    """A validated, human-reviewed finding — the only thing eligible for a report."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: str = Field(pattern=_ID)
    candidate_id: str = Field(pattern=_ID)
    program_handle: str = Field(pattern=_ID)
    target_url: str = Field(min_length=1, max_length=2_048)
    candidate_type: str = Field(pattern=_SLUG)
    claimed_severity: ClaimedSeverity
    plan_digest: str = Field(pattern=_DIGEST)
    outcome_digest: str = Field(pattern=_DIGEST)
    reviewer_key_id: str = Field(pattern=_ID)
    reviewed_at: datetime

    def digest(self) -> str:
        return canonical_digest(self)


# --------------------------------------------------------------------------- #
# Planning
# --------------------------------------------------------------------------- #


def _default_risk_group(method: str) -> RiskGroup:
    return "readonly" if method in _READONLY_METHODS else "mutation"


def build_verification_plan(
    candidate: AssetCandidateV1,
    *,
    program_handle: str,
    signal: VerificationSignalV1,
    negative_control_url: str,
    scope_draft: ScopeProfileDraftV1,
    now: datetime,
    risk_group: RiskGroup | None = None,
    compensation_plan: str = "",
    control_method: ProbeMethod | None = None,
) -> VerificationPlanV1:
    """Plan a minimal, scope-bound, positive/negative-control verification.

    Both the candidate URL and the control URL are re-authorized against the N1
    signed scope (fail-closed); DELETE is refused; a mutation probe requires a
    compensation plan.
    """

    if candidate.method == "DELETE":  # pragma: no cover - candidate methods exclude DELETE
        raise VerificationError("verification must never use DELETE")
    for url in (candidate.target_url, negative_control_url):
        try:
            authorize_target(scope_draft, url)
        except ScopeProfileError as exc:
            raise VerificationError(f"verification target outside signed scope: {exc}") from exc

    method: ProbeMethod = candidate.method
    resolved_risk = risk_group or _default_risk_group(method)
    plan_id = "vplan-" + candidate.candidate_id.removeprefix("cand-")[:24]
    try:
        return VerificationPlanV1(
            plan_id=plan_id,
            candidate_id=candidate.candidate_id,
            program_handle=program_handle,
            scope_profile_digest=scope_draft.digest(),
            candidate_type=candidate.candidate_type,
            candidate_probe=ProbeSpecV1(url=candidate.target_url, method=method, note="candidate"),
            control_probe=ProbeSpecV1(
                url=negative_control_url, method=control_method or method, note="negative-control"
            ),
            signal=signal,
            risk_group=resolved_risk,
            compensation_plan=compensation_plan,
            created_at=now,
        )
    except ValueError as exc:
        raise VerificationError(str(exc)) from exc


# --------------------------------------------------------------------------- #
# Approval
# --------------------------------------------------------------------------- #


def sign_verification_plan(
    plan: VerificationPlanV1,
    private_key: Ed25519PrivateKey,
    *,
    key_id: str,
    signed_at: datetime,
    ttl: timedelta = timedelta(hours=8),
) -> SignedVerificationApprovalV1:
    """Produce a human's per-action approval of exactly this plan."""

    if signed_at.tzinfo is None:
        raise VerificationError("signed_at must be timezone-aware")
    payload = canonical_json({"plan_digest": plan.digest()})
    return SignedVerificationApprovalV1(
        plan_digest=plan.digest(),
        approver_key_id=key_id,
        signed_at=signed_at,
        expires_at=signed_at + ttl,
        signature_b64=sign_ed25519(private_key, payload),
    )


def require_execution_authorized(
    plan: VerificationPlanV1,
    approval: SignedVerificationApprovalV1,
    trust_store: TrustStoreV2,
    scope_draft: ScopeProfileDraftV1,
    *,
    now: datetime,
) -> None:
    """Fail-closed gate before the two probes may be issued.

    Requires: the approval matches this exact plan, is unexpired, and is signed by
    a key trusted for APPROVAL; and both probe URLs are still in the signed scope.
    """

    if approval.plan_digest != plan.digest():
        raise VerificationError("approval does not match the plan it is presented with")
    if now >= approval.expires_at:
        raise VerificationError("verification approval has expired")
    try:
        trust_store.verify(
            key_id=approval.approver_key_id,
            usage=KeyUsage.APPROVAL,
            payload=canonical_json({"plan_digest": plan.digest()}),
            signature=approval.signature_b64,
            at=approval.signed_at,
        )
    except SecurityContractError as exc:
        raise VerificationError(f"verification approval is not trusted: {exc}") from exc
    for probe in (plan.candidate_probe, plan.control_probe):
        try:
            authorize_target(scope_draft, probe.url)
        except ScopeProfileError as exc:
            raise VerificationError(f"probe target left the signed scope: {exc}") from exc


# --------------------------------------------------------------------------- #
# Deterministic signal + verdict (正反对照)
# --------------------------------------------------------------------------- #


def evaluate_signal(observation: ProbeObservationV1, signal: VerificationSignalV1) -> bool:
    """Deterministically decide whether an observation exhibits the signal."""

    if signal.kind == "header_absent":
        return observation.header(signal.argument) is None
    if signal.kind == "header_present":
        return observation.header(signal.argument) is not None
    if signal.kind == "status_equals":
        try:
            return observation.status_code == int(signal.argument)
        except ValueError:
            return False
    # body_contains
    return signal.argument in observation.body_excerpt


def decide_verification(
    plan: VerificationPlanV1,
    candidate_observation: ProbeObservationV1,
    control_observation: ProbeObservationV1,
    *,
    now: datetime,
) -> VerificationOutcomeV1:
    """Compute the positive/negative-control verdict from the two observations.

    validated  = candidate exhibits the signal AND control does not;
    disproved  = candidate does not exhibit the signal;
    inconclusive = both exhibit it (the control is not clean).
    """

    candidate_exhibits = evaluate_signal(candidate_observation, plan.signal)
    control_exhibits = evaluate_signal(control_observation, plan.signal)
    if not candidate_exhibits:
        verdict: VerificationVerdict = "disproved"
        rationale = "candidate did not exhibit the signal under a minimal request"
    elif control_exhibits:
        verdict = "inconclusive"
        rationale = "negative control also exhibited the signal; nothing is distinguished"
    else:
        verdict = "validated"
        rationale = "candidate exhibits the signal and the matched negative control does not"
    return VerificationOutcomeV1(
        verdict=verdict,
        candidate_id=plan.candidate_id,
        plan_digest=plan.digest(),
        candidate_exhibits=candidate_exhibits,
        control_exhibits=control_exhibits,
        candidate_evidence=candidate_observation.evidence,
        control_evidence=control_observation.evidence,
        rationale=rationale,
        decided_at=now,
    )


# --------------------------------------------------------------------------- #
# Promotion to a finding (only after human review of a validated outcome)
# --------------------------------------------------------------------------- #


def promote_to_finding(
    outcome: VerificationOutcomeV1,
    plan: VerificationPlanV1,
    candidate: AssetCandidateV1,
    *,
    review_signature_b64: str,
    reviewer_key_id: str,
    reviewed_at: datetime,
    trust_store: TrustStoreV2,
    now: datetime,
) -> ValidatedFindingV1:
    """Yield a ValidatedFinding only from a *validated* outcome a human reviewed.

    Fail-closed: refuses non-validated outcomes, and requires a signature from a
    key trusted for HUMAN_REVIEW over the outcome digest. The caller enforces
    reviewer != approver (separation of duties).
    """

    if outcome.verdict != "validated":
        raise VerificationError(
            f"only a validated outcome can become a finding (got {outcome.verdict!r})"
        )
    if outcome.plan_digest != plan.digest() or outcome.candidate_id != candidate.candidate_id:
        raise VerificationError("outcome is not bound to the given plan and candidate")
    payload = canonical_json({"outcome_digest": outcome.digest()})
    try:
        trust_store.verify(
            key_id=reviewer_key_id,
            usage=KeyUsage.HUMAN_REVIEW,
            payload=payload,
            signature=review_signature_b64,
            at=reviewed_at,
        )
    except SecurityContractError as exc:
        raise VerificationError(f"review signature is not trusted: {exc}") from exc
    finding_id = "finding-" + candidate.candidate_id.removeprefix("cand-")[:22]
    return ValidatedFindingV1(
        finding_id=finding_id,
        candidate_id=candidate.candidate_id,
        program_handle=plan.program_handle,
        target_url=candidate.target_url,
        candidate_type=candidate.candidate_type,
        claimed_severity=candidate.claimed_severity,
        plan_digest=plan.digest(),
        outcome_digest=outcome.digest(),
        reviewer_key_id=reviewer_key_id,
        reviewed_at=reviewed_at,
    )


def sign_review(
    outcome: VerificationOutcomeV1, private_key: Ed25519PrivateKey
) -> str:
    """Helper: a reviewer's signature over an outcome (KeyUsage.HUMAN_REVIEW)."""

    return sign_ed25519(private_key, canonical_json({"outcome_digest": outcome.digest()}))
