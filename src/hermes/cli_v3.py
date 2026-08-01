"""Fail-closed operator management helpers for Phase 4 runs.

The public CLI remains responsible for argument parsing and state transitions.
This module owns the security-sensitive part of the management commands: loading
only a frozen V3 run, validating the canonical challenge, and committing one
immutable signed decision or review.
"""

from __future__ import annotations

import json
import stat
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, TypeVar, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, ValidationError

from .domain_contracts_v3 import (
    ApprovalBatchV3,
    CoverageReportV3,
    FindingSet,
    RiskGroup,
    RunPlanV3,
    SignedReviewBatchV3,
    VerificationCampaignPlan,
)
from .promotion import file_sha256
from .runtime import RunContext
from .security import (
    KeyUsage,
    SecurityContractError,
    TrustStoreV2,
    encode_base64,
    load_ed25519_private_key,
    public_key_bytes,
)
from .security_v3 import (
    approval_actions_v3,
    cleanup_challenge_payload_v3,
    coverage_gap_digests,
    sign_approval_batch_v3,
    sign_review_batch_v3,
    verify_approval_batch_v3,
    verify_review_batch_v3,
)
from .vertical_v3 import ExecutionStateV3, VerticalStateV3

ApprovalDecision = Literal["approved", "rejected"]
ReviewVerdict = Literal["accepted", "accepted_with_gaps", "rejected"]
_ModelT = TypeVar("_ModelT", bound=BaseModel)


class V3ManagementError(RuntimeError):
    """A management command did not match the frozen Phase 4 run."""


def _read_model(context: RunContext, relative: str, model: type[_ModelT]) -> _ModelT:
    path = context.artifact_path(relative)
    try:
        return model.model_validate_json(path.read_bytes())
    except (OSError, ValidationError, ValueError) as exc:
        raise V3ManagementError(f"invalid or missing V3 artifact: {relative}") from exc


def _load_v3_plan(context: RunContext) -> RunPlanV3:
    path = context.artifact_path("plan/run-v3.json")
    if not path.is_file():
        raise V3ManagementError("operation requires a Phase 4 V3 run")
    plan = _read_model(context, "plan/run-v3.json", RunPlanV3)
    if plan.run_id != context.run_id or plan.scope_digest != context.scope_digest:
        raise V3ManagementError("V3 run plan is bound to another run or scope")
    return plan


def load_v3_state(context: RunContext) -> VerticalStateV3:
    """Load state only after proving that the run has a canonical V3 plan."""

    _load_v3_plan(context)
    state = _read_model(context, "state.json", VerticalStateV3)
    if state.run_id != context.run_id:
        raise V3ManagementError("V3 state is bound to another run")
    return state


def emit_v3_payload(state: VerticalStateV3) -> dict[str, Any]:
    """Return the stable machine-readable Phase 4 state payload."""

    return state.model_dump(mode="json")


def _load_private_key(key: Ed25519PrivateKey | Path) -> Ed25519PrivateKey:
    if isinstance(key, Ed25519PrivateKey):
        return key
    if not key.is_absolute():
        raise V3ManagementError("private key path must be absolute")
    try:
        details = key.lstat()
    except OSError as exc:
        raise V3ManagementError("private key could not be inspected") from exc
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
        raise V3ManagementError("private key must be a regular non-symlink file")
    if stat.S_IMODE(details.st_mode) != 0o600:
        raise V3ManagementError("private key permissions must be 0600")
    try:
        return load_ed25519_private_key(key)
    except SecurityContractError as exc:
        raise V3ManagementError("private key is not a valid Ed25519 key") from exc


def _key_id(
    store: TrustStoreV2,
    usage: KeyUsage,
    private_key: Ed25519PrivateKey,
    *,
    at: datetime,
) -> str:
    public = encode_base64(public_key_bytes(private_key))
    matches = tuple(
        item.key_id for item in store.keys if usage in item.usages and item.public_key == public
    )
    if len(matches) != 1:
        raise V3ManagementError(
            "private key does not uniquely match the required trust-store usage"
        )
    try:
        store.trusted_public_key(matches[0], usage, at=at)
    except SecurityContractError as exc:
        raise V3ManagementError("private key is not currently trusted") from exc
    return matches[0]


def _expected_challenge(
    context: RunContext,
    campaign: VerificationCampaignPlan,
    risk_group: RiskGroup,
    *,
    issued_at: datetime | None = None,
) -> dict[str, Any]:
    actions = approval_actions_v3(campaign, risk_group)
    if not actions:
        raise V3ManagementError("campaign has no actions in the requested risk group")
    if issued_at is not None:
        try:
            return cleanup_challenge_payload_v3(campaign, issued_at)
        except SecurityContractError as exc:
            raise V3ManagementError("campaign has no cleanup action graph") from exc
    challenge = {
        "version": "3",
        "challenge_id": f"phase4-{risk_group}",
        "run_id": context.run_id,
        "scope_digest": context.scope_digest,
        "campaign_digest": campaign.digest,
        "risk_group": risk_group,
        "candidate_ids": sorted({item.candidate_id for item in actions}),
        "action_digests": [item.action_digest for item in actions],
        "expires_at": campaign.expires_at.isoformat(),
    }
    return challenge


def create_cleanup_challenge_v3(
    context: RunContext,
    campaign: VerificationCampaignPlan,
    *,
    issued_at: datetime | None = None,
) -> dict[str, Any]:
    """Create the immutable ten-minute authority challenge for cleanup only."""

    if campaign.run_id != context.run_id or campaign.scope_digest != context.scope_digest:
        raise V3ManagementError("cleanup challenge crosses a run or scope boundary")
    now = issued_at or datetime.now(UTC)
    if now.tzinfo is None:
        raise V3ManagementError("cleanup challenge time must be timezone-aware")
    challenge = _expected_challenge(context, campaign, "cleanup", issued_at=now)
    relative = "approvals_v3/challenge-cleanup.json"
    try:
        context.write_json(relative, challenge, immutable=True)
    except FileExistsError:
        _verify_challenge(context, campaign, "cleanup")
    return challenge


def _verify_challenge(
    context: RunContext,
    campaign: VerificationCampaignPlan,
    risk_group: RiskGroup,
) -> dict[str, Any]:
    relative = f"approvals_v3/challenge-{risk_group}.json"
    try:

        def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate challenge field")
                result[key] = value
            return result

        value = json.loads(
            context.artifact_path(relative).read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicates,
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise V3ManagementError("canonical approval challenge is missing or invalid") from exc
    if not isinstance(value, dict):
        raise V3ManagementError("canonical approval challenge is not an object")
    challenge_value = cast(dict[str, Any], value)
    issued_at: datetime | None = None
    if risk_group == "cleanup":
        try:
            issued_at = datetime.fromisoformat(str(challenge_value["issued_at"]))
            expires_at = datetime.fromisoformat(str(challenge_value["expires_at"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise V3ManagementError("cleanup approval challenge has invalid timestamps") from exc
        if issued_at.tzinfo is None or expires_at.tzinfo is None:
            raise V3ManagementError("cleanup approval challenge timestamps must be aware")
        if expires_at != issued_at + timedelta(minutes=10):
            raise V3ManagementError("cleanup approval challenge exceeds its bounded TTL")
        if datetime.now(UTC) > expires_at:
            raise V3ManagementError("cleanup approval challenge has expired")
    if challenge_value != _expected_challenge(context, campaign, risk_group, issued_at=issued_at):
        raise V3ManagementError("canonical approval challenge was altered")
    return challenge_value


def _require_expected_approval_state(state: VerticalStateV3, risk_group: RiskGroup) -> None:
    expected = {
        "readonly": ExecutionStateV3.AWAITING_READONLY_APPROVAL,
        "mutation": ExecutionStateV3.AWAITING_MUTATION_APPROVAL,
        "cleanup": ExecutionStateV3.AWAITING_CLEANUP_APPROVAL,
    }[risk_group]
    if risk_group == "cleanup" and state.execution_state is ExecutionStateV3.CLEANUP_REQUIRED:
        return
    if state.execution_state is not expected:
        raise V3ManagementError(f"run is not awaiting {risk_group} approval")


def _selected_action_digests(
    campaign: VerificationCampaignPlan,
    risk_group: RiskGroup,
    candidate_ids: tuple[str, ...],
) -> tuple[str, ...]:
    eligible = approval_actions_v3(campaign, risk_group)
    available = {item.candidate_id for item in eligible}
    if not candidate_ids or len(candidate_ids) != len(set(candidate_ids)):
        raise V3ManagementError("selected candidate IDs must be non-empty and unique")
    if not set(candidate_ids) <= available:
        raise V3ManagementError("selected candidate is outside the requested risk group")
    return tuple(
        sorted(item.action_digest for item in eligible if item.candidate_id in candidate_ids)
    )


def _reject_existing_consumptions(
    context: RunContext, selected_action_digests: tuple[str, ...]
) -> None:
    root = context.artifact_path("approvals_v3/consumptions")
    selected = set(selected_action_digests)
    if not root.is_dir():
        return
    for path in root.glob("*.json"):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise V3ManagementError("approval consumption store is invalid") from exc
        if not isinstance(value, dict):
            raise V3ManagementError("approval consumption store is invalid")
        action_digest = value.get("action_digest")
        if action_digest in selected:
            raise V3ManagementError("cannot decide an action graph after approval consumption")


def sign_decision_v3(
    context: RunContext,
    campaign: VerificationCampaignPlan,
    risk_group: RiskGroup,
    selected_candidate_ids: Sequence[str],
    decision: ApprovalDecision,
    key: Ed25519PrivateKey | Path,
    store: TrustStoreV2,
    operator: str,
    reason: str,
    *,
    signed_at: datetime | None = None,
) -> ApprovalBatchV3:
    """Sign and exclusively commit one exact V3 candidate-graph decision."""

    state = load_v3_state(context)
    _require_expected_approval_state(state, risk_group)
    persisted_campaign = _read_model(
        context, "verification_v3/campaign.json", VerificationCampaignPlan
    )
    if persisted_campaign != campaign:
        raise V3ManagementError("campaign argument is not the frozen campaign artifact")
    if campaign.run_id != context.run_id or campaign.scope_digest != context.scope_digest:
        raise V3ManagementError("campaign is bound to another run or scope")
    challenge = _verify_challenge(context, campaign, risk_group)

    candidate_ids = tuple(sorted(selected_candidate_ids))
    action_digests = _selected_action_digests(campaign, risk_group, candidate_ids)
    _reject_existing_consumptions(context, action_digests)
    if not operator or not reason:
        raise V3ManagementError("operator and reason must be non-empty")

    now = signed_at or datetime.now(UTC)
    if now.tzinfo is None:
        raise V3ManagementError("approval signing time must be timezone-aware")
    private_key = _load_private_key(key)
    key_id = _key_id(store, KeyUsage.APPROVAL, private_key, at=now)
    try:
        unsigned = ApprovalBatchV3(
            run_id=context.run_id,
            scope_digest=context.scope_digest,
            generated_by_task_id=operator,
            approval_id=f"approval-{risk_group}-{uuid.uuid4().hex}",
            campaign_digest=campaign.digest,
            risk_group=risk_group,
            verdict=decision,
            candidate_ids=candidate_ids,
            action_digests=action_digests,
            key_id=key_id,
            signed_at=now,
            expires_at=(
                datetime.fromisoformat(str(challenge["expires_at"]))
                if risk_group == "cleanup"
                else campaign.expires_at
            ),
            rationale=reason,
            signature_b64="unsigned-signature",
        )
        signed = sign_approval_batch_v3(unsigned, private_key)
        verify_approval_batch_v3(signed, campaign, store, at=now)
    except (SecurityContractError, ValidationError, ValueError) as exc:
        raise V3ManagementError("V3 approval decision is invalid") from exc

    relative = f"approvals_v3/{risk_group}.json"
    try:
        context.write_json(relative, signed.model_dump(mode="json"), immutable=True)
    except FileExistsError as exc:
        raise V3ManagementError("risk-group decision is immutable and already exists") from exc
    return signed


def _load_approval_batches(context: RunContext) -> tuple[ApprovalBatchV3, ...]:
    root = context.artifact_path("approvals_v3")
    values: list[ApprovalBatchV3] = []
    if not root.is_dir():
        return ()
    for path in sorted(root.glob("*.json")):
        if path.name.startswith("challenge-"):
            continue
        try:
            values.append(ApprovalBatchV3.model_validate_json(path.read_bytes()))
        except (OSError, ValidationError, ValueError) as exc:
            raise V3ManagementError(f"invalid V3 approval artifact: {path.name}") from exc
    return tuple(values)


def sign_review_v3(
    context: RunContext,
    verdict: ReviewVerdict,
    key: Ed25519PrivateKey | Path,
    store: TrustStoreV2,
    rationale: str,
    *,
    operator: str = "human-review-v3",
    approval_store: TrustStoreV2 | None = None,
    reviewed_at: datetime | None = None,
) -> SignedReviewBatchV3:
    """Sign the exact V3 findings, coverage, draft, and coverage-gap set."""

    state = load_v3_state(context)
    if state.execution_state is not ExecutionStateV3.AWAITING_REVIEW:
        raise V3ManagementError("run is not awaiting human review")
    findings = _read_model(context, "report/finding-set-v3.json", FindingSet)
    coverage = _read_model(context, "report/coverage-v3.json", CoverageReportV3)
    draft_path = context.artifact_path("report/draft-v3.md")
    if not draft_path.is_file():
        raise V3ManagementError("V3 report draft is missing")
    if (
        findings.run_id != context.run_id
        or coverage.run_id != context.run_id
        or findings.scope_digest != context.scope_digest
        or coverage.scope_digest != context.scope_digest
        or coverage.finding_set_digest != findings.digest
    ):
        raise V3ManagementError("review artifacts break the frozen run digest chain")
    expected = "accepted_with_gaps" if coverage.completion == "completed_with_gaps" else "accepted"
    if verdict != "rejected" and verdict != expected:
        raise V3ManagementError(f"coverage completion requires review verdict {expected}")
    if not operator or not rationale:
        raise V3ManagementError("reviewer and rationale must be non-empty")

    now = reviewed_at or datetime.now(UTC)
    if now.tzinfo is None:
        raise V3ManagementError("review signing time must be timezone-aware")
    private_key = _load_private_key(key)
    key_id = _key_id(store, KeyUsage.HUMAN_REVIEW, private_key, at=now)
    approvals = _load_approval_batches(context)
    if approvals and approval_store is None:
        raise V3ManagementError("approval trust store is required for reviewer separation")
    try:
        unsigned = SignedReviewBatchV3(
            run_id=context.run_id,
            scope_digest=context.scope_digest,
            generated_by_task_id=operator,
            review_id=f"review-{uuid.uuid4().hex}",
            finding_set_digest=findings.digest,
            coverage_report_digest=coverage.digest,
            report_draft_digest=file_sha256(draft_path),
            gap_digests=coverage_gap_digests(coverage),
            verdict=verdict,
            reviewer_key_id=key_id,
            reviewed_at=now,
            rationale=rationale,
            signature_b64="unsigned-signature",
        )
        signed = sign_review_batch_v3(unsigned, private_key)
        verify_review_batch_v3(
            signed,
            findings,
            coverage,
            store,
            report_draft_digest=file_sha256(draft_path),
            approval_batches=approvals,
            approval_trust_store=approval_store,
        )
    except (SecurityContractError, ValidationError, ValueError) as exc:
        raise V3ManagementError("V3 signed human review is invalid") from exc

    try:
        context.write_json("reviews/signed-v3.json", signed.model_dump(mode="json"), immutable=True)
    except FileExistsError as exc:
        raise V3ManagementError("V3 signed review is immutable and already exists") from exc
    return signed


__all__ = [
    "V3ManagementError",
    "create_cleanup_challenge_v3",
    "emit_v3_payload",
    "load_v3_state",
    "sign_decision_v3",
    "sign_review_v3",
]
