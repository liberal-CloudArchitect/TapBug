"""Sensitive V4 operator actions kept out of the top-level CLI parser."""

from __future__ import annotations

import json
import stat
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, TypeVar

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, ValidationError

from .campaign_v4 import RiskGroupV4, VerificationCampaignPlanV4, approval_actions_v4
from .domain_contracts_v4 import RunPlanV4, SignedReviewBatchV4
from .runtime import RunContext
from .security import (
    KeyUsage,
    SecurityContractError,
    TrustStoreV2,
    decode_base64,
    encode_base64,
    load_ed25519_private_key,
    public_key_bytes,
)
from .security_v4 import ApprovalBatchV4, V4SecurityError, sign_approval_batch_v4
from .vertical_v4 import ExecutionStateV4, VerticalStateV4

_ModelT = TypeVar("_ModelT", bound=BaseModel)


class V4ManagementError(RuntimeError):
    """An operator request did not match frozen V4 governance artifacts."""


def _read(context: RunContext, relative: str, model: type[_ModelT]) -> _ModelT:
    try:
        return model.model_validate_json(context.artifact_path(relative).read_bytes())
    except (OSError, ValidationError, ValueError) as exc:
        raise V4ManagementError(f"invalid or missing V4 artifact: {relative}") from exc


def load_v4_state(context: RunContext) -> VerticalStateV4:
    plan = _read(context, "plan/run-v4.json", RunPlanV4)
    if plan.run_id != context.run_id or plan.scope_digest != context.scope_digest:
        raise V4ManagementError("V4 plan is bound to another run or scope")
    state = _read(context, "state.json", VerticalStateV4)
    if state.run_id != context.run_id:
        raise V4ManagementError("V4 state is bound to another run")
    return state


def _private_key(value: Path | Ed25519PrivateKey) -> Ed25519PrivateKey:
    if isinstance(value, Ed25519PrivateKey):
        return value
    if not value.is_absolute():
        raise V4ManagementError("private key path must be absolute")
    try:
        details = value.lstat()
    except OSError as exc:
        raise V4ManagementError("private key could not be inspected") from exc
    if not stat.S_ISREG(details.st_mode) or stat.S_ISLNK(details.st_mode):
        raise V4ManagementError("private key must be a regular non-symlink file")
    if stat.S_IMODE(details.st_mode) != 0o600:
        raise V4ManagementError("private key permissions must be 0600")
    try:
        return load_ed25519_private_key(value)
    except SecurityContractError as exc:
        raise V4ManagementError("private key is not a valid Ed25519 key") from exc


def _key_id(store: TrustStoreV2, usage: KeyUsage, private: Ed25519PrivateKey, at: datetime) -> str:
    encoded = encode_base64(public_key_bytes(private))
    values = tuple(
        item.key_id for item in store.keys if usage in item.usages and item.public_key == encoded
    )
    if len(values) != 1:
        raise V4ManagementError("private key is not uniquely authorized for this V4 operation")
    try:
        store.trusted_public_key(values[0], usage, at=at)
    except SecurityContractError as exc:
        raise V4ManagementError("private key is not currently trusted") from exc
    return values[0]


def _challenge(
    context: RunContext, campaign: VerificationCampaignPlanV4, risk_group: RiskGroupV4
) -> dict[str, object]:
    relative = f"approvals_v4/challenge-{risk_group}.json"
    try:
        value = json.loads(context.artifact_path(relative).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise V4ManagementError("V4 approval challenge is unavailable") from exc
    actions = approval_actions_v4(campaign, risk_group)
    expected = {
        "version": "4",
        "challenge_id": f"phase5-{risk_group}",
        "run_id": context.run_id,
        "scope_digest": context.scope_digest,
        "campaign_digest": campaign.digest,
        "risk_group": risk_group,
        "candidate_ids": sorted({item.candidate_id for item in actions}),
        "action_digests": [item.action_digest for item in actions],
        "expires_at": campaign.expires_at.isoformat(),
    }
    if value != expected:
        raise V4ManagementError("V4 approval challenge does not match the frozen campaign")
    return dict(expected)


def sign_decision_v4(
    context: RunContext,
    *,
    risk_group: RiskGroupV4,
    decision: Literal["approved", "rejected"],
    selected_candidate_ids: tuple[str, ...],
    key: Path | Ed25519PrivateKey,
    trust_store: TrustStoreV2,
    operator: str,
    rationale: str,
    signed_at: datetime | None = None,
) -> ApprovalBatchV4:
    state = load_v4_state(context)
    expected_state = {
        "readonly": ExecutionStateV4.AWAITING_READONLY_APPROVAL,
        "mutation": ExecutionStateV4.AWAITING_MUTATION_APPROVAL,
        "cleanup": ExecutionStateV4.AWAITING_CLEANUP_APPROVAL,
    }[risk_group]
    if state.execution_state is not expected_state and not (
        risk_group == "cleanup" and state.execution_state is ExecutionStateV4.CLEANUP_REQUIRED
    ):
        raise V4ManagementError(f"run is not awaiting {risk_group} approval")
    campaign = _read(context, "verification_v4/campaign.json", VerificationCampaignPlanV4)
    _challenge(context, campaign, risk_group)
    available = {item.candidate_id for item in approval_actions_v4(campaign, risk_group)}
    candidates = tuple(sorted(selected_candidate_ids))
    if (
        not candidates
        or len(candidates) != len(set(candidates))
        or not set(candidates) <= available
    ):
        raise V4ManagementError("candidate selection is not a complete V4 risk-group subset")
    action_digests = tuple(
        sorted(
            item.action_digest
            for item in approval_actions_v4(campaign, risk_group)
            if item.candidate_id in candidates
        )
    )
    now = signed_at or datetime.now(UTC)
    private = _private_key(key)
    key_id = _key_id(trust_store, KeyUsage.APPROVAL, private, now)
    unsigned = ApprovalBatchV4(
        run_id=context.run_id,
        scope_digest=context.scope_digest,
        generated_by_task_id=operator,
        approval_id=f"approval-{risk_group}-{uuid.uuid4().hex}",
        campaign_digest=campaign.digest,
        risk_group=risk_group,
        verdict=decision,
        candidate_ids=candidates,
        action_digests=action_digests,
        key_id=key_id,
        signed_at=now,
        expires_at=campaign.expires_at,
        rationale=rationale,
        signature_b64="unsigned-signature",
    )
    signed = sign_approval_batch_v4(unsigned, private)
    context.write_json(
        f"approvals_v4/{risk_group}.json", signed.model_dump(mode="json"), immutable=True
    )
    return signed


def sign_review_v4(
    batch: SignedReviewBatchV4, key: Path | Ed25519PrivateKey
) -> SignedReviewBatchV4:
    private = _private_key(key)
    payload = json.dumps(
        batch.model_dump(mode="json", exclude={"signature_b64"}),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return batch.model_copy(update={"signature_b64": encode_base64(private.sign(payload))})


def verify_review_v4(batch: SignedReviewBatchV4, store: TrustStoreV2) -> None:
    payload = json.dumps(
        batch.model_dump(mode="json", exclude={"signature_b64"}),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    try:
        key = store.trusted_public_key(
            batch.reviewer_key_id, KeyUsage.HUMAN_REVIEW, at=batch.reviewed_at
        )
        key.verify(decode_base64(batch.signature_b64), payload)
    except (SecurityContractError, InvalidSignature, ValueError) as exc:
        raise V4SecurityError("review signature is invalid or untrusted") from exc


__all__ = [
    "V4ManagementError",
    "load_v4_state",
    "sign_decision_v4",
    "sign_review_v4",
    "verify_review_v4",
]
