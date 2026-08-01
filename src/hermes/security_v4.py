"""Signatures and exact-graph checks for the isolated V4 governance plane."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .campaign_v4 import VerificationCampaignPlanV4, approval_actions_v4
from .domain_contracts import canonical_digest
from .domain_contracts_v4 import ApprovalBatchV4
from .security import KeyUsage, SecurityContractError, TrustStoreV2, decode_base64, encode_base64

_DIGEST = r"^sha256:[0-9a-f]{64}$"
_ID = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$"


class ApprovalConsumptionV4(BaseModel):
    """Atomic proof that one signed V4 action was consumed once for evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["4"] = "4"
    consumption_id: str = Field(pattern=_ID)
    run_id: str = Field(pattern=_ID)
    scope_digest: str = Field(pattern=_DIGEST)
    campaign_id: str = Field(pattern=_ID)
    campaign_digest: str = Field(pattern=_DIGEST)
    approval_id: str = Field(pattern=_ID)
    approval_batch_digest: str = Field(pattern=_DIGEST)
    candidate_id: str = Field(pattern=_ID)
    action_id: str = Field(pattern=_ID)
    action_digest: str = Field(pattern=_DIGEST)
    task_id: str = Field(pattern=_ID)
    task_input_sha256: str = Field(pattern=_DIGEST)
    request_id: str = Field(pattern=_ID)
    evidence_id: str = Field(pattern=_ID)
    consumed_at: datetime

    @field_validator("consumed_at")
    @classmethod
    def aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("consumption timestamp must be timezone-aware")
        return value

    @property
    def digest(self) -> str:
        return canonical_digest(self)


class V4SecurityError(ValueError):
    """An approval, signature, or exact action graph is not trustworthy."""


def _payload(batch: ApprovalBatchV4) -> bytes:
    return json.dumps(
        batch.model_dump(mode="json", exclude={"signature_b64"}),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def sign_approval_batch_v4(
    batch: ApprovalBatchV4, private_key: Ed25519PrivateKey
) -> ApprovalBatchV4:
    return batch.model_copy(
        update={"signature_b64": encode_base64(private_key.sign(_payload(batch)))}
    )


def verify_approval_batch_v4(
    batch: ApprovalBatchV4,
    campaign: VerificationCampaignPlanV4,
    trust_store: TrustStoreV2,
    *,
    at: datetime | None = None,
) -> None:
    now = at or datetime.now(UTC)
    if (batch.run_id, batch.scope_digest, batch.campaign_digest) != (
        campaign.run_id,
        campaign.scope_digest,
        campaign.digest,
    ):
        raise V4SecurityError("approval crosses campaign, run, or scope")
    if now > batch.expires_at:
        raise V4SecurityError("approval has expired")
    try:
        public = trust_store.trusted_public_key(batch.key_id, KeyUsage.APPROVAL, at=batch.signed_at)
        # A new approval must still be active at consumption time.  Historical
        # verification is an audit-only capability and cannot authorize egress.
        trust_store.trusted_public_key(batch.key_id, KeyUsage.APPROVAL, at=now)
        public.verify(decode_base64(batch.signature_b64), _payload(batch))
    except (SecurityContractError, InvalidSignature, ValueError) as exc:
        raise V4SecurityError("approval signature is invalid or untrusted") from exc
    eligible = approval_actions_v4(campaign, batch.risk_group)
    action_by_digest = {item.action_digest: item for item in eligible}
    if set(batch.action_digests) != {
        item.action_digest for item in eligible if item.candidate_id in batch.candidate_ids
    }:
        raise V4SecurityError("approval does not bind complete candidate action subgraphs")
    if not set(batch.action_digests) <= set(action_by_digest):
        raise V4SecurityError("approval contains an action outside its risk group")
    if not set(batch.candidate_ids) <= {item.candidate_id for item in eligible}:
        raise V4SecurityError("approval contains an unknown candidate")


__all__ = [
    "ApprovalBatchV4",
    "ApprovalConsumptionV4",
    "V4SecurityError",
    "sign_approval_batch_v4",
    "verify_approval_batch_v4",
]
