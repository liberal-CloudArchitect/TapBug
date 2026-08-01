"""Cryptographic approval, review, and identity-vault primitives for Phase 4.

This module deliberately owns no workflow state.  It validates V3 records against
their canonical campaign/coverage artifacts and keeps secret identity material in
the trusted parent runtime.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .domain_contracts import canonical_digest
from .domain_contracts_v3 import (
    ApprovalBatchV3,
    CoverageReportV3,
    FindingSet,
    RiskGroup,
    SignedReviewBatchV3,
    VerificationActionV3,
    VerificationCampaignPlan,
)
from .security import (
    KeyUsage,
    SecurityContractError,
    TrustedKey,
    TrustStoreV2,
    canonical_json,
    sign_ed25519,
)

_ALIAS = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MAX_VAULT_BYTES = 64 * 1024
_MAX_SECRET_CHARACTERS = 4096
_CLEANUP_APPROVAL_TTL = timedelta(minutes=10)


def _approval_signing_payload(batch: ApprovalBatchV3) -> bytes:
    return canonical_json(batch.model_dump(mode="json", exclude={"signature_b64"}))


def _review_signing_payload(review: SignedReviewBatchV3) -> bytes:
    return canonical_json(review.model_dump(mode="json", exclude={"signature_b64"}))


def _aware_instant(value: datetime | None) -> datetime:
    instant = value or datetime.now(UTC)
    if instant.tzinfo is None:
        raise SecurityContractError("verification time must be timezone-aware")
    return instant


def _trusted_record(store: TrustStoreV2, key_id: str) -> TrustedKey:
    record = next((item for item in store.keys if item.key_id == key_id), None)
    if record is None:
        raise SecurityContractError(f"key {key_id!r} is not trusted")
    return record


def _require_exclusive_usage(
    store: TrustStoreV2, key_id: str, *, required: KeyUsage, forbidden: KeyUsage
) -> None:
    record = _trusted_record(store, key_id)
    if required not in record.usages:
        raise SecurityContractError(f"key {key_id!r} is not trusted for {required.value}")
    if forbidden in record.usages:
        raise SecurityContractError(
            f"key {key_id!r} cannot be shared by {required.value} and {forbidden.value}"
        )


def sign_approval_batch_v3(
    batch: ApprovalBatchV3, private_key: Ed25519PrivateKey
) -> ApprovalBatchV3:
    """Return an Ed25519-signed replacement for an unsigned V3 approval batch."""

    unsigned = batch.model_copy(update={"signature_b64": "unsigned-signature"})
    return unsigned.model_copy(
        update={"signature_b64": sign_ed25519(private_key, _approval_signing_payload(unsigned))}
    )


def approval_actions_v3(
    campaign: VerificationCampaignPlan, risk_group: RiskGroup
) -> tuple[VerificationActionV3, ...]:
    """Return the exact campaign actions governed by one approval risk group.

    Cleanup actions remain classified as mutation actions in the immutable
    campaign.  A cleanup-only approval is an emergency authority projection:
    it can authorize only the predeclared cleanup and cleanup-check nodes and
    can never authorize their forward mutation, baseline, or control nodes.
    """

    if risk_group == "cleanup":
        return tuple(
            action for action in campaign.actions if action.purpose in {"cleanup", "cleanup_check"}
        )
    return tuple(action for action in campaign.actions if action.risk_group == risk_group)


def cleanup_challenge_payload_v3(
    campaign: VerificationCampaignPlan, issued_at: datetime
) -> dict[str, Any]:
    """Build the exact, short-lived challenge for predeclared compensation nodes."""

    if issued_at.tzinfo is None:
        raise SecurityContractError("cleanup challenge time must be timezone-aware")
    actions = approval_actions_v3(campaign, "cleanup")
    if not actions:
        raise SecurityContractError("campaign has no cleanup action graph")
    return {
        "version": "3",
        "challenge_id": "phase4-cleanup",
        "run_id": campaign.run_id,
        "scope_digest": campaign.scope_digest,
        "campaign_digest": campaign.digest,
        "risk_group": "cleanup",
        "candidate_ids": sorted({item.candidate_id for item in actions}),
        "action_digests": [item.action_digest for item in actions],
        "expires_at": (issued_at + _CLEANUP_APPROVAL_TTL).isoformat(),
        "issued_at": issued_at.isoformat(),
    }


def _expected_batch_actions(
    batch: ApprovalBatchV3, campaign: VerificationCampaignPlan
) -> tuple[str, ...]:
    selected_candidates = set(batch.candidate_ids)
    eligible = approval_actions_v3(campaign, batch.risk_group)
    available_candidates = {action.candidate_id for action in eligible}
    if not selected_candidates:
        raise SecurityContractError("approval batch must bind at least one candidate graph")
    if not selected_candidates <= available_candidates:
        raise SecurityContractError("approval batch contains a candidate outside its risk group")

    expected = tuple(
        sorted(
            action.action_digest
            for action in eligible
            if action.candidate_id in selected_candidates
        )
    )
    if not expected:
        raise SecurityContractError("approval batch does not select any campaign actions")
    return expected


def verify_approval_batch_v3(
    batch: ApprovalBatchV3,
    campaign: VerificationCampaignPlan,
    trust_store: TrustStoreV2,
    *,
    at: datetime | None = None,
) -> None:
    """Verify signature, TTL, context, and all-or-none candidate action graphs."""

    instant = _aware_instant(at)
    if (
        batch.run_id != campaign.run_id
        or batch.scope_digest != campaign.scope_digest
        or batch.campaign_digest != campaign.digest
    ):
        raise SecurityContractError(
            "approval batch is bound to a different campaign, run, or scope"
        )
    if batch.risk_group == "cleanup":
        if batch.signed_at < campaign.created_at:
            raise SecurityContractError("cleanup approval predates the campaign")
        if batch.expires_at > batch.signed_at + _CLEANUP_APPROVAL_TTL:
            raise SecurityContractError("cleanup-only approval exceeds its ten-minute TTL")
        if instant < batch.signed_at or instant > batch.expires_at:
            raise SecurityContractError("cleanup-only approval is not currently valid")
    else:
        if batch.signed_at < campaign.created_at or batch.signed_at > campaign.expires_at:
            raise SecurityContractError("approval signature time is outside the campaign lifetime")
        if batch.expires_at > campaign.expires_at:
            raise SecurityContractError("approval TTL cannot outlive the verification campaign")
        if instant < batch.signed_at or instant > batch.expires_at or instant > campaign.expires_at:
            raise SecurityContractError("approval batch or campaign is not currently valid")

    expected = _expected_batch_actions(batch, campaign)
    if tuple(sorted(batch.action_digests)) != expected:
        raise SecurityContractError(
            "approval batch must bind every action in each selected candidate graph"
        )

    _require_exclusive_usage(
        trust_store,
        batch.key_id,
        required=KeyUsage.APPROVAL,
        forbidden=KeyUsage.HUMAN_REVIEW,
    )
    trust_store.verify(
        key_id=batch.key_id,
        usage=KeyUsage.APPROVAL,
        payload=_approval_signing_payload(batch),
        signature=batch.signature_b64,
        at=batch.signed_at,
    )


def gap_digest(gap: str) -> str:
    """Return the canonical, domain-separated digest for one exact coverage gap."""

    if not gap:
        raise SecurityContractError("coverage gaps must be non-empty")
    return canonical_digest({"contract": "hermes.coverage_gap/v3", "gap": gap})


def coverage_gap_digests(coverage: CoverageReportV3) -> tuple[str, ...]:
    return tuple(sorted(gap_digest(gap) for gap in coverage.gaps))


def sign_review_batch_v3(
    review: SignedReviewBatchV3, private_key: Ed25519PrivateKey
) -> SignedReviewBatchV3:
    """Return an Ed25519-signed replacement for an unsigned V3 human review."""

    unsigned = review.model_copy(update={"signature_b64": "unsigned-signature"})
    return unsigned.model_copy(
        update={"signature_b64": sign_ed25519(private_key, _review_signing_payload(unsigned))}
    )


def _raw_public_key(store: TrustStoreV2, key_id: str, usage: KeyUsage, at: datetime) -> bytes:
    return store.trusted_public_key(key_id, usage, at=at).public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def verify_review_batch_v3(
    review: SignedReviewBatchV3,
    finding_set: FindingSet,
    coverage: CoverageReportV3,
    review_trust_store: TrustStoreV2,
    *,
    report_draft_digest: str,
    approval_batches: Sequence[ApprovalBatchV3] = (),
    approval_trust_store: TrustStoreV2 | None = None,
) -> None:
    """Verify a review and prove that reviewer and approvers use distinct keys."""

    if (
        review.run_id != finding_set.run_id
        or review.run_id != coverage.run_id
        or review.scope_digest != finding_set.scope_digest
        or review.scope_digest != coverage.scope_digest
    ):
        raise SecurityContractError("human review is bound to a different run or scope")
    if (
        review.finding_set_digest != finding_set.digest
        or review.coverage_report_digest != coverage.digest
        or review.report_draft_digest != report_draft_digest
    ):
        raise SecurityContractError("human review is bound to different report artifacts")

    expected_gaps = coverage_gap_digests(coverage)
    if tuple(review.gap_digests) != expected_gaps:
        raise SecurityContractError("human review does not bind the exact coverage gaps")
    if coverage.completion == "completed" and review.verdict not in {"accepted", "rejected"}:
        raise SecurityContractError("gap-free coverage cannot be accepted_with_gaps")
    if coverage.completion == "completed_with_gaps" and review.verdict not in {
        "accepted_with_gaps",
        "rejected",
    }:
        raise SecurityContractError("coverage with gaps requires accepted_with_gaps or rejection")

    _require_exclusive_usage(
        review_trust_store,
        review.reviewer_key_id,
        required=KeyUsage.HUMAN_REVIEW,
        forbidden=KeyUsage.APPROVAL,
    )
    review_public = _raw_public_key(
        review_trust_store,
        review.reviewer_key_id,
        KeyUsage.HUMAN_REVIEW,
        review.reviewed_at,
    )
    if approval_batches:
        if approval_trust_store is None:
            raise SecurityContractError("approval trust store is required to prove key separation")
        for approval in approval_batches:
            if approval.run_id != review.run_id or approval.scope_digest != review.scope_digest:
                raise SecurityContractError("approval and review belong to different run contexts")
            if approval.key_id == review.reviewer_key_id:
                raise SecurityContractError("approver and reviewer key IDs must be distinct")
            _require_exclusive_usage(
                approval_trust_store,
                approval.key_id,
                required=KeyUsage.APPROVAL,
                forbidden=KeyUsage.HUMAN_REVIEW,
            )
            approval_public = _raw_public_key(
                approval_trust_store,
                approval.key_id,
                KeyUsage.APPROVAL,
                approval.signed_at,
            )
            if approval_public == review_public:
                raise SecurityContractError("approver and reviewer key material must be distinct")

    review_trust_store.verify(
        key_id=review.reviewer_key_id,
        usage=KeyUsage.HUMAN_REVIEW,
        payload=_review_signing_payload(review),
        signature=review.signature_b64,
        at=review.reviewed_at,
    )


@dataclass(frozen=True, slots=True)
class IdentityCredentialV3:
    """One parent-runtime credential; repr intentionally hides the secret."""

    alias: str
    secret: str = field(repr=False)
    binding_digest: str


@dataclass(frozen=True, slots=True, init=False)
class IdentityVaultV3:
    """Immutable in-memory identity material loaded from an external protected file."""

    source: Path
    _credentials: Mapping[str, IdentityCredentialV3] = field(repr=False)

    def __init__(self, source: Path, credentials: Mapping[str, IdentityCredentialV3]) -> None:
        object.__setattr__(self, "source", source)
        object.__setattr__(self, "_credentials", MappingProxyType(dict(credentials)))

    @property
    def aliases(self) -> tuple[str, ...]:
        return tuple(sorted(self._credentials))

    @property
    def binding_digests(self) -> Mapping[str, str]:
        return MappingProxyType(
            {alias: item.binding_digest for alias, item in self._credentials.items()}
        )

    def credential(self, alias: str) -> IdentityCredentialV3:
        try:
            return self._credentials[alias]
        except KeyError as exc:
            raise SecurityContractError(f"identity alias {alias!r} is not available") from exc

    def __repr__(self) -> str:
        return f"IdentityVaultV3(source={self.source!r}, aliases={self.aliases!r})"


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SecurityContractError(f"identity vault contains duplicate key {key!r}")
        result[key] = value
    return result


def _inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _read_protected_file(path: Path) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise SecurityContractError(f"could not inspect identity vault: {exc}") from exc
    if stat.S_ISLNK(before.st_mode):
        raise SecurityContractError("identity vault must not be a symlink")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            details = os.fstat(descriptor)
            if (details.st_dev, details.st_ino) != (before.st_dev, before.st_ino):
                raise SecurityContractError("identity vault changed while it was being opened")
            if not stat.S_ISREG(details.st_mode):
                raise SecurityContractError("identity vault must be a regular file")
            if stat.S_IMODE(details.st_mode) != 0o600:
                raise SecurityContractError("identity vault permissions must be 0600")
            if details.st_size > _MAX_VAULT_BYTES:
                raise SecurityContractError("identity vault exceeds the 64 KiB size limit")
            chunks: list[bytes] = []
            remaining = _MAX_VAULT_BYTES + 1
            while remaining:
                chunk = os.read(descriptor, min(remaining, 8192))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) > _MAX_VAULT_BYTES:
                raise SecurityContractError("identity vault exceeds the 64 KiB size limit")
            return raw
        finally:
            os.close(descriptor)
    except SecurityContractError:
        raise
    except OSError as exc:
        raise SecurityContractError(f"could not read identity vault: {exc}") from exc


def _identity_binding(alias: str, secret: str) -> str:
    hasher = hashlib.sha256()
    hasher.update(b"hermes-identity-binding-v3\x00")
    hasher.update(alias.encode("utf-8"))
    hasher.update(b"\x00")
    hasher.update(secret.encode("utf-8"))
    return f"sha256:{hasher.hexdigest()}"


def load_identity_vault_v3(path: Path, *, repo_root: Path, runs_root: Path) -> IdentityVaultV3:
    """Load a protected JSON identity vault outside repository and run artifacts.

    The on-disk schema is ``{"version":"1","identities":{"alias":"opaque secret"}}``.
    """

    if not path.is_absolute():
        raise SecurityContractError("identity vault path must be absolute")
    resolved = path.resolve(strict=False)
    for label, root in (("repository", repo_root), ("runs root", runs_root)):
        resolved_root = root.resolve(strict=False)
        if _inside(resolved, resolved_root):
            raise SecurityContractError(f"identity vault must be outside the {label}")
    raw = _read_protected_file(path)
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except SecurityContractError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SecurityContractError(f"identity vault is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(document, dict) or set(document) != {"version", "identities"}:
        raise SecurityContractError("identity vault must contain only version and identities")
    if document["version"] != "1" or not isinstance(document["identities"], dict):
        raise SecurityContractError("identity vault version or identities object is invalid")
    identities: dict[str, Any] = document["identities"]
    if not identities:
        raise SecurityContractError("identity vault must contain at least one identity")
    credentials: dict[str, IdentityCredentialV3] = {}
    for alias, secret in identities.items():
        if not _ALIAS.fullmatch(alias):
            raise SecurityContractError(f"identity alias {alias!r} is invalid")
        if (
            not isinstance(secret, str)
            or not secret
            or len(secret) > _MAX_SECRET_CHARACTERS
            or any(character in secret for character in "\x00\r\n")
        ):
            raise SecurityContractError(f"identity secret for {alias!r} is invalid")
        credentials[alias] = IdentityCredentialV3(
            alias=alias,
            secret=secret,
            binding_digest=_identity_binding(alias, secret),
        )
    return IdentityVaultV3(resolved, credentials)


__all__ = [
    "IdentityCredentialV3",
    "IdentityVaultV3",
    "approval_actions_v3",
    "cleanup_challenge_payload_v3",
    "coverage_gap_digests",
    "gap_digest",
    "load_identity_vault_v3",
    "sign_approval_batch_v3",
    "sign_review_batch_v3",
    "verify_approval_batch_v3",
    "verify_review_batch_v3",
]
