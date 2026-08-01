"""Wheel V2 trust and signed registry primitives."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from hermes.r25_contracts import R25Contract, WheelLifecycleV2
from hermes.security import (
    KeyStatus,
    KeyUsage,
    SecurityContractError,
    TrustedKey,
    TrustStoreV2,
    canonical_json,
    sign_ed25519,
)


class WheelKeyUsageV2(StrEnum):
    PUBLISHER = "wheel_publisher"
    VALIDATOR = "wheel_validator"
    APPROVER = "wheel_approver"
    OPERATOR = "wheel_operator"
    REVOKER = "wheel_revoker"


class WheelKeyStatusV2(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"
    REVOKED = "revoked"


class WheelTrustedKeyV2(BaseModel):
    """Purpose-constrained Ed25519 verification key for R2.5 wheel governance."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    usage: WheelKeyUsageV2
    status: WheelKeyStatusV2 = WheelKeyStatusV2.ACTIVE
    public_key: str
    valid_from: datetime
    valid_until: datetime | None = None
    revoked_at: datetime | None = None

    @field_validator("valid_from", "valid_until", "revoked_at")
    @classmethod
    def aware_instants(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("wheel key timestamps must be timezone-aware")
        return value

    @model_validator(mode="after")
    def coherent_lifecycle(self) -> WheelTrustedKeyV2:
        if self.valid_until is not None and self.valid_until <= self.valid_from:
            raise ValueError("wheel key valid_until must follow valid_from")
        if self.status is WheelKeyStatusV2.REVOKED and self.revoked_at is None:
            raise ValueError("revoked wheel keys require revoked_at")
        if self.status is not WheelKeyStatusV2.REVOKED and self.revoked_at is not None:
            raise ValueError("only revoked wheel keys may set revoked_at")
        return self

    def as_trusted_key(self) -> TrustedKey:
        status = {
            WheelKeyStatusV2.ACTIVE: KeyStatus.ACTIVE,
            WheelKeyStatusV2.DISABLED: KeyStatus.DISABLED,
            WheelKeyStatusV2.REVOKED: KeyStatus.REVOKED,
        }[self.status]
        return TrustedKey(
            key_id=self.key_id,
            public_key=self.public_key,
            usages=frozenset({KeyUsage.WHEEL_APPROVAL}),
            status=status,
            valid_from=self.valid_from,
            valid_until=self.valid_until,
            revoked_at=self.revoked_at,
        )


class WheelTrustStoreV2(BaseModel):
    """Separate trust root for governed wheel publication and activation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str = Field(default="2", pattern=r"^2$")
    keys: tuple[WheelTrustedKeyV2, ...] = Field(min_length=5)

    @model_validator(mode="after")
    def distinct_roles(self) -> WheelTrustStoreV2:
        key_ids = [key.key_id for key in self.keys]
        if len(key_ids) != len(set(key_ids)):
            raise ValueError("wheel trust-store key IDs must be unique")
        usages = [key.usage for key in self.keys]
        required = {
            WheelKeyUsageV2.PUBLISHER,
            WheelKeyUsageV2.VALIDATOR,
            WheelKeyUsageV2.APPROVER,
            WheelKeyUsageV2.OPERATOR,
            WheelKeyUsageV2.REVOKER,
        }
        missing = required.difference(usages)
        if missing:
            raise ValueError(
                "wheel trust store is missing required usages: "
                + ", ".join(sorted(item.value for item in missing))
            )
        if len(usages) != len(set(usages)):
            raise ValueError("wheel trust store requires one distinct key per governance usage")
        return self

    def _record(self, key_id: str) -> WheelTrustedKeyV2:
        record = next((item for item in self.keys if item.key_id == key_id), None)
        if record is None:
            raise SecurityContractError(f"wheel key {key_id!r} is not trusted")
        return record

    def verify_usage(
        self, key_id: str, expected: WheelKeyUsageV2, *, at: datetime | None = None
    ) -> None:
        instant = at or datetime.now(UTC)
        if instant.tzinfo is None:
            raise SecurityContractError("wheel verification time must be timezone-aware")
        record = self._record(key_id)
        if record.usage is not expected:
            raise SecurityContractError(f"wheel key {key_id!r} is not trusted for {expected.value}")
        surrogate = TrustStoreV2(version="2", keys=(record.as_trusted_key(),))
        surrogate.trusted_public_key(key_id, KeyUsage.WHEEL_APPROVAL, at=instant)


def _contract_payload(contract: R25Contract) -> bytes:
    return canonical_json(contract.model_dump(mode="json", exclude={"signature_b64"}))


def _event_payload(payload: dict[str, Any]) -> bytes:
    return canonical_json(payload)


def sign_learning_contract(contract: R25Contract, private_key: Ed25519PrivateKey) -> str:
    return sign_ed25519(private_key, _contract_payload(contract))


def sign_registry_event_payload(payload: dict[str, Any], private_key: Ed25519PrivateKey) -> str:
    return sign_ed25519(private_key, _event_payload(payload))


def verify_learning_contract(
    contract: R25Contract,
    *,
    trust_store: WheelTrustStoreV2,
    key_id: str,
    usage: WheelKeyUsageV2,
    signature: str,
    at: datetime | None = None,
) -> None:
    trust_store.verify_usage(key_id, usage, at=at)
    surrogate = TrustStoreV2(version="2", keys=(trust_store._record(key_id).as_trusted_key(),))
    surrogate.verify(
        key_id=key_id,
        usage=KeyUsage.WHEEL_APPROVAL,
        payload=_contract_payload(contract),
        signature=signature,
        at=at,
    )


def verify_registry_event_payload(
    payload: dict[str, Any],
    *,
    trust_store: WheelTrustStoreV2,
    key_id: str,
    usage: WheelKeyUsageV2,
    signature: str,
    at: datetime | None = None,
) -> None:
    trust_store.verify_usage(key_id, usage, at=at)
    surrogate = TrustStoreV2(version="2", keys=(trust_store._record(key_id).as_trusted_key(),))
    surrogate.verify(
        key_id=key_id,
        usage=KeyUsage.WHEEL_APPROVAL,
        payload=_event_payload(payload),
        signature=signature,
        at=at,
    )


class WheelRegistryLifecycleEventV2(BaseModel):
    """One immutable, hash-linked lifecycle journal record."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    wheel_id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,63}$")
    wheel_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$")
    event_type: str = Field(min_length=1, max_length=64)
    actor_key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    actor_usage: WheelKeyUsageV2
    target_lifecycle: WheelLifecycleV2
    previous_event_hash: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    manifest_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    payload_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    manifest_json: dict[str, Any]
    event_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    occurred_at: datetime
    approved_until: datetime | None = None
    activation_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    signature_b64: str = Field(min_length=16, max_length=4_096)

    @field_validator("occurred_at", "approved_until")
    @classmethod
    def aware_occurred_at(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("registry event timestamps must be timezone-aware")
        return value


class WheelRegistryRecordV2(BaseModel):
    """In-memory authority for the latest immutable wheel governance state."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    wheel_id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,63}$")
    wheel_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$")
    lifecycle: WheelLifecycleV2
    manifest_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    last_event_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    approved_until: datetime | None = None
    activation_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")

    @field_validator("approved_until")
    @classmethod
    def aware_approved_until(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("registry approved_until must be timezone-aware")
        return value


class WheelUsageV2(StrEnum):
    RESOLVED = "resolved"
    INCONCLUSIVE = "inconclusive"
    FAILED = "failed"
    INVALID_OUTPUT = "invalid_output"
    SANDBOX_VIOLATION = "sandbox_violation"
    INTEGRITY_FAILURE = "integrity_failure"
    MANUAL_FALSE_POSITIVE = "manual_false_positive"


class WheelUsageEventV2(BaseModel):
    """Recorded outcome from capability execution or post-hoc operator judgment."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    usage_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    wheel_id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,63}$")
    wheel_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$")
    usage: WheelUsageV2
    execution_receipt_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    recorded_at: datetime
    operator_key_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9._-]{1,128}$")

    @field_validator("recorded_at")
    @classmethod
    def aware_recorded_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("usage event recorded_at must be timezone-aware")
        return value
