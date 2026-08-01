"""Independent trust primitives for the governed R2.5 learning lifecycle."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .security import (
    SecurityContractError,
    decode_base64,
    encode_base64,
    load_ed25519_private_key,
    public_key_bytes,
    sign_ed25519,
)


class LearningKeyUsage(StrEnum):
    WHEEL_PUBLISHER = "wheel_publisher"
    WHEEL_VALIDATOR = "wheel_validator"
    WHEEL_APPROVER = "wheel_approver"
    WHEEL_OPERATOR = "wheel_operator"
    WHEEL_REVOKER = "wheel_revoker"


class LearningKeyStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"
    REVOKED = "revoked"


class LearningTrustedKey(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    public_key: str
    usages: frozenset[LearningKeyUsage] = Field(min_length=1)
    status: LearningKeyStatus = LearningKeyStatus.ACTIVE
    valid_from: datetime
    valid_until: datetime | None = None
    revoked_at: datetime | None = None

    @field_validator("valid_from", "valid_until", "revoked_at")
    @classmethod
    def require_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("learning key timestamps must be timezone-aware")
        return value

    @field_validator("public_key")
    @classmethod
    def valid_public_key(cls, value: str) -> str:
        if len(decode_base64(value)) != 32:
            raise ValueError("Ed25519 public keys must contain 32 bytes")
        return value

    @model_validator(mode="after")
    def coherent_lifecycle(self) -> LearningTrustedKey:
        if self.valid_until is not None and self.valid_until <= self.valid_from:
            raise ValueError("valid_until must follow valid_from")
        if self.status is LearningKeyStatus.REVOKED and self.revoked_at is None:
            raise ValueError("revoked keys require revoked_at")
        if self.status is not LearningKeyStatus.REVOKED and self.revoked_at is not None:
            raise ValueError("only revoked keys may set revoked_at")
        return self


class LearningTrustStoreV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str = Field(default="1", pattern=r"^1$")
    keys: tuple[LearningTrustedKey, ...] = Field(min_length=5)

    @model_validator(mode="after")
    def unique_key_ids(self) -> LearningTrustStoreV1:
        ids = [item.key_id for item in self.keys]
        if len(ids) != len(set(ids)):
            raise ValueError("learning trust-store key IDs must be unique")
        return self

    @classmethod
    def from_file(cls, path: Path) -> LearningTrustStoreV1:
        try:
            return cls.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise SecurityContractError(f"could not load learning trust store: {exc}") from exc

    def key_for(self, usage: LearningKeyUsage, *, at: datetime | None = None) -> LearningTrustedKey:
        instant = at or datetime.now(UTC)
        if instant.tzinfo is None:
            raise SecurityContractError("learning verification time must be timezone-aware")
        matches = [item for item in self.keys if usage in item.usages]
        if len(matches) != 1:
            raise SecurityContractError(f"learning trust store must define exactly one {usage}")
        record = matches[0]
        if record.status is LearningKeyStatus.DISABLED:
            raise SecurityContractError(f"key {record.key_id!r} is disabled")
        if record.status is LearningKeyStatus.REVOKED and (
            record.revoked_at is None or instant >= record.revoked_at
        ):
            raise SecurityContractError(
                f"key {record.key_id!r} is not active because it was revoked"
            )
        if instant < record.valid_from or (
            record.valid_until is not None and instant > record.valid_until
        ):
            raise SecurityContractError(f"key {record.key_id!r} is outside its validity interval")
        return record

    def assert_role_separation(self) -> None:
        key_ids = {usage: self.key_for(usage).key_id for usage in LearningKeyUsage}
        if len(set(key_ids.values())) != len(key_ids):
            raise SecurityContractError("learning trust-store keys must be duty-separated")

    def verify(
        self,
        *,
        usage: LearningKeyUsage,
        payload: bytes,
        signature: str,
        at: datetime | None = None,
    ) -> str:
        instant = at or datetime.now(UTC)
        record = self.key_for(usage, at=instant)
        public_key = Ed25519PublicKey.from_public_bytes(decode_base64(record.public_key))
        try:
            public_key.verify(decode_base64(signature), payload)
        except Exception as exc:  # pragma: no cover - cryptography provides concrete types
            raise SecurityContractError("learning Ed25519 signature verification failed") from exc
        return record.key_id


def match_learning_private_key(
    store: LearningTrustStoreV1, usage: LearningKeyUsage, key_path: Path, *, at: datetime
) -> tuple[str, Ed25519PrivateKey]:
    """Return the trusted key ID and loaded private key for one explicit learning role."""

    private_key = load_ed25519_private_key(key_path)
    public_key = encode_base64(public_key_bytes(private_key))
    record = store.key_for(usage, at=at)
    if record.public_key != public_key:
        raise SecurityContractError("private key does not match the trusted learning role")
    return record.key_id, private_key


def sign_learning_payload(
    store: LearningTrustStoreV1,
    usage: LearningKeyUsage,
    key_path: Path,
    payload: bytes,
    *,
    at: datetime,
) -> tuple[str, str]:
    key_id, private_key = match_learning_private_key(store, usage, key_path, at=at)
    return key_id, sign_ed25519(private_key, payload)
