"""Shared cryptographic trust primitives for Hermes security contracts."""

from __future__ import annotations

import base64
import ipaddress
import json
import socket
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class SecurityContractError(ValueError):
    """A key, signature, trust decision, or resolver result is invalid."""


def canonical_json(value: Any) -> bytes:
    """Encode a JSON-compatible value for stable signatures."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def encode_base64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def decode_base64(value: str) -> bytes:
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, TypeError) as exc:
        raise SecurityContractError("value is not valid URL-safe base64") from exc


class SystemResolver:
    """Resolve a host with the operating-system resolver and return canonical IPs.

    PolicyEngine remains responsible for deciding whether DNS is allowed and whether
    the returned addresses are safe. This helper performs resolution only.
    """

    def __call__(self, host: str) -> tuple[str, ...]:
        if not host or "\x00" in host:
            raise SecurityContractError("resolver host must be non-empty")
        try:
            records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise SecurityContractError(f"system resolver failed for {host!r}") from exc
        addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
        for record in records:
            try:
                addresses.add(ipaddress.ip_address(record[4][0]))
            except (IndexError, ValueError):
                continue
        if not addresses:
            raise SecurityContractError(f"system resolver returned no addresses for {host!r}")
        return tuple(
            str(address)
            for address in sorted(addresses, key=lambda item: (item.version, int(item)))
        )


class KeyUsage(StrEnum):
    APPROVAL = "approval"
    HUMAN_REVIEW = "human_review"
    ROLE_MANIFEST = "role_manifest"
    WHEEL_APPROVAL = "wheel_approval"
    # N1 (docs/19): a human authorizing a real-asset ScopeProfile — kept distinct
    # from operational APPROVAL so scope authorization is a separate duty from
    # per-action approval.
    SCOPE_APPROVAL = "scope_approval"


class KeyStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"
    REVOKED = "revoked"


class TrustedKey(BaseModel):
    """One purpose-constrained Ed25519 verification key."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    public_key: str
    usages: frozenset[KeyUsage] = Field(min_length=1)
    status: KeyStatus = KeyStatus.ACTIVE
    valid_from: datetime
    valid_until: datetime | None = None
    revoked_at: datetime | None = None

    @field_validator("valid_from", "valid_until", "revoked_at")
    @classmethod
    def require_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("key validity timestamps must be timezone-aware")
        return value

    @field_validator("public_key")
    @classmethod
    def valid_public_key(cls, value: str) -> str:
        if len(decode_base64(value)) != 32:
            raise ValueError("Ed25519 public keys must contain 32 bytes")
        return value

    @model_validator(mode="after")
    def coherent_lifecycle(self) -> TrustedKey:
        if self.valid_until is not None and self.valid_until <= self.valid_from:
            raise ValueError("valid_until must follow valid_from")
        if self.status is KeyStatus.REVOKED and self.revoked_at is None:
            raise ValueError("revoked keys require revoked_at")
        if self.status is not KeyStatus.REVOKED and self.revoked_at is not None:
            raise ValueError("only revoked keys may set revoked_at")
        return self


class TrustStoreV2(BaseModel):
    """Versioned, usage-scoped public-key trust store."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str = Field(default="2", pattern=r"^2$")
    keys: tuple[TrustedKey, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_key_ids(self) -> TrustStoreV2:
        ids = [key.key_id for key in self.keys]
        if len(ids) != len(set(ids)):
            raise ValueError("trust-store key IDs must be unique")
        return self

    @classmethod
    def from_file(cls, path: Path) -> TrustStoreV2:
        try:
            return cls.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise SecurityContractError(f"could not load trust store v2: {exc}") from exc

    def trusted_public_key(
        self, key_id: str, usage: KeyUsage, *, at: datetime | None = None
    ) -> Ed25519PublicKey:
        instant = at or datetime.now(UTC)
        if instant.tzinfo is None:
            raise SecurityContractError("verification time must be timezone-aware")
        record = next((item for item in self.keys if item.key_id == key_id), None)
        if record is None:
            raise SecurityContractError(f"key {key_id!r} is not trusted")
        if record.status is KeyStatus.DISABLED:
            raise SecurityContractError(f"key {key_id!r} is disabled")
        if record.status is KeyStatus.REVOKED and (
            record.revoked_at is None or instant >= record.revoked_at
        ):
            raise SecurityContractError(
                f"key {key_id!r} is not active because it was revoked at signing time"
            )
        if usage not in record.usages:
            raise SecurityContractError(f"key {key_id!r} is not trusted for {usage.value}")
        if instant < record.valid_from or (
            record.valid_until is not None and instant > record.valid_until
        ):
            raise SecurityContractError(f"key {key_id!r} is outside its validity interval")
        return Ed25519PublicKey.from_public_bytes(decode_base64(record.public_key))

    def verify(
        self,
        *,
        key_id: str,
        usage: KeyUsage,
        payload: bytes,
        signature: str,
        at: datetime | None = None,
    ) -> None:
        public_key = self.trusted_public_key(key_id, usage, at=at)
        try:
            public_key.verify(decode_base64(signature), payload)
        except (InvalidSignature, ValueError) as exc:
            raise SecurityContractError("Ed25519 signature verification failed") from exc


def generate_ed25519_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def public_key_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def load_ed25519_private_key(path: Path, *, password: bytes | None = None) -> Ed25519PrivateKey:
    try:
        raw = path.read_bytes()
        if len(raw) == 32:
            return Ed25519PrivateKey.from_private_bytes(raw)
        loaded = serialization.load_pem_private_key(raw, password=password)
    except (OSError, TypeError, ValueError) as exc:
        raise SecurityContractError(f"could not load Ed25519 private key: {exc}") from exc
    if not isinstance(loaded, Ed25519PrivateKey):
        raise SecurityContractError("private key is not Ed25519")
    return loaded


def load_ed25519_public_key(path: Path) -> Ed25519PublicKey:
    try:
        raw = path.read_bytes()
        if len(raw) == 32:
            return Ed25519PublicKey.from_public_bytes(raw)
        loaded = serialization.load_pem_public_key(raw)
    except (OSError, TypeError, ValueError) as exc:
        raise SecurityContractError(f"could not load Ed25519 public key: {exc}") from exc
    if not isinstance(loaded, Ed25519PublicKey):
        raise SecurityContractError("public key is not Ed25519")
    return loaded


def sign_ed25519(private_key: Ed25519PrivateKey, payload: bytes) -> str:
    return encode_base64(private_key.sign(payload))


def verify_ed25519(public_key: Ed25519PublicKey, payload: bytes, signature: str) -> None:
    try:
        public_key.verify(decode_base64(signature), payload)
    except (InvalidSignature, ValueError) as exc:
        raise SecurityContractError("Ed25519 signature verification failed") from exc
