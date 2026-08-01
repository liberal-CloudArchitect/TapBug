from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from enum import StrEnum
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .errors import ApprovalDenied


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class ActionKind(StrEnum):
    HTTP_GET = "http_get"
    VALIDATION_HTTP_GET = "validation_http_get"
    HTTP_POST = "http_post"
    LOGIN = "login"
    CREDENTIAL_PROBE = "credential_probe"
    INJECTION_PROBE = "injection_probe"
    DNS = "dns"
    COMMAND = "command"


class ProposedAction(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: ActionKind
    target: str
    method: str | None = None
    max_requests: int = Field(default=1, ge=1, le=1000)
    detail: str = ""

    @field_validator("method")
    @classmethod
    def canonical_method(cls, value: str | None) -> str | None:
        return value.upper() if value is not None else None

    @model_validator(mode="after")
    def safe_read_kind_must_match_http_method(self) -> ProposedAction:
        """Do not let a mutating request masquerade as a read-only action."""
        if self.kind is ActionKind.HTTP_GET and self.method not in {None, "GET", "HEAD"}:
            raise ValueError("http_get actions may only use GET or HEAD")
        if self.kind is ActionKind.VALIDATION_HTTP_GET and self.method not in {None, "GET", "HEAD"}:
            raise ValueError("validation_http_get actions may only use GET or HEAD")
        return self

    @property
    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(_canonical(self.model_dump(mode="json"))).hexdigest()

    @property
    def requires_approval(self) -> bool:
        return self.kind is not ActionKind.HTTP_GET


class ApprovalChallenge(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    challenge_id: str
    run_id: str
    scope_digest: str
    action_digest: str
    target: str
    expires_at: int


class ApprovalToken(ApprovalChallenge):
    token_id: str
    max_requests: int
    signature: str

    @property
    def encoded(self) -> str:
        payload = self.model_dump(exclude={"signature"}, mode="json")
        return _b64(_canonical(payload)) + "." + self.signature


class ApprovalAuthority:
    """Ed25519 issuer/verifier with one-time token consumption in this run."""

    def __init__(
        self, private_key: Ed25519PrivateKey | None = None, public_key: bytes | None = None
    ):
        if private_key is None and public_key is None:
            private_key = Ed25519PrivateKey.generate()
        self._private = private_key
        self._public = (
            private_key.public_key()
            if private_key
            else Ed25519PublicKey.from_public_bytes(public_key or b"")
        )
        self._consumed: set[str] = set()

    @property
    def public_key_bytes(self) -> bytes:
        return self._public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def challenge(
        self, *, run_id: str, scope_digest: str, action: ProposedAction, ttl_seconds: int = 300
    ) -> ApprovalChallenge:
        if ttl_seconds <= 0:
            raise ValueError("approval ttl must be positive")
        return ApprovalChallenge(
            challenge_id=str(uuid.uuid4()),
            run_id=run_id,
            scope_digest=scope_digest,
            action_digest=action.digest,
            target=action.target,
            expires_at=int(time.time()) + ttl_seconds,
        )

    def approve(
        self,
        challenge: ApprovalChallenge,
        action: ProposedAction,
        *,
        max_requests: int | None = None,
    ) -> ApprovalToken:
        if not self._private:
            raise ApprovalDenied("a verifier-only authority cannot issue approval tokens")
        if challenge.action_digest != action.digest or challenge.target != action.target:
            raise ApprovalDenied("challenge does not bind this action")
        payload = {
            **challenge.model_dump(mode="json"),
            "token_id": str(uuid.uuid4()),
            "max_requests": max_requests or action.max_requests,
        }
        signature = _b64(self._private.sign(_canonical(payload)))
        return ApprovalToken(**payload, signature=signature)

    def consume(
        self,
        token: ApprovalToken | str | None,
        *,
        run_id: str,
        scope_digest: str,
        action: ProposedAction,
    ) -> ApprovalToken:
        if token is None:
            raise ApprovalDenied("this action requires an approval token")
        if isinstance(token, str):
            token = self.decode(token)
        payload = token.model_dump(exclude={"signature"}, mode="json")
        try:
            self._public.verify(_unb64(token.signature), _canonical(payload))
        except (InvalidSignature, ValueError) as exc:
            raise ApprovalDenied("invalid approval signature") from exc
        if token.token_id in self._consumed:
            raise ApprovalDenied("approval token was already consumed")
        if token.expires_at < int(time.time()):
            raise ApprovalDenied("approval token has expired")
        if (token.run_id, token.scope_digest, token.action_digest, token.target) != (
            run_id,
            scope_digest,
            action.digest,
            action.target,
        ):
            raise ApprovalDenied("approval token is bound to a different run, scope, or action")
        if token.max_requests < action.max_requests:
            raise ApprovalDenied("approval token request budget is too small")
        self._consumed.add(token.token_id)
        return token

    def decode(self, encoded: str) -> ApprovalToken:
        try:
            payload_text, signature = encoded.split(".", 1)
            return ApprovalToken(**json.loads(_unb64(payload_text)), signature=signature)
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            raise ApprovalDenied("malformed approval token") from exc
