"""Append-only Wheel V2 governance registry."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hermes.domain_contracts import canonical_digest
from hermes.r25_contracts import (
    ValidationReceiptV2,
    WheelActivationReceiptV2,
    WheelApprovalV2,
    WheelLifecycleV2,
    WheelManifestV2,
)

from .security import (
    WheelKeyUsageV2,
    WheelRegistryLifecycleEventV2,
    WheelRegistryRecordV2,
    WheelTrustStoreV2,
    WheelUsageEventV2,
    WheelUsageV2,
    verify_learning_contract,
    verify_registry_event_payload,
)


class WheelRegistryErrorV2(RuntimeError):
    """Raised when Wheel V2 governance invariants are violated."""


class RegistryEventV2:
    REGISTERED = "registered"
    RESEARCHED = "researched"
    SPECIFIED = "specified"
    GENERATED = "generated"
    VALIDATED = "validated"
    CANDIDATE = "candidate"
    APPROVED = "approved"
    ACTIVE = "active"
    QUARANTINED = "quarantined"
    REVOKED = "revoked"


_TRANSITIONS: dict[WheelLifecycleV2, frozenset[WheelLifecycleV2]] = {
    "draft": frozenset({"researched"}),
    "researched": frozenset({"specified"}),
    "specified": frozenset({"generated"}),
    "generated": frozenset({"validated"}),
    "validated": frozenset({"candidate"}),
    "candidate": frozenset({"approved", "quarantined"}),
    "approved": frozenset({"active", "quarantined"}),
    "active": frozenset({"quarantined", "revoked"}),
    "quarantined": frozenset({"revoked"}),
    "revoked": frozenset(),
}

_QUARANTINE_USAGES = {
    WheelUsageV2.INVALID_OUTPUT,
    WheelUsageV2.SANDBOX_VIOLATION,
    WheelUsageV2.INTEGRITY_FAILURE,
    WheelUsageV2.MANUAL_FALSE_POSITIVE,
}


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _event_hash(payload: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(payload)).hexdigest()


def _normalize_replay_body(payload: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(payload)
    for key in ("occurred_at", "approved_until"):
        value = normalized.get(key)
        if isinstance(value, str) and value.endswith("Z"):
            normalized[key] = value[:-1] + "+00:00"
    return normalized


class WheelRegistryV2:
    """Signed, hash-chained lifecycle registry for isolated Wheel V2 artifacts."""

    def __init__(self, trust_store: WheelTrustStoreV2, *, journal_path: Path | None = None) -> None:
        self._trust_store = trust_store
        self._journal_path = journal_path.resolve() if journal_path is not None else None
        self._events: list[WheelRegistryLifecycleEventV2] = []
        self._records: dict[tuple[str, str], WheelRegistryRecordV2] = {}
        self._manifests: dict[tuple[str, str], WheelManifestV2] = {}
        self._usage_events: list[WheelUsageEventV2] = []
        if self._journal_path is not None:
            self._journal_path.parent.mkdir(parents=True, exist_ok=True)
            if self._journal_path.exists():
                self._replay()

    @property
    def events(self) -> tuple[WheelRegistryLifecycleEventV2, ...]:
        return tuple(self._events)

    @property
    def usage_events(self) -> tuple[WheelUsageEventV2, ...]:
        return tuple(self._usage_events)

    def get(self, wheel_id: str, wheel_version: str) -> WheelRegistryRecordV2:
        try:
            return self._records[(wheel_id, wheel_version)]
        except KeyError as exc:
            raise WheelRegistryErrorV2("unknown wheel record") from exc

    def manifest(self, wheel_id: str, wheel_version: str) -> WheelManifestV2:
        try:
            return self._manifests[(wheel_id, wheel_version)]
        except KeyError as exc:
            raise WheelRegistryErrorV2("unknown wheel manifest") from exc

    def event_signing_payload(
        self,
        manifest: WheelManifestV2,
        *,
        event_type: str,
        actor_key_id: str,
        actor_usage: WheelKeyUsageV2,
        target_lifecycle: WheelLifecycleV2,
        occurred_at: datetime,
        payload: Any | None = None,
        approved_until: datetime | None = None,
        activation_digest: str | None = None,
    ) -> dict[str, Any]:
        """Return the exact pre-signature body for the next registry event.

        This is intentionally public so an operator can create a detached
        Ed25519 signature without duplicating the hash-chain implementation.
        It is not an append operation; a concurrent append invalidates it.
        """
        return {
            "event_id": f"{manifest.wheel_id}-{manifest.manifest_version}-{len(self._events) + 1}",
            "wheel_id": manifest.wheel_id,
            "wheel_version": manifest.manifest_version,
            "event_type": event_type,
            "actor_key_id": actor_key_id,
            "actor_usage": actor_usage.value,
            "target_lifecycle": target_lifecycle,
            "previous_event_hash": self._events[-1].event_hash if self._events else None,
            "manifest_digest": manifest.digest,
            "payload_digest": canonical_digest(
                payload if payload is not None else {"event_type": event_type}
            ),
            "manifest_json": manifest.model_dump(mode="json"),
            "occurred_at": occurred_at.isoformat(),
            "approved_until": approved_until.isoformat() if approved_until is not None else None,
            "activation_digest": activation_digest,
        }

    def add_draft(
        self,
        manifest: WheelManifestV2,
        *,
        publisher_key_id: str,
        signature_b64: str,
        registry_signature_b64: str,
        occurred_at: datetime | None = None,
    ) -> WheelRegistryRecordV2:
        key = (manifest.wheel_id, manifest.manifest_version)
        if key in self._records:
            raise WheelRegistryErrorV2("wheel versions are immutable; choose a new version")
        if manifest.lifecycle != "draft":
            raise WheelRegistryErrorV2("new wheel manifests must start in draft")
        instant = occurred_at or manifest.generated_at
        verify_learning_contract(
            manifest,
            trust_store=self._trust_store,
            key_id=publisher_key_id,
            usage=WheelKeyUsageV2.PUBLISHER,
            signature=signature_b64,
            at=instant,
        )
        return self._append_manifest_event(
            manifest,
            event_type=RegistryEventV2.REGISTERED,
            actor_key_id=publisher_key_id,
            actor_usage=WheelKeyUsageV2.PUBLISHER,
            target_lifecycle="draft",
            occurred_at=instant,
            signature_b64=registry_signature_b64,
        )

    def transition(
        self,
        wheel_id: str,
        wheel_version: str,
        target: WheelLifecycleV2,
        *,
        actor_key_id: str,
        actor_usage: WheelKeyUsageV2,
        signature_b64: str,
        occurred_at: datetime | None = None,
    ) -> WheelRegistryRecordV2:
        record = self.get(wheel_id, wheel_version)
        manifest = self.manifest(wheel_id, wheel_version)
        if target not in _TRANSITIONS[record.lifecycle]:
            raise WheelRegistryErrorV2(f"cannot transition {record.lifecycle} -> {target}")
        if target in {"validated", "approved", "active"}:
            raise WheelRegistryErrorV2(f"{target} requires its dedicated governance method")
        usage = WheelKeyUsageV2.REVOKER if target == "revoked" else actor_usage
        return self._append_manifest_event(
            manifest,
            event_type=target,
            actor_key_id=actor_key_id,
            actor_usage=usage,
            target_lifecycle=target,
            occurred_at=occurred_at or datetime.now(UTC),
            signature_b64=signature_b64,
        )

    def record_validation(
        self,
        manifest: WheelManifestV2,
        receipt: ValidationReceiptV2,
        *,
        event_signature_b64: str,
    ) -> WheelRegistryRecordV2:
        record = self.get(manifest.wheel_id, manifest.manifest_version)
        if record.lifecycle != "generated":
            raise WheelRegistryErrorV2("only generated wheels can be validated")
        if receipt.wheel_manifest_digest != manifest.digest:
            raise WheelRegistryErrorV2("validation receipt digest does not match manifest")
        verify_learning_contract(
            receipt,
            trust_store=self._trust_store,
            key_id=receipt.validator_key_id,
            usage=WheelKeyUsageV2.VALIDATOR,
            signature=receipt.signature_b64,
            at=receipt.validated_at,
        )
        return self._append_manifest_event(
            manifest,
            event_type=RegistryEventV2.VALIDATED,
            actor_key_id=receipt.validator_key_id,
            actor_usage=WheelKeyUsageV2.VALIDATOR,
            target_lifecycle="validated",
            occurred_at=receipt.validated_at,
            payload=receipt,
            signature_b64=event_signature_b64,
        )

    def approve(
        self,
        manifest: WheelManifestV2,
        approval: WheelApprovalV2,
        *,
        event_signature_b64: str,
    ) -> WheelRegistryRecordV2:
        record = self.get(manifest.wheel_id, manifest.manifest_version)
        if record.lifecycle != "candidate":
            raise WheelRegistryErrorV2("only candidate wheels can be approved")
        if approval.wheel_manifest_digest != manifest.digest:
            raise WheelRegistryErrorV2("approval digest does not match manifest")
        verify_learning_contract(
            approval,
            trust_store=self._trust_store,
            key_id=approval.approver_key_id,
            usage=WheelKeyUsageV2.APPROVER,
            signature=approval.signature_b64,
            at=approval.approved_at,
        )
        return self._append_manifest_event(
            manifest,
            event_type=RegistryEventV2.APPROVED,
            actor_key_id=approval.approver_key_id,
            actor_usage=WheelKeyUsageV2.APPROVER,
            target_lifecycle="approved",
            occurred_at=approval.approved_at,
            payload=approval,
            approved_until=approval.expires_at,
            signature_b64=event_signature_b64,
        )

    def activate(
        self,
        manifest: WheelManifestV2,
        activation: WheelActivationReceiptV2,
        *,
        event_signature_b64: str,
    ) -> WheelRegistryRecordV2:
        record = self.get(manifest.wheel_id, manifest.manifest_version)
        if record.lifecycle != "approved":
            raise WheelRegistryErrorV2("only approved wheels can be activated")
        if activation.wheel_manifest_digest != manifest.digest:
            raise WheelRegistryErrorV2("activation digest does not match manifest")
        if record.approved_until is None or activation.activated_at > record.approved_until:
            raise WheelRegistryErrorV2("activation occurs after approval expiry")
        verify_learning_contract(
            activation,
            trust_store=self._trust_store,
            key_id=activation.operator_key_id,
            usage=WheelKeyUsageV2.OPERATOR,
            signature=activation.signature_b64,
            at=activation.activated_at,
        )
        return self._append_manifest_event(
            manifest,
            event_type=RegistryEventV2.ACTIVE,
            actor_key_id=activation.operator_key_id,
            actor_usage=WheelKeyUsageV2.OPERATOR,
            target_lifecycle="active",
            occurred_at=activation.activated_at,
            payload=activation,
            approved_until=record.approved_until,
            activation_digest=activation.digest,
            signature_b64=event_signature_b64,
        )

    def record_usage(
        self, usage_event: WheelUsageEventV2, *, event_signature_b64: str | None = None
    ) -> WheelRegistryRecordV2:
        record = self.get(usage_event.wheel_id, usage_event.wheel_version)
        self._usage_events.append(usage_event)
        if usage_event.usage not in _QUARANTINE_USAGES:
            return record
        manifest = self.manifest(usage_event.wheel_id, usage_event.wheel_version)
        return self._append_manifest_event(
            manifest,
            event_type=RegistryEventV2.QUARANTINED,
            actor_key_id=usage_event.operator_key_id or "system-quarantine",
            actor_usage=WheelKeyUsageV2.REVOKER,
            target_lifecycle="quarantined",
            occurred_at=usage_event.recorded_at,
            payload=usage_event,
            approved_until=record.approved_until,
            activation_digest=record.activation_digest,
            verify_actor=usage_event.operator_key_id is not None,
            signature_b64=event_signature_b64 or "system-quarantine-signature-0001",
        )

    def select_active(
        self,
        wheel_id: str,
        wheel_version: str,
        *,
        profile: str,
        required_template_id: str,
        artifact_digest: str,
        now: datetime | None = None,
    ) -> WheelManifestV2:
        instant = now or datetime.now(UTC)
        record = self.get(wheel_id, wheel_version)
        manifest = self.manifest(wheel_id, wheel_version)
        if record.lifecycle != "active":
            raise WheelRegistryErrorV2("wheel is not active")
        if manifest.profile != profile:
            raise WheelRegistryErrorV2("wheel profile does not match selector")
        if manifest.template_id != required_template_id:
            raise WheelRegistryErrorV2("wheel template does not match selector")
        if manifest.artifact_digest != artifact_digest:
            raise WheelRegistryErrorV2("wheel artifact digest does not match selector")
        if record.approved_until is not None and instant > record.approved_until:
            raise WheelRegistryErrorV2("wheel approval has expired")
        return manifest

    def _append_manifest_event(
        self,
        manifest: WheelManifestV2,
        *,
        event_type: str,
        actor_key_id: str,
        actor_usage: WheelKeyUsageV2,
        target_lifecycle: WheelLifecycleV2,
        occurred_at: datetime,
        signature_b64: str,
        payload: Any | None = None,
        approved_until: datetime | None = None,
        activation_digest: str | None = None,
        verify_actor: bool = True,
    ) -> WheelRegistryRecordV2:
        event_body = self.event_signing_payload(
            manifest,
            event_type=event_type,
            actor_key_id=actor_key_id,
            actor_usage=actor_usage,
            target_lifecycle=target_lifecycle,
            occurred_at=occurred_at,
            payload=payload,
            approved_until=approved_until,
            activation_digest=activation_digest,
        )
        if verify_actor:
            verify_registry_event_payload(
                event_body,
                trust_store=self._trust_store,
                key_id=actor_key_id,
                usage=actor_usage,
                signature=signature_b64,
                at=occurred_at,
            )
        event_hash = _event_hash(event_body)
        event = WheelRegistryLifecycleEventV2.model_validate(
            {**event_body, "event_hash": event_hash, "signature_b64": signature_b64}
        )
        self._events.append(event)
        record = WheelRegistryRecordV2(
            wheel_id=manifest.wheel_id,
            wheel_version=manifest.manifest_version,
            lifecycle=target_lifecycle,
            manifest_digest=manifest.digest,
            last_event_hash=event.event_hash,
            approved_until=approved_until,
            activation_digest=activation_digest,
        )
        self._records[(manifest.wheel_id, manifest.manifest_version)] = record
        self._manifests[(manifest.wheel_id, manifest.manifest_version)] = manifest
        if self._journal_path is not None:
            with self._journal_path.open("a", encoding="utf-8") as handle:
                handle.write(event.model_dump_json() + "\n")
        return record

    def _replay(self) -> None:
        previous_hash: str | None = None
        assert self._journal_path is not None
        for line in self._journal_path.read_text(encoding="utf-8").splitlines():
            raw_event = json.loads(line)
            event = WheelRegistryLifecycleEventV2.model_validate_json(line)
            if event.previous_event_hash != previous_hash:
                raise WheelRegistryErrorV2("wheel registry hash chain mismatch")
            body = _normalize_replay_body(dict(raw_event))
            body.pop("event_hash", None)
            body.pop("signature_b64", None)
            expected_hash = _event_hash(body)
            if event.event_hash != expected_hash:
                raise WheelRegistryErrorV2("wheel registry event hash mismatch")
            verify_registry_event_payload(
                body,
                trust_store=self._trust_store,
                key_id=event.actor_key_id,
                usage=event.actor_usage,
                signature=event.signature_b64,
                at=event.occurred_at,
            )
            previous_hash = event.event_hash
            self._events.append(event)
            manifest = WheelManifestV2.model_validate(event.manifest_json)
            self._manifests[(manifest.wheel_id, manifest.manifest_version)] = manifest
            self._records[(manifest.wheel_id, manifest.manifest_version)] = WheelRegistryRecordV2(
                wheel_id=manifest.wheel_id,
                wheel_version=manifest.manifest_version,
                lifecycle=event.target_lifecycle,
                manifest_digest=event.manifest_digest,
                last_event_hash=event.event_hash,
                approved_until=event.approved_until,
                activation_digest=event.activation_digest,
            )
