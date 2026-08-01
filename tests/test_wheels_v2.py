from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes.domain_contracts import canonical_digest
from hermes.r25_contracts import (
    CapabilitySpecV2,
    LineFieldRuleV1,
    ValidationReceiptV2,
    WheelActivationReceiptV2,
    WheelApprovalV2,
    WheelManifestV2,
)
from hermes.security import encode_base64, public_key_bytes
from hermes.wheels_v2 import (
    RegistryEventV2,
    WheelKeyUsageV2,
    WheelRegistryErrorV2,
    WheelRegistryV2,
    WheelTrustedKeyV2,
    WheelTrustStoreV2,
    WheelUsageEventV2,
    WheelUsageV2,
    sign_learning_contract,
    sign_registry_event_payload,
)


def _private_keys() -> dict[WheelKeyUsageV2, Ed25519PrivateKey]:
    return {usage: Ed25519PrivateKey.generate() for usage in WheelKeyUsageV2}


def _trust_store(keys: dict[WheelKeyUsageV2, Ed25519PrivateKey]) -> WheelTrustStoreV2:
    now = datetime.now(UTC) - timedelta(minutes=1)
    return WheelTrustStoreV2(
        keys=tuple(
            WheelTrustedKeyV2(
                key_id=f"{usage.value}-key",
                usage=usage,
                public_key=encode_base64(public_key_bytes(private_key)),
                valid_from=now,
            )
            for usage, private_key in keys.items()
        )
    )


def _spec() -> CapabilitySpecV2:
    return CapabilitySpecV2(
        capability_id="line-kv-status",
        input_schema_id="learning/input@v1",
        output_schema_id="learning/output@v1",
        field_rules=(LineFieldRuleV1(field_name="status", source_key="Status"),),
        required_output_fields=("status",),
        counterexamples=("free-form paragraph",),
        revocation_conditions=("field collision with nested keys",),
        source_digests=("sha256:" + "a" * 64,),
    )


def _manifest(now: datetime) -> WheelManifestV2:
    return WheelManifestV2(
        wheel_id="line-kv-status",
        manifest_version="1.0.0",
        capability_spec_digest=_spec().digest,
        entrypoint="wheel.entry:parse",
        artifact_digest="sha256:" + "b" * 64,
        sbom_digest="sha256:" + "c" * 64,
        readme_digest="sha256:" + "d" * 64,
        lock_digest="sha256:" + "e" * 64,
        generated_at=now,
    )


def _validation(
    manifest: WheelManifestV2,
    key_id: str,
    private_key: Ed25519PrivateKey,
    now: datetime,
) -> ValidationReceiptV2:
    unsigned = ValidationReceiptV2(
        receipt_id="validation-1",
        learning_run_id="learn-run-1",
        wheel_manifest_digest=manifest.digest,
        validator_key_id=key_id,
        static_checks=("ast", "sbom"),
        docker_checks=("sandbox",),
        sandbox_image="wheel-sandbox:1",
        sandbox_image_digest="sha256:" + "1" * 64,
        fixture_positive_digest="sha256:" + "2" * 64,
        fixture_negative_digest="sha256:" + "3" * 64,
        validated_at=now,
        signature_b64="placeholder-signature",
    )
    return unsigned.model_copy(
        update={"signature_b64": sign_learning_contract(unsigned, private_key)}
    )


def _approval(
    manifest: WheelManifestV2,
    validation: ValidationReceiptV2,
    key_id: str,
    private_key: Ed25519PrivateKey,
    now: datetime,
) -> WheelApprovalV2:
    unsigned = WheelApprovalV2(
        approval_id="approval-1",
        learning_run_id="learn-run-1",
        wheel_manifest_digest=manifest.digest,
        validation_receipt_digest=validation.digest,
        approver_key_id=key_id,
        approved_at=now,
        expires_at=now + timedelta(minutes=10),
        signature_b64="placeholder-signature",
    )
    return unsigned.model_copy(
        update={"signature_b64": sign_learning_contract(unsigned, private_key)}
    )


def _activation(
    manifest: WheelManifestV2,
    approval: WheelApprovalV2,
    key_id: str,
    private_key: Ed25519PrivateKey,
    now: datetime,
) -> WheelActivationReceiptV2:
    unsigned = WheelActivationReceiptV2(
        activation_id="activation-1",
        learning_run_id="learn-run-1",
        wheel_manifest_digest=manifest.digest,
        wheel_approval_digest=approval.digest,
        operator_key_id=key_id,
        activated_at=now,
        signature_b64="placeholder-signature",
    )
    return unsigned.model_copy(
        update={"signature_b64": sign_learning_contract(unsigned, private_key)}
    )


def _transition_signature(
    registry: WheelRegistryV2,
    manifest: WheelManifestV2,
    *,
    target: str,
    actor_key_id: str,
    actor_usage: WheelKeyUsageV2,
    private_key: Ed25519PrivateKey,
    when: datetime,
) -> str:
    payload = {
        "event_id": f"{manifest.wheel_id}-{manifest.manifest_version}-{len(registry.events) + 1}",
        "wheel_id": manifest.wheel_id,
        "wheel_version": manifest.manifest_version,
        "event_type": target,
        "actor_key_id": actor_key_id,
        "actor_usage": actor_usage.value,
        "target_lifecycle": target,
        "previous_event_hash": registry.events[-1].event_hash if registry.events else None,
        "manifest_digest": manifest.digest,
        "payload_digest": canonical_digest({"event_type": target}),
        "manifest_json": manifest.model_dump(mode="json"),
        "occurred_at": when.isoformat(),
        "approved_until": None,
        "activation_digest": None,
    }
    return sign_registry_event_payload(payload, private_key)


def _security_event_signature(
    registry: WheelRegistryV2,
    manifest: WheelManifestV2,
    *,
    event_type: str,
    target_lifecycle: str,
    actor_key_id: str,
    actor_usage: WheelKeyUsageV2,
    private_key: Ed25519PrivateKey,
    when: datetime,
    payload_digest: str | None = None,
    approved_until: datetime | None = None,
    activation_digest: str | None = None,
) -> str:
    payload = {
        "event_id": f"{manifest.wheel_id}-{manifest.manifest_version}-{len(registry.events) + 1}",
        "wheel_id": manifest.wheel_id,
        "wheel_version": manifest.manifest_version,
        "event_type": event_type,
        "actor_key_id": actor_key_id,
        "actor_usage": actor_usage.value,
        "target_lifecycle": target_lifecycle,
        "previous_event_hash": registry.events[-1].event_hash if registry.events else None,
        "manifest_digest": manifest.digest,
        "payload_digest": payload_digest
        if payload_digest is not None
        else canonical_digest({"event_type": event_type}),
        "manifest_json": manifest.model_dump(mode="json"),
        "occurred_at": when.isoformat(),
        "approved_until": approved_until.isoformat() if approved_until is not None else None,
        "activation_digest": activation_digest,
    }
    return sign_registry_event_payload(payload, private_key)


def test_wheel_trust_store_requires_all_five_distinct_roles() -> None:
    now = datetime.now(UTC)
    key = Ed25519PrivateKey.generate()
    with pytest.raises(ValueError, match="missing required usages"):
        WheelTrustStoreV2(
            keys=(
                WheelTrustedKeyV2(
                    key_id="publisher",
                    usage=WheelKeyUsageV2.PUBLISHER,
                    public_key=encode_base64(public_key_bytes(key)),
                    valid_from=now,
                ),
                WheelTrustedKeyV2(
                    key_id="publisher-2",
                    usage=WheelKeyUsageV2.PUBLISHER,
                    public_key=encode_base64(public_key_bytes(key)),
                    valid_from=now,
                ),
                WheelTrustedKeyV2(
                    key_id="approver",
                    usage=WheelKeyUsageV2.APPROVER,
                    public_key=encode_base64(public_key_bytes(Ed25519PrivateKey.generate())),
                    valid_from=now,
                ),
                WheelTrustedKeyV2(
                    key_id="operator",
                    usage=WheelKeyUsageV2.OPERATOR,
                    public_key=encode_base64(public_key_bytes(Ed25519PrivateKey.generate())),
                    valid_from=now,
                ),
                WheelTrustedKeyV2(
                    key_id="revoker",
                    usage=WheelKeyUsageV2.REVOKER,
                    public_key=encode_base64(public_key_bytes(Ed25519PrivateKey.generate())),
                    valid_from=now,
                ),
            )
        )


def test_registry_lifecycle_is_hash_chained_and_selects_only_matching_active_wheels(
    tmp_path: Path,
) -> None:
    now = datetime.now(UTC)
    keys = _private_keys()
    store = _trust_store(keys)
    registry = WheelRegistryV2(store, journal_path=tmp_path / "wheel-registry.jsonl")
    manifest = _manifest(now)

    registry.add_draft(
        manifest,
        publisher_key_id="wheel_publisher-key",
        signature_b64=sign_learning_contract(manifest, keys[WheelKeyUsageV2.PUBLISHER]),
        registry_signature_b64=_security_event_signature(
            registry,
            manifest,
            event_type="registered",
            target_lifecycle="draft",
            actor_key_id="wheel_publisher-key",
            actor_usage=WheelKeyUsageV2.PUBLISHER,
            private_key=keys[WheelKeyUsageV2.PUBLISHER],
            when=now,
        ),
    )
    for target in ("researched", "specified", "generated"):
        registry.transition(
            manifest.wheel_id,
            manifest.manifest_version,
            target,
            actor_key_id="wheel_publisher-key",
            actor_usage=WheelKeyUsageV2.PUBLISHER,
            signature_b64=_transition_signature(
                registry,
                manifest,
                target=target,
                actor_key_id="wheel_publisher-key",
                actor_usage=WheelKeyUsageV2.PUBLISHER,
                private_key=keys[WheelKeyUsageV2.PUBLISHER],
                when=now,
            ),
            occurred_at=now,
        )
    validation = _validation(
        manifest,
        "wheel_validator-key",
        keys[WheelKeyUsageV2.VALIDATOR],
        now,
    )
    registry.record_validation(
        manifest,
        validation,
        event_signature_b64=_security_event_signature(
            registry,
            manifest,
            event_type="validated",
            target_lifecycle="validated",
            actor_key_id="wheel_validator-key",
            actor_usage=WheelKeyUsageV2.VALIDATOR,
            private_key=keys[WheelKeyUsageV2.VALIDATOR],
            when=now,
            payload_digest=validation.digest,
        ),
    )
    registry.transition(
        manifest.wheel_id,
        manifest.manifest_version,
        "candidate",
        actor_key_id="wheel_publisher-key",
        actor_usage=WheelKeyUsageV2.PUBLISHER,
        signature_b64=_transition_signature(
            registry,
            manifest,
            target="candidate",
            actor_key_id="wheel_publisher-key",
            actor_usage=WheelKeyUsageV2.PUBLISHER,
            private_key=keys[WheelKeyUsageV2.PUBLISHER],
            when=now,
        ),
        occurred_at=now,
    )
    approval = _approval(
        manifest,
        validation,
        "wheel_approver-key",
        keys[WheelKeyUsageV2.APPROVER],
        now,
    )
    registry.approve(
        manifest,
        approval,
        event_signature_b64=_security_event_signature(
            registry,
            manifest,
            event_type="approved",
            target_lifecycle="approved",
            actor_key_id="wheel_approver-key",
            actor_usage=WheelKeyUsageV2.APPROVER,
            private_key=keys[WheelKeyUsageV2.APPROVER],
            when=now,
            payload_digest=approval.digest,
            approved_until=approval.expires_at,
        ),
    )
    activation = _activation(
        manifest,
        approval,
        "wheel_operator-key",
        keys[WheelKeyUsageV2.OPERATOR],
        now,
    )
    active = registry.activate(
        manifest,
        activation,
        event_signature_b64=_security_event_signature(
            registry,
            manifest,
            event_type="active",
            target_lifecycle="active",
            actor_key_id="wheel_operator-key",
            actor_usage=WheelKeyUsageV2.OPERATOR,
            private_key=keys[WheelKeyUsageV2.OPERATOR],
            when=now,
            payload_digest=activation.digest,
            approved_until=approval.expires_at,
            activation_digest=activation.digest,
        ),
    )
    assert active.lifecycle == "active"
    assert (
        registry.select_active(
            manifest.wheel_id,
            manifest.manifest_version,
            profile="local-lab",
            required_template_id="line_kv_parser/v1",
            artifact_digest=manifest.artifact_digest,
            now=now + timedelta(minutes=1),
        )
        == manifest
    )
    assert registry.events[-1].event_type == RegistryEventV2.ACTIVE

    restored = WheelRegistryV2(store, journal_path=tmp_path / "wheel-registry.jsonl")
    restored_record = restored.get(manifest.wheel_id, manifest.manifest_version)
    assert restored_record.last_event_hash == registry.events[-1].event_hash

    journal = tmp_path / "wheel-registry.jsonl"
    journal.write_text(
        journal.read_text(encoding="utf-8").replace(manifest.wheel_id, "tampered-wheel", 1),
        encoding="utf-8",
    )
    with pytest.raises(WheelRegistryErrorV2, match="hash mismatch"):
        WheelRegistryV2(store, journal_path=journal)


def test_registry_rejects_wrong_role_signatures_and_quarantines_on_invalid_usage(
    tmp_path: Path,
) -> None:
    now = datetime.now(UTC)
    keys = _private_keys()
    store = _trust_store(keys)
    registry = WheelRegistryV2(store, journal_path=tmp_path / "wheel-registry.jsonl")
    manifest = _manifest(now)

    registry.add_draft(
        manifest,
        publisher_key_id="wheel_publisher-key",
        signature_b64=sign_learning_contract(manifest, keys[WheelKeyUsageV2.PUBLISHER]),
        registry_signature_b64=_security_event_signature(
            registry,
            manifest,
            event_type="registered",
            target_lifecycle="draft",
            actor_key_id="wheel_publisher-key",
            actor_usage=WheelKeyUsageV2.PUBLISHER,
            private_key=keys[WheelKeyUsageV2.PUBLISHER],
            when=now,
        ),
    )
    for target in ("researched", "specified", "generated"):
        registry.transition(
            manifest.wheel_id,
            manifest.manifest_version,
            target,
            actor_key_id="wheel_publisher-key",
            actor_usage=WheelKeyUsageV2.PUBLISHER,
            signature_b64=_transition_signature(
                registry,
                manifest,
                target=target,
                actor_key_id="wheel_publisher-key",
                actor_usage=WheelKeyUsageV2.PUBLISHER,
                private_key=keys[WheelKeyUsageV2.PUBLISHER],
                when=now,
            ),
            occurred_at=now,
        )

    bad_validation = _validation(
        manifest,
        "wheel_validator-key",
        keys[WheelKeyUsageV2.APPROVER],
        now,
    )
    with pytest.raises(Exception, match="verification failed"):
        registry.record_validation(
            manifest,
            bad_validation,
            event_signature_b64=_security_event_signature(
                registry,
                manifest,
                event_type="validated",
                target_lifecycle="validated",
                actor_key_id="wheel_validator-key",
                actor_usage=WheelKeyUsageV2.VALIDATOR,
                private_key=keys[WheelKeyUsageV2.VALIDATOR],
                when=now,
                payload_digest=bad_validation.digest,
            ),
        )

    good_validation = _validation(
        manifest,
        "wheel_validator-key",
        keys[WheelKeyUsageV2.VALIDATOR],
        now,
    )
    registry.record_validation(
        manifest,
        good_validation,
        event_signature_b64=_security_event_signature(
            registry,
            manifest,
            event_type="validated",
            target_lifecycle="validated",
            actor_key_id="wheel_validator-key",
            actor_usage=WheelKeyUsageV2.VALIDATOR,
            private_key=keys[WheelKeyUsageV2.VALIDATOR],
            when=now,
            payload_digest=good_validation.digest,
        ),
    )
    registry.transition(
        manifest.wheel_id,
        manifest.manifest_version,
        "candidate",
        actor_key_id="wheel_publisher-key",
        actor_usage=WheelKeyUsageV2.PUBLISHER,
        signature_b64=_transition_signature(
            registry,
            manifest,
            target="candidate",
            actor_key_id="wheel_publisher-key",
            actor_usage=WheelKeyUsageV2.PUBLISHER,
            private_key=keys[WheelKeyUsageV2.PUBLISHER],
            when=now,
        ),
        occurred_at=now,
    )
    approval = _approval(
        manifest,
        good_validation,
        "wheel_approver-key",
        keys[WheelKeyUsageV2.APPROVER],
        now,
    )
    registry.approve(
        manifest,
        approval,
        event_signature_b64=_security_event_signature(
            registry,
            manifest,
            event_type="approved",
            target_lifecycle="approved",
            actor_key_id="wheel_approver-key",
            actor_usage=WheelKeyUsageV2.APPROVER,
            private_key=keys[WheelKeyUsageV2.APPROVER],
            when=now,
            payload_digest=approval.digest,
            approved_until=approval.expires_at,
        ),
    )
    activation = _activation(
        manifest,
        approval,
        "wheel_operator-key",
        keys[WheelKeyUsageV2.OPERATOR],
        now,
    )
    registry.activate(
        manifest,
        activation,
        event_signature_b64=_security_event_signature(
            registry,
            manifest,
            event_type="active",
            target_lifecycle="active",
            actor_key_id="wheel_operator-key",
            actor_usage=WheelKeyUsageV2.OPERATOR,
            private_key=keys[WheelKeyUsageV2.OPERATOR],
            when=now,
            payload_digest=activation.digest,
            approved_until=approval.expires_at,
            activation_digest=activation.digest,
        ),
    )

    usage_event = WheelUsageEventV2(
        usage_id="usage-1",
        wheel_id=manifest.wheel_id,
        wheel_version=manifest.manifest_version,
        usage=WheelUsageV2.INVALID_OUTPUT,
        execution_receipt_digest="sha256:" + "9" * 64,
        recorded_at=now + timedelta(minutes=1),
        operator_key_id="wheel_revoker-key",
    )
    quarantined = registry.record_usage(
        usage_event,
        event_signature_b64=_security_event_signature(
            registry,
            manifest,
            event_type="quarantined",
            target_lifecycle="quarantined",
            actor_key_id="wheel_revoker-key",
            actor_usage=WheelKeyUsageV2.REVOKER,
            private_key=keys[WheelKeyUsageV2.REVOKER],
            when=usage_event.recorded_at,
            payload_digest=canonical_digest(usage_event.model_dump(mode="json")),
            approved_until=approval.expires_at,
            activation_digest=activation.digest,
        ),
    )
    assert quarantined.lifecycle == "quarantined"
    with pytest.raises(WheelRegistryErrorV2, match="not active"):
        registry.select_active(
            manifest.wheel_id,
            manifest.manifest_version,
            profile="local-lab",
            required_template_id="line_kv_parser/v1",
            artifact_digest=manifest.artifact_digest,
        )
