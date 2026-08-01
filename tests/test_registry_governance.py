from __future__ import annotations

import base64
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes.wheels import (
    CapabilityExecutionError,
    CapabilityHost,
    RuntimeSelector,
    SourceRecord,
    ValidationReport,
    WheelKind,
    WheelManifest,
    WheelRegistry,
    WheelRegistryError,
    WheelStatus,
    artifact_sha256_for_directory,
    ed25519_signature_verifier,
)
from hermes.wheels.registry import _signature_payload


def _artifact(tmp_path: Path) -> Path:
    root = tmp_path / "artifact"
    root.mkdir()
    (root / "wheel.py").write_text("def parse(value): return value\n", encoding="utf-8")
    return root


def _manifest(root: Path) -> WheelManifest:
    return WheelManifest(
        id="safe-parser",
        version="1.0.0",
        kind=WheelKind.PASSIVE_PARSER,
        entrypoint="wheel:parse",
        input_schema="input.json",
        output_schema="output.json",
        capabilities=("parse_response",),
        profiles=("local-lab",),
        sources=(
            SourceRecord(
                url="https://docs.example.test/parser",
                retrieved_at=datetime.now(UTC),
                content_sha256="sha256:" + "a" * 64,
                license="CC-BY-4.0",
                applicability="offline parsing",
            ),
        ),
        tests=("wheel.py",),
        artifact_sha256=artifact_sha256_for_directory(root),
    )


@dataclass(frozen=True)
class _Actors:
    publisher: str
    validator: str
    approver: str
    operator: str
    capability_host: str
    sign_manifest: Callable[[bytes], str]


def _activate(
    registry: WheelRegistry, manifest: WheelManifest, root: Path, *, actors: _Actors
) -> None:
    registry.add(manifest, actor=actors.publisher)
    registry.research(manifest.id, manifest.version, actor=actors.publisher)
    registry.specify(manifest.id, manifest.version, actor=actors.publisher)
    registry.record_generation(manifest.id, manifest.version, actor=actors.publisher)
    registry.record_validation(
        manifest.id,
        manifest.version,
        ValidationReport(
            wheel_id=manifest.id,
            wheel_version=manifest.version,
            artifact_sha256=manifest.artifact_sha256,
            passed=True,
            validated_at=datetime.now(UTC),
        ),
        actor=actors.validator,
    )
    registry.nominate(manifest.id, manifest.version, actor=actors.publisher)
    signature = actors.sign_manifest(_signature_payload(manifest))
    registry.approve(
        manifest.id,
        manifest.version,
        approved_by="human-review",
        signature=signature,
        actor=actors.approver,
    )
    registry.activate(manifest.id, manifest.version, actor=actors.operator)


def _signed_registry(
    tmp_path: Path, manifest_key: Ed25519PrivateKey
) -> tuple[WheelRegistry, _Actors]:
    actor_keys = {
        name: Ed25519PrivateKey.generate()
        for name in ("publisher", "validator", "approver", "operator", "capability-host", "revoker")
    }
    public_key = manifest_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )

    def sign_event(payload: bytes, actor: str) -> str:
        return base64.urlsafe_b64encode(actor_keys[actor].sign(payload)).decode().rstrip("=")

    def verify_event(payload: bytes, signature: str, actor: str) -> bool:
        try:
            encoded = signature + "=" * (-len(signature) % 4)
            actor_keys[actor].public_key().verify(base64.urlsafe_b64decode(encoded), payload)
        except (KeyError, ValueError):
            return False
        except Exception:
            return False
        return True

    actors = _Actors(
        publisher="publisher",
        validator="validator",
        approver="approver",
        operator="operator",
        capability_host="capability-host",
        sign_manifest=lambda payload: (
            base64.urlsafe_b64encode(manifest_key.sign(payload)).decode().rstrip("=")
        ),
    )
    registry = WheelRegistry(
        ed25519_signature_verifier(public_key),
        journal_path=tmp_path / "registry.jsonl",
        journal_signer=sign_event,
        journal_verifier=verify_event,
        actor_roles={name: name for name in actor_keys},
        require_signed_journal=True,
    )
    return registry, actors


def test_security_lifecycle_cannot_use_generic_transition(tmp_path: Path) -> None:
    root = _artifact(tmp_path)
    manifest = _manifest(root)
    registry = WheelRegistry()
    registry.add(manifest)
    for state in (WheelStatus.RESEARCHED, WheelStatus.SPECIFIED, WheelStatus.GENERATED):
        registry.transition(manifest.id, manifest.version, state)
    with pytest.raises(WheelRegistryError, match="dedicated"):
        registry.transition(manifest.id, manifest.version, WheelStatus.VALIDATED)
    with pytest.raises(WheelRegistryError, match="dedicated"):
        registry.transition(manifest.id, manifest.version, WheelStatus.APPROVED)


def test_signed_hash_chained_journal_rejects_tampering_and_requires_roles(tmp_path: Path) -> None:
    root = _artifact(tmp_path)
    manifest_key = Ed25519PrivateKey.generate()
    registry, actors = _signed_registry(tmp_path, manifest_key)
    manifest = _manifest(root)
    with pytest.raises(WheelRegistryError, match="required registry role"):
        registry.add(manifest, actor="validator")
    _activate(registry, manifest, root, actors=actors)
    assert registry.select(manifest.id, manifest.version, profile="local-lab", artifact_root=root)

    journal = tmp_path / "registry.jsonl"
    journal.write_text(
        journal.read_text(encoding="utf-8").replace("safe-parser", "evil-parser", 1),
        encoding="utf-8",
    )
    with pytest.raises(WheelRegistryError, match="hash chain mismatch"):
        _signed_registry(tmp_path, manifest_key)


@dataclass(frozen=True)
class _FixtureResult:
    passed: bool = True
    exit_code: int | None = 0
    timed_out: bool = False
    stdout_preview: str = ""
    stderr_preview: str = ""
    stdout_sha256: str = "sha256:" + "a" * 64
    stderr_sha256: str = "sha256:" + "b" * 64
    failure_reason: str | None = None


@dataclass(frozen=True)
class _JsonResult:
    passed: bool = True
    output_json: str = '{"items": []}'
    stdout_sha256: str = "sha256:" + "a" * 64
    stderr_sha256: str = "sha256:" + "b" * 64
    failure_reason: str | None = None


class _Sandbox:
    def __init__(self, result: _JsonResult) -> None:
        self.result = result
        self.calls: list[str] = []

    def execute(self, artifact_root: Path, *, test_target: str = "/wheel/tests") -> _FixtureResult:
        return _FixtureResult()

    def execute_json(self, artifact_root: Path, *, entrypoint: str, input_json: str) -> _JsonResult:
        self.calls.append(input_json)
        return self.result


def test_capability_host_uses_sandbox_and_quarantines_invalid_output(tmp_path: Path) -> None:
    root = _artifact(tmp_path)
    manifest_key = Ed25519PrivateKey.generate()
    registry, actors = _signed_registry(tmp_path, manifest_key)
    manifest = _manifest(root)
    _activate(registry, manifest, root, actors=actors)
    host = CapabilityHost(
        RuntimeSelector(registry, profile="local-lab"),
        _Sandbox(_JsonResult()),
        actor=actors.capability_host,
    )
    execution = host.execute(
        manifest.id,
        manifest.version,
        artifact_root=root,
        input_payload={"sample": "value"},
        required_capability="parse_response",
    )
    assert execution.output == {"items": []}

    unsafe_host = CapabilityHost(
        RuntimeSelector(registry, profile="local-lab"),
        _Sandbox(_JsonResult(output_json="not-json")),
        actor=actors.capability_host,
    )
    with pytest.raises(CapabilityExecutionError, match="not JSON"):
        unsafe_host.execute(
            manifest.id, manifest.version, artifact_root=root, input_payload={"sample": "value"}
        )
    assert registry.get(manifest.id, manifest.version).status is WheelStatus.QUARANTINED


def test_two_reviewed_false_positives_quarantine_an_active_wheel(tmp_path: Path) -> None:
    root = _artifact(tmp_path)
    manifest_key = Ed25519PrivateKey.generate()
    registry, actors = _signed_registry(tmp_path, manifest_key)
    manifest = _manifest(root)
    _activate(registry, manifest, root, actors=actors)
    for _ in range(2):
        registry.record_usage(
            manifest.id,
            manifest.version,
            outcome="false_positive",
            human_reviewed=True,
            false_positive=True,
            actor=actors.capability_host,
        )
    assert registry.get(manifest.id, manifest.version).status is WheelStatus.QUARANTINED
