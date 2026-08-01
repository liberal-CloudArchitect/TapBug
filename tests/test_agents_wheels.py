from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes.runtime import RunContext
from hermes.runtime.agents import FixtureAgentRunner, HandoffEnvelope, TaskEnvelope
from hermes.wheels import (
    DockerSandbox,
    RuntimeSelector,
    SourceRecord,
    WheelKind,
    WheelManifest,
    WheelRegistry,
    WheelRegistryError,
    WheelStatus,
    WheelValidator,
    artifact_sha256_for_directory,
    ed25519_signature_verifier,
)
from hermes.wheels.registry import _signature_payload

SCOPE = "sha256:" + "a" * 64
CONTENT = "sha256:" + "b" * 64


def _task() -> TaskEnvelope:
    return TaskEnvelope(run_id="run-1", task_id="task-1", role="recon", scope_digest=SCOPE)


def test_fixture_runner_accepts_only_task_bound_handoff() -> None:
    task = _task()

    def reply(input_task: TaskEnvelope) -> HandoffEnvelope:
        return HandoffEnvelope(
            run_id=input_task.run_id,
            task_id=input_task.task_id,
            role=input_task.role,
            scope_digest=input_task.scope_digest,
            input_sha256=input_task.input_hash(),
            status="completed",
            result={"assets": []},
        )

    result = FixtureAgentRunner({"recon": reply}).run(task)
    assert result.lifecycle == "completed"
    assert result.handoff is not None
    assert result.output_sha256 is not None

    mismatched = HandoffEnvelope(
        run_id="other-run",
        task_id=task.task_id,
        role=task.role,
        scope_digest=task.scope_digest,
        input_sha256=task.input_hash(),
        status="completed",
    )
    rejected = FixtureAgentRunner({"recon": mismatched}).run(task)
    assert rejected.lifecycle == "invalid_handoff"


def _source() -> SourceRecord:
    return SourceRecord(
        url="https://docs.example.test/protocol",
        retrieved_at=datetime.now(UTC),
        content_sha256=CONTENT,
        license="CC-BY-4.0",
        applicability="offline JSON parsing",
    )


def _manifest(root: Path, *, status: WheelStatus = WheelStatus.DRAFT) -> WheelManifest:
    return WheelManifest(
        id="json-parser",
        version="0.1.0",
        kind=WheelKind.PASSIVE_PARSER,
        entrypoint="wheel:parse",
        input_schema="schemas/input.json",
        output_schema="schemas/output.json",
        capabilities=("parse_response",),
        profiles=("recon-only",),
        sources=(_source(),),
        tests=("tests/test_wheel.py",),
        artifact_sha256=artifact_sha256_for_directory(root),
        status=status,
    )


def _safe_artifact(tmp_path: Path) -> Path:
    root = tmp_path / "wheel"
    (root / "tests").mkdir(parents=True)
    (root / "wheel.py").write_text(
        "import json\n\ndef parse(value):\n    return json.loads(value)\n", encoding="utf-8"
    )
    (root / "tests" / "test_wheel.py").write_text(
        "def test_placeholder():\n    assert True\n", encoding="utf-8"
    )
    return root


def test_validator_rejects_network_and_dynamic_execution(tmp_path: Path) -> None:
    root = _safe_artifact(tmp_path)
    manifest = _manifest(root)
    assert WheelValidator().validate(manifest, root).passed

    (root / "wheel.py").write_text("import httpx\nexec('x = 1')\n", encoding="utf-8")
    bad_manifest = _manifest(root)
    report = WheelValidator().validate(bad_manifest, root)
    assert not report.passed
    assert any("forbidden import httpx" in issue for issue in report.violations)
    assert any("dynamic execution" in issue for issue in report.violations)


def test_registry_requires_validation_signed_approval_and_untampered_artifact(
    tmp_path: Path,
) -> None:
    root = _safe_artifact(tmp_path)
    manifest = _manifest(root)
    signing_key = Ed25519PrivateKey.generate()
    public_key = signing_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    registry = WheelRegistry(ed25519_signature_verifier(public_key))
    registry.add(manifest)
    for state in (WheelStatus.RESEARCHED, WheelStatus.SPECIFIED, WheelStatus.GENERATED):
        registry.transition(manifest.id, manifest.version, state)
    report = WheelValidator().validate(manifest, root)
    registry.record_validation(manifest.id, manifest.version, report)
    registry.transition(manifest.id, manifest.version, WheelStatus.CANDIDATE)
    signature = (
        base64.urlsafe_b64encode(signing_key.sign(_signature_payload(manifest)))
        .decode()
        .rstrip("=")
    )
    approved = registry.approve(
        manifest.id, manifest.version, approved_by="reviewer", signature=signature
    )
    assert approved.status == WheelStatus.APPROVED
    registry.transition(manifest.id, manifest.version, WheelStatus.ACTIVE)
    assert (
        registry.select(
            manifest.id, manifest.version, profile="recon-only", artifact_root=root
        ).status
        == WheelStatus.ACTIVE
    )

    (root / "wheel.py").write_text("def parse(value): return value\n", encoding="utf-8")
    with pytest.raises(WheelRegistryError, match="hash mismatch"):
        registry.select(manifest.id, manifest.version, profile="recon-only", artifact_root=root)


def test_docker_sandbox_command_has_no_network_and_no_privilege(tmp_path: Path) -> None:
    root = _safe_artifact(tmp_path)
    command = DockerSandbox().build_command(root)
    assert command[:3] == ["docker", "run", "--rm"]
    assert ["--network", "none"] == command[
        command.index("--network") : command.index("--network") + 2
    ]
    assert "--read-only" in command
    assert command[command.index("--cap-drop") + 1] == "ALL"
    assert "no-new-privileges" in command


def test_registry_rejects_an_unverifiable_wheel_approval(tmp_path: Path) -> None:
    root = _safe_artifact(tmp_path)
    manifest = _manifest(root)
    registry = WheelRegistry()
    registry.add(manifest)
    for state in (WheelStatus.RESEARCHED, WheelStatus.SPECIFIED, WheelStatus.GENERATED):
        registry.transition(manifest.id, manifest.version, state)
    registry.record_validation(
        manifest.id, manifest.version, WheelValidator().validate(manifest, root)
    )
    registry.transition(manifest.id, manifest.version, WheelStatus.CANDIDATE)

    with pytest.raises(WheelRegistryError, match="signature was rejected"):
        registry.approve(
            manifest.id, manifest.version, approved_by="reviewer", signature="not-verifiable"
        )


def _active_registry(
    root: Path,
    *,
    context: RunContext | None = None,
    expires_at: datetime | None = None,
) -> tuple[WheelRegistry, WheelManifest, bytes]:
    manifest = _manifest(root).model_copy(update={"expires_at": expires_at})
    signing_key = Ed25519PrivateKey.generate()
    public_key = signing_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    registry = WheelRegistry(ed25519_signature_verifier(public_key), context=context)
    registry.add(manifest)
    for state in (WheelStatus.RESEARCHED, WheelStatus.SPECIFIED, WheelStatus.GENERATED):
        registry.transition(manifest.id, manifest.version, state)
    registry.record_validation(
        manifest.id, manifest.version, WheelValidator().validate(manifest, root)
    )
    registry.transition(manifest.id, manifest.version, WheelStatus.CANDIDATE)
    signature = (
        base64.urlsafe_b64encode(signing_key.sign(_signature_payload(manifest)))
        .decode()
        .rstrip("=")
    )
    registry.approve(manifest.id, manifest.version, approved_by="reviewer", signature=signature)
    registry.transition(manifest.id, manifest.version, WheelStatus.ACTIVE)
    return registry, manifest, public_key


def test_registry_replays_persistent_lifecycle_and_revocation(tmp_path: Path) -> None:
    root = _safe_artifact(tmp_path)
    context = RunContext(tmp_path / "runs", {"profile": "local-lab"}, run_id="wheel-run")
    registry, manifest, public_key = _active_registry(root, context=context)
    journal = context.path / "wheels" / "registry.jsonl"
    assert journal.exists()
    assert len(journal.read_text(encoding="utf-8").splitlines()) == len(registry.events)

    restored = WheelRegistry(ed25519_signature_verifier(public_key), context=context)
    selector = RuntimeSelector(restored, profile="recon-only")
    assert (
        selector.select(
            manifest.id,
            manifest.version,
            artifact_root=root,
            required_capability="parse_response",
        ).status
        is WheelStatus.ACTIVE
    )

    restored.transition(manifest.id, manifest.version, WheelStatus.QUARANTINED, actor="reviewer")
    restored.transition(manifest.id, manifest.version, WheelStatus.REVOKED, actor="reviewer")
    replayed = WheelRegistry(ed25519_signature_verifier(public_key), context=context)
    with pytest.raises(WheelRegistryError, match="not active"):
        RuntimeSelector(replayed, profile="recon-only").select(
            manifest.id, manifest.version, artifact_root=root
        )
    assert replayed.get(manifest.id, manifest.version).status is WheelStatus.REVOKED


def test_runtime_selector_requires_approved_profile_hash_and_unexpired_wheel(
    tmp_path: Path,
) -> None:
    root = _safe_artifact(tmp_path)
    expires_at = datetime.now(UTC) + timedelta(seconds=1)
    registry, manifest, _public_key = _active_registry(root, expires_at=expires_at)
    selector = RuntimeSelector(registry, profile="recon-only")

    with pytest.raises(WheelRegistryError, match="approval has expired"):
        selector.select(
            manifest.id,
            manifest.version,
            artifact_root=root,
            now=expires_at + timedelta(seconds=1),
        )
    with pytest.raises(WheelRegistryError, match="profile"):
        RuntimeSelector(registry, profile="production").select(
            manifest.id, manifest.version, artifact_root=root
        )
    with pytest.raises(WheelRegistryError, match="required capability"):
        selector.select(
            manifest.id,
            manifest.version,
            artifact_root=root,
            required_capability="network",
        )
    (root / "wheel.py").write_text("def parse(value): return value\n", encoding="utf-8")
    with pytest.raises(WheelRegistryError, match="hash mismatch"):
        selector.select(manifest.id, manifest.version, artifact_root=root)
