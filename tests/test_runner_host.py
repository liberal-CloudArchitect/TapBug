from __future__ import annotations

import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes.runtime.actions import ActionKind, ProposedAction
from hermes.runtime.agents import (
    DockerRoleSandbox,
    GatewayActionRequest,
    RoleManifest,
    RoleManifestError,
    RoleTrustStore,
    RunnerHost,
    SandboxLimits,
    TaskEnvelope,
    load_role_manifest,
    role_manifest_signing_payload,
)
from hermes.runtime.errors import PolicyDenied

SCOPE = "sha256:" + "a" * 64
IMAGE = "registry.example.test/hermes/recon@sha256:" + "b" * 64


def _manifest(
    private_key: Ed25519PrivateKey,
    *,
    allowed_ipc: tuple[str, ...] = ("gateway_action",),
    output_limit: int = 16_384,
) -> RoleManifest:
    unsigned = RoleManifest(
        role="recon",
        image=IMAGE,
        command=("/opt/hermes/agent",),
        allowed_ipc=allowed_ipc,
        limits=SandboxLimits(max_output_bytes=output_limit),
        key_id="publisher-1",
        signature="placeholder",
    )
    signature = private_key.sign(role_manifest_signing_payload(unsigned))
    return unsigned.model_copy(
        update={"signature": signature.hex()},
    )


def _trust_store(private_key: Ed25519PrivateKey) -> RoleTrustStore:
    public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return RoleTrustStore({"publisher-1": public})


def _task(*, actions: tuple[str, ...] = ("http_get",)) -> TaskEnvelope:
    return TaskEnvelope(
        run_id="host-run",
        task_id="recon-1",
        role="recon",
        scope_digest=SCOPE,
        allowed_actions=actions,
        request_budget=1,
        timeout_seconds=5,
    )


def test_task_hash_omits_volatile_creation_time_for_resume() -> None:
    task = _task()
    reopened = task.model_copy(update={"created_at": datetime.now(UTC) + timedelta(days=1)})
    assert reopened.input_hash() == task.input_hash()


def test_role_manifest_requires_a_trusted_signature_and_immutable_image() -> None:
    private_key = Ed25519PrivateKey.generate()
    manifest = _manifest(private_key)
    store = _trust_store(private_key)
    store.verify(manifest)

    with pytest.raises(RoleManifestError, match="signature"):
        store.verify(manifest.model_copy(update={"image": IMAGE.replace("b", "c", 1)}))

    with pytest.raises(ValueError, match="immutable image"):
        RoleManifest(
            role="recon",
            image="registry.example.test/hermes/recon:latest",
            command=("agent",),
            key_id="publisher-1",
            signature="not-used",
        )


def test_role_manifest_can_be_loaded_then_checked_against_the_trust_store(tmp_path: Path) -> None:
    private_key = Ed25519PrivateKey.generate()
    manifest_path = tmp_path / "recon-role.json"
    manifest_path.write_text(_manifest(private_key).model_dump_json(), encoding="utf-8")
    loaded = load_role_manifest(manifest_path)
    _trust_store(private_key).verify(loaded)


def test_docker_role_sandbox_removes_network_privileges_and_parent_environment() -> None:
    private_key = Ed25519PrivateKey.generate()
    command = DockerRoleSandbox(labels={"com.hermes.run_id": "run-1"}).build_command(
        _manifest(private_key)
    )
    assert command[:3] == ("docker", "run", "--rm")
    assert command[command.index("--pull") + 1] == "never"
    assert ("--network", "none") == command[
        command.index("--network") : command.index("--network") + 2
    ]
    assert "--read-only" in command
    assert command[command.index("--cap-drop") + 1] == "ALL"
    assert command[command.index("--user") + 1] == "65532:65532"
    assert "com.hermes.run_id=run-1" in command
    assert command[-2:] == (IMAGE, "/opt/hermes/agent")


def _popen_script(script: Path, environments: list[object] | None = None):
    def factory(_command: tuple[str, ...], **kwargs: object) -> subprocess.Popen[bytes]:
        if environments is not None:
            environments.append(kwargs["env"])
        return subprocess.Popen([sys.executable, str(script)], **kwargs)  # type: ignore[arg-type]

    return factory


def test_runner_host_routes_only_manifest_and_task_authorized_gateway_actions(
    tmp_path: Path,
) -> None:
    script = tmp_path / "agent.py"
    script.write_text(
        "import json, sys\n"
        "initial = json.loads(sys.stdin.readline())\n"
        "task = initial['task']\n"
        "print(json.dumps({'type': 'gateway_action', 'request_id': 'request-1', "
        "'action': {'kind': 'http_get', 'target': 'https://allowed.example.test/', "
        "'method': 'GET'}, 'url': 'https://allowed.example.test/'}), flush=True)\n"
        "json.loads(sys.stdin.readline())\n"
        "handoff = {'type': 'handoff', 'handoff': {'run_id': task['run_id'], "
        "'task_id': task['task_id'], 'role': task['role'], 'scope_digest': task['scope_digest'], "
        "'input_sha256': initial['input_sha256'], 'status': 'completed', "
        "'result': {'assets': []}}}\n"
        "print(json.dumps(handoff), flush=True)\n",
        encoding="utf-8",
    )
    private_key = Ed25519PrivateKey.generate()
    received: list[GatewayActionRequest] = []
    child_environments: list[object] = []

    def gateway(request: GatewayActionRequest, _task: TaskEnvelope) -> dict[str, object]:
        received.append(request)
        return {"status_code": 200}

    host = RunnerHost(
        manifests={"recon": _manifest(private_key)},
        trust_store=_trust_store(private_key),
        gateway_handler=gateway,
        popen_factory=_popen_script(script, child_environments),
    )
    result = host.run(_task())
    assert result.lifecycle == "completed"
    assert len(received) == 1
    assert child_environments == [{}]
    assert received[0].action == ProposedAction(
        kind=ActionKind.HTTP_GET,
        target="https://allowed.example.test/",
        method="GET",
    )


def test_runner_host_denies_ungranted_ipc_without_calling_gateway(tmp_path: Path) -> None:
    script = tmp_path / "agent.py"
    script.write_text(
        "import json, sys\n"
        "initial = json.loads(sys.stdin.readline())\n"
        "task = initial['task']\n"
        "print(json.dumps({'type': 'gateway_action', 'request_id': 'request-1', "
        "'action': {'kind': 'http_get', 'target': 'https://allowed.example.test/', "
        "'method': 'GET'}, 'url': 'https://allowed.example.test/'}), flush=True)\n"
        "reply = json.loads(sys.stdin.readline())\n"
        "assert reply['ok'] is False\n"
        "print(json.dumps({'type': 'handoff', 'handoff': {'run_id': task['run_id'], "
        "'task_id': task['task_id'], 'role': task['role'], 'scope_digest': task['scope_digest'], "
        "'input_sha256': initial['input_sha256'], 'status': 'completed', "
        "'result': {}}}), flush=True)\n",
        encoding="utf-8",
    )
    private_key = Ed25519PrivateKey.generate()
    host = RunnerHost(
        manifests={"recon": _manifest(private_key, allowed_ipc=())},
        trust_store=_trust_store(private_key),
        gateway_handler=lambda _request, _task: pytest.fail("gateway must not run"),
        popen_factory=_popen_script(script),
    )
    assert host.run(_task()).lifecycle == "completed"


def test_runner_host_kills_a_role_that_exceeds_its_output_cap(tmp_path: Path) -> None:
    script = tmp_path / "noisy.py"
    script.write_text(
        "import sys\nsys.stdout.write('x' * 2048)\nsys.stdout.flush()\n", encoding="utf-8"
    )
    private_key = Ed25519PrivateKey.generate()
    host = RunnerHost(
        manifests={"recon": _manifest(private_key, output_limit=256)},
        trust_store=_trust_store(private_key),
        popen_factory=_popen_script(script),
    )
    result = host.run(_task(actions=()))
    assert result.lifecycle == "failed"
    assert result.error is not None and "output limit" in result.error
    assert result.failure_layer == "runtime"
    assert result.failure_code == "role_output_limit_exceeded"


def test_runner_host_bounds_large_protocol_validation_errors(tmp_path: Path) -> None:
    script = tmp_path / "malformed.py"
    script.write_text(
        "import json, sys\n"
        "print(json.dumps({'type': 'unknown', 'padding': 'x' * 10000}), flush=True)\n",
        encoding="utf-8",
    )
    private_key = Ed25519PrivateKey.generate()
    host = RunnerHost(
        manifests={"recon": _manifest(private_key)},
        trust_store=_trust_store(private_key),
        popen_factory=_popen_script(script),
    )

    result = host.run(_task(actions=()))

    assert result.lifecycle == "invalid_handoff"
    assert result.error is not None and len(result.error) == 2000
    assert result.failure_code == "protocol_message_invalid"


def test_runner_host_classifies_container_exit_without_handoff(tmp_path: Path) -> None:
    script = tmp_path / "exit.py"
    script.write_text("raise SystemExit(17)\n", encoding="utf-8")
    private_key = Ed25519PrivateKey.generate()
    host = RunnerHost(
        manifests={"recon": _manifest(private_key)},
        trust_store=_trust_store(private_key),
        popen_factory=_popen_script(script),
    )

    result = host.run(_task(actions=()))

    assert result.lifecycle == "failed"
    assert result.failure_layer == "docker"
    assert result.failure_code == "container_exit_nonzero"
    assert result.retryable is True


def test_runner_host_preserves_parent_gateway_root_cause_when_role_exits(
    tmp_path: Path,
) -> None:
    script = tmp_path / "denied.py"
    script.write_text(
        "import json, sys\n"
        "json.loads(sys.stdin.readline())\n"
        "print(json.dumps({'type': 'gateway_action', 'request_id': 'request-1', "
        "'action': {'kind': 'http_get', 'target': 'https://allowed.example.test/', "
        "'method': 'GET'}, 'url': 'https://allowed.example.test/'}), flush=True)\n"
        "json.loads(sys.stdin.readline())\n"
        "raise SystemExit(17)\n",
        encoding="utf-8",
    )
    private_key = Ed25519PrivateKey.generate()
    host = RunnerHost(
        manifests={"recon": _manifest(private_key)},
        trust_store=_trust_store(private_key),
        gateway_handler=lambda _request, _task: (_ for _ in ()).throw(
            PolicyDenied("scope rejected the request")
        ),
        popen_factory=_popen_script(script),
    )

    result = host.run(_task())

    assert result.lifecycle == "failed"
    assert result.failure_layer == "gateway"
    assert result.failure_code == "gateway_policy_denied"
    assert result.request_id == "request-1"
    assert result.exit_code == 17


def test_runner_host_preserves_billing_failure_when_role_returns_blocked(
    tmp_path: Path,
) -> None:
    script = tmp_path / "provider_blocked.py"
    script.write_text(
        "import json, sys\n"
        "initial = json.loads(sys.stdin.readline())\n"
        "task = initial['task']\n"
        "print(json.dumps({'type': 'model_request', 'request_id': 'model-1', "
        "'operation': 'extract', 'input': {}}), flush=True)\n"
        "json.loads(sys.stdin.readline())\n"
        "print(json.dumps({'type': 'handoff', 'handoff': {"
        "'run_id': task['run_id'], 'task_id': task['task_id'], 'role': task['role'], "
        "'scope_digest': task['scope_digest'], 'input_sha256': initial['input_sha256'], "
        "'status': 'blocked', 'error': 'parent model rejected request'}}), flush=True)\n",
        encoding="utf-8",
    )

    class ProviderBillingError(RuntimeError):
        pass

    private_key = Ed25519PrivateKey.generate()
    host = RunnerHost(
        manifests={"recon": _manifest(private_key, allowed_ipc=("model_request",))},
        trust_store=_trust_store(private_key),
        model_handler=lambda _request, _task: (_ for _ in ()).throw(
            ProviderBillingError("provider balance exhausted")
        ),
        popen_factory=_popen_script(script),
    )

    result = host.run(_task(actions=()))

    assert result.lifecycle == "failed"
    assert result.failure_layer == "provider"
    assert result.failure_code == "provider_billing_unavailable"
    assert result.request_id == "model-1"
    assert result.retryable is False
