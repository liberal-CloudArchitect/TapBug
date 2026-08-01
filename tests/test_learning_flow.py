from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes.domain_contracts_v3 import ExecutionBudgetV3, RunPlanV3
from hermes.evidence import EvidenceBinding, EvidenceStore, HeaderField
from hermes.learning import (
    continue_learning_run,
    generate_learning_capability,
    learning_status_payload,
    start_learning_run,
    validate_learning_capability,
    validate_learning_config,
)
from hermes.learning_contracts import CapabilitySpecV2, LearningStatusV1, ResearchSourceArtifactV1
from hermes.learning_security import LearningKeyUsage, LearningTrustedKey, LearningTrustStoreV1
from hermes.runtime import RunContext
from hermes.security import encode_base64, public_key_bytes
from hermes.vertical_v3 import ExecutionStateV3, NetworkStateV3, VerticalStateV3


def _write_key(path: Path, key: Ed25519PrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)


def _learning_keys(tmp_path: Path) -> tuple[dict[str, Path], Path]:
    mapping: dict[str, Path] = {}
    records: list[LearningTrustedKey] = []
    now = datetime.now(UTC)
    for usage in LearningKeyUsage:
        key = Ed25519PrivateKey.generate()
        key_path = tmp_path / f"{usage.value}.pem"
        _write_key(key_path, key)
        records.append(
            LearningTrustedKey(
                key_id=f"{usage.value}-key",
                public_key=encode_base64(public_key_bytes(key)),
                usages=frozenset({usage}),
                valid_from=now,
            )
        )
        mapping[usage.value] = key_path
    trust_store = LearningTrustStoreV1(keys=tuple(records))
    store_path = tmp_path / "wheel-trust-store.json"
    store_path.write_text(trust_store.model_dump_json(indent=2), encoding="utf-8")
    return mapping, store_path


def _learn_manifests(tmp_path: Path) -> Path:
    image = "registry.example.test/hermes/role-runtime@sha256:" + "d" * 64
    registry = json.loads(
        (Path(__file__).resolve().parents[1] / "prompts" / "r25" / "registry.json").read_text(
            encoding="utf-8"
        )
    )["roles"]
    roles = [
        {
            "version": "1",
            "protocol_version": "1",
            "role": "researcher",
            "prompt_id": "hermes.researcher",
            "prompt_version": "25.0",
            "prompt_sha256": registry["researcher"]["prompt_sha256"],
            "output_contract_id": "hermes.r25.research_facts/v1",
            "signed_at": datetime.now(UTC).isoformat(),
            "image": image,
            "command": (
                "--role",
                "researcher",
                "--prompt-version",
                "25.0",
                "--prompt-sha256",
                registry["researcher"]["prompt_sha256"],
                "--registry-path",
                "prompts/r25/registry.json",
            ),
            "allowed_ipc": ("model_request",),
            "input_schema": "task-envelope/v25",
            "output_schema": "handoff-envelope/v25",
            "limits": {
                "timeout_seconds": 180,
                "cpu_count": 1.0,
                "memory_mib": 256,
                "pids_limit": 64,
                "nofile_limit": 128,
                "max_output_bytes": 65536,
                "tmpfs_mib": 16,
            },
            "key_id": "publisher-key",
            "signature": "c2lnbmF0dXJl",
        },
        {
            "version": "1",
            "protocol_version": "1",
            "role": "capability-planner",
            "prompt_id": "hermes.capability-planner",
            "prompt_version": "25.0",
            "prompt_sha256": registry["capability-planner"]["prompt_sha256"],
            "output_contract_id": "hermes.r25.capability_spec/v2",
            "signed_at": datetime.now(UTC).isoformat(),
            "image": image,
            "command": (
                "--role",
                "capability-planner",
                "--prompt-version",
                "25.0",
                "--prompt-sha256",
                registry["capability-planner"]["prompt_sha256"],
                "--registry-path",
                "prompts/r25/registry.json",
            ),
            "allowed_ipc": ("model_request",),
            "input_schema": "task-envelope/v25",
            "output_schema": "handoff-envelope/v25",
            "limits": {
                "timeout_seconds": 180,
                "cpu_count": 1.0,
                "memory_mib": 256,
                "pids_limit": 64,
                "nofile_limit": 128,
                "max_output_bytes": 65536,
                "tmpfs_mib": 16,
            },
            "key_id": "publisher-key",
            "signature": "c2lnbmF0dXJl",
        },
    ]
    bundle = {"roles": roles}
    path = tmp_path / "learn-role-manifests.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    return path


def _config(tmp_path: Path) -> dict[str, object]:
    key_paths, trust_store = _learning_keys(tmp_path)
    return {
        "runs_root": tmp_path / "runs",
        "prompt_root": Path(__file__).resolve().parents[1],
        "learn_role_manifests": _learn_manifests(tmp_path),
        "wheel_trust_store": trust_store,
        "wheel_publisher_key_file": key_paths["wheel_publisher"],
        "wheel_validator_key_file": key_paths["wheel_validator"],
        "wheel_operator_key_file": key_paths["wheel_operator"],
        "wheel_sandbox_image": "registry.example.test/hermes/wheel@sha256:" + "e" * 64,
        "role_trust_store": tmp_path / "unused-role-trust.json",
    }


def _parent_run(tmp_path: Path) -> tuple[dict[str, object], str, str]:
    config = _config(tmp_path)
    scope = {"profile": "local-lab", "hosts": ["localhost"]}
    context = RunContext(Path(config["runs_root"]), scope, run_id="parent-run-1")
    plan = RunPlanV3(
        run_id=context.run_id,
        target="http://localhost:5000/candidate",
        scope_digest=context.scope_digest,
        provider_id="hermes-acp-restricted",
        model_id="fixture-model",
        prompt_registry_digest="sha256:" + "1" * 64,
        role_manifest_set_digest="sha256:" + "2" * 64,
        roles=(
            "gatekeeper",
            "recon",
            "mapper",
            "web-vuln",
            "api",
            "authz",
            "infra",
            "verifier",
            "reporter",
        ),
        identity_binding_digests={},
        budget=ExecutionBudgetV3(),
        created_at=datetime.now(UTC),
    )
    context.write_json("plan/run-v3.json", plan.model_dump(mode="json"), immutable=True)
    context.write_json(
        "state.json",
        VerticalStateV3(
            run_id=context.run_id,
            execution_state=ExecutionStateV3.COMPLETED,
            network_state=NetworkStateV3.USED,
            requests_planned=15,
            requests_used=15,
            requests_blocked=0,
            current_role=None,
            next_required_action=None,
            cleanup_state="restored",
        ).model_dump(mode="json"),
        immutable=True,
    )
    store = EvidenceStore(context.path)
    ref = store.capture(
        binding=EvidenceBinding(
            evidence_id="parent-evidence-1",
            run_id=context.run_id,
            scope_digest=context.scope_digest,
            task_id="phase4-recon",
            task_input_sha256="sha256:" + "3" * 64,
            role="recon",
            request_id="request-1",
            action_id="action-1",
            action_digest="sha256:" + "4" * 64,
            captured_at=datetime.now(UTC),
        ),
        request_method="GET",
        request_url="http://localhost:5000/candidate",
        request_headers=(HeaderField(name="Accept", value="text/html"),),
        request_body=b"",
        response_status=200,
        response_headers=(HeaderField(name="Content-Type", value="text/plain"),),
        response_body=b"Service: HERMES-LINE\nVersion: 1\n",
    )
    observation = tmp_path / "observation.txt"
    observation.write_text("unknown line protocol", encoding="utf-8")
    return config, ref.evidence_id, str(observation)


def test_validate_learning_config_accepts_repo_prompt_assets(tmp_path: Path) -> None:
    result = validate_learning_config(_config(tmp_path))
    assert result["learning_prompt_registry"] is True
    assert result["learning_wheel_sandbox_image"] is True


def test_start_learning_run_binds_parent_v3_evidence(tmp_path: Path) -> None:
    config, evidence_id, observation = _parent_run(tmp_path)
    status = start_learning_run(
        config,
        parent_run_id="parent-run-1",
        evidence_id=evidence_id,
        observation_file=Path(observation),
    )
    assert status.state == "started"
    payload = learning_status_payload(config, run_id=status.run_id)
    assert payload["parent_run_id"] == "parent-run-1"
    assert payload["parent_evidence_id"] == evidence_id


class _SandboxResult:
    def __init__(self, *, passed: bool = True, output_json: str = "") -> None:
        self.passed = passed
        self.exit_code = 0 if passed else 1
        self.timed_out = False
        self.stdout_preview = ""
        self.stderr_preview = ""
        self.stdout_sha256 = "sha256:" + "a" * 64
        self.stderr_sha256 = "sha256:" + "b" * 64
        self.failure_reason = None if passed else "failed"
        self.output_json = output_json


class _Sandbox:
    def __init__(self, image: str) -> None:
        self.image = image

    def execute(self, artifact_root: Path, *, test_target: str = "/wheel/tests") -> _SandboxResult:
        return _SandboxResult()

    def execute_json(
        self, artifact_root: Path, *, entrypoint: str, input_json: str
    ) -> _SandboxResult:
        value = json.loads(input_json)
        text = value.get("analysis_text", "")
        if "Version:" in text:
            output = {
                "status": "matched",
                "observations": [{"line_number": 1, "key": "service", "value": "hermes-line"}],
                "summary": "matched",
            }
        else:
            output = {"status": "no_match", "observations": [], "summary": "no match"}
        return _SandboxResult(output_json=json.dumps(output, ensure_ascii=False, sort_keys=True))


def test_generate_validate_and_continue_flow(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config, evidence_id, observation = _parent_run(tmp_path)
    status = start_learning_run(
        config,
        parent_run_id="parent-run-1",
        evidence_id=evidence_id,
        observation_file=Path(observation),
    )
    from hermes.learning import (
        activate_learning_capability,
        approve_learning_capability,
        open_learning_run,
    )

    run = open_learning_run(config, status.run_id)
    spec = CapabilitySpecV2(
        run_id=run.context.run_id,
        scope_digest=run.context.scope_digest,
        generated_by_task_id="learning-plan-1",
        wheel_id="line-protocol-parser",
        fixed_fields=("service", "version"),
        known_counterexamples=("plain text",),
        revocation_conditions=("false-positive regression",),
        source_digests=("sha256:" + "9" * 64,),
    )
    run.context.write_json(
        "wheels/capability-spec-v2.json", spec.model_dump(mode="json"), immutable=True
    )
    run.context.write_json(
        "knowledge/research-source-source-1.json",
        ResearchSourceArtifactV1(
            run_id=run.context.run_id,
            scope_digest=run.context.scope_digest,
            generated_by_task_id="research-archive",
            source_id="source-1",
            url="https://docs.example.test/spec",
            license="CC-BY-4.0",
            content_sha256="sha256:" + "1" * 64,
            projection_sha256="sha256:" + "2" * 64,
            archived_path="knowledge/research-sources/source-1/spec.txt",
            projection_path="knowledge/research-sources/source-1/spec.projection.txt",
            captured_at=datetime.now(UTC),
        ).model_dump(mode="json"),
        immutable=True,
    )
    run.context.write_json(
        "state.json",
        LearningStatusV1(
            run_id=run.context.run_id,
            parent_run_id=run.request.parent_run_id,
            scope_digest=run.context.scope_digest,
            state="planned",
            updated_at=datetime.now(UTC),
        ).model_dump(mode="json"),
    )
    monkeypatch.setattr("hermes.learning.DockerSandbox", _Sandbox)
    generated = generate_learning_capability(config, run_id=run.context.run_id)
    assert generated.state == "generated"
    validated = validate_learning_capability(config, run_id=run.context.run_id)
    assert validated.state == "candidate"
    approved = approve_learning_capability(
        config,
        run_id=run.context.run_id,
        key_path=Path(config["wheel_publisher_key_file"]).parent / "wheel_approver.pem",
        rationale="approved for local continuation",
    )
    assert approved.state == "approved"
    activated = activate_learning_capability(
        config,
        run_id=run.context.run_id,
        key_path=Path(config["wheel_publisher_key_file"]).parent / "wheel_operator.pem",
    )
    assert activated.state == "active"
    continued = continue_learning_run(config, run_id=run.context.run_id)
    assert continued.state == "continued"
