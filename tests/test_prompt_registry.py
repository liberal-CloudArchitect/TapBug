from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from hermes.domain_contracts import ContractEnvelope, GateDecisionV2
from hermes.runtime.agents import RoleManifest, RoleTrustStore, TaskEnvelope
from hermes.runtime.agents.contracts import (
    FinalHandoffMessage,
    RoleManifestError,
    role_manifest_signing_payload,
)
from hermes.security import KeyUsage, TrustedKey, TrustStoreV2, encode_base64, sign_ed25519

ROOT = Path(__file__).resolve().parents[1]
ROLES = {"gatekeeper", "recon", "mapper", "web-vuln", "verifier", "reporter"}


def _module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runtime = _module("role_runtime_test", ROOT / "containers" / "role-runtime" / "runtime.py")
builder = _module("role_builder_test", ROOT / "scripts" / "build_role_image.py")


def test_registry_binds_six_role_prompts_to_agent_frontmatter() -> None:
    registry = builder.validate_assets(ROOT)
    assert set(registry) == ROLES
    assert all(entry["prompt_version"] == "2.0" for entry in registry.values())
    assert {entry["output_contract_id"] for entry in registry.values()} == {
        "hermes.gate_decision/v2",
        "hermes.asset_inventory/v2",
        "hermes.endpoint_inventory/v2",
        "hermes.candidate_set/v2",
        "hermes.verification_outcome/v2",
        "hermes.reporter_acknowledgement/v2",
    }
    assert all(entry["prompt_sha256"].startswith("sha256:") for entry in registry.values())


def test_registry_rejects_changed_prompt_content(tmp_path: Path) -> None:
    shutil.copytree(ROOT / "prompts", tmp_path / "prompts")
    prompt = tmp_path / "prompts" / "recon" / "v2.md"
    prompt.write_text(prompt.read_text(encoding="utf-8") + "tampered\n", encoding="utf-8")
    with pytest.raises(runtime.RegistryError, match="digest mismatch"):
        runtime.load_prompt_registry(tmp_path)


def test_manifest_binds_prompt_version_and_hash_and_has_valid_signature(tmp_path: Path) -> None:
    private_key = Ed25519PrivateKey.generate()
    private_path = tmp_path / "publisher.pem"
    private_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    image = "registry.example.test/hermes/role-runtime@sha256:" + "b" * 64
    bundle = builder.generate_manifest_bundle(
        ROOT, image=image, key_id="publisher-1", private_key_path=private_path
    )
    public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    trust = RoleTrustStore({"publisher-1": public})
    registry = runtime.load_prompt_registry(ROOT)

    assert {entry["role"] for entry in bundle["roles"]} == ROLES
    for raw in bundle["roles"]:
        manifest = RoleManifest.model_validate(raw)
        trust.verify(manifest)
        role = registry[manifest.role]
        assert manifest.prompt_id == f"hermes.{manifest.role}"
        assert manifest.prompt_version == role["prompt_version"]
        assert manifest.prompt_sha256 == role["prompt_sha256"]
        assert manifest.output_contract_id == role["output_contract_id"]
        assert role["prompt_version"] in manifest.command
        assert role["prompt_sha256"] in manifest.command


def test_historical_manifest_verification_uses_the_signing_time() -> None:
    """An expired publisher key must not invalidate an already-signed run artifact."""
    private_key = Ed25519PrivateKey.generate()
    signed_at = datetime.now(UTC) - timedelta(days=2)
    store = TrustStoreV2(
        keys=(
            TrustedKey(
                key_id="expired-publisher",
                public_key=encode_base64(
                    private_key.public_key().public_bytes(
                        serialization.Encoding.Raw, serialization.PublicFormat.Raw
                    )
                ),
                usages=frozenset({KeyUsage.ROLE_MANIFEST}),
                valid_from=signed_at - timedelta(hours=1),
                valid_until=signed_at + timedelta(hours=1),
            ),
        )
    )
    unsigned = RoleManifest(
        role="gatekeeper",
        prompt_id="hermes.gatekeeper",
        prompt_version="2.0",
        prompt_sha256="sha256:" + "a" * 64,
        output_contract_id="hermes.gate_decision/v2",
        signed_at=signed_at,
        image="registry.example.test/hermes/role-runtime@sha256:" + "b" * 64,
        command=("role-runtime",),
        key_id="expired-publisher",
        signature="unsigned",
    )
    manifest = unsigned.model_copy(
        update={"signature": sign_ed25519(private_key, role_manifest_signing_payload(unsigned))}
    )
    trust = RoleTrustStore(
        {
            "expired-publisher": private_key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        },
        trust_store_v2=store,
    )

    with pytest.raises(RoleManifestError, match="signature was rejected"):
        trust.verify(manifest)
    trust.verify_historical(manifest)


def test_role_runtime_uses_host_jsonl_and_returns_bound_handoff() -> None:
    registry = runtime.load_prompt_registry(ROOT)
    entry = registry["mapper"]
    task = TaskEnvelope(
        run_id="prompt-run",
        task_id="mapper-1",
        role="mapper",
        scope_digest="sha256:" + "a" * 64,
        payload={"entrypoint": "/health"},
    )
    process = subprocess.Popen(
        [
            sys.executable,
            str(ROOT / "containers" / "role-runtime" / "runtime.py"),
            "--root",
            str(ROOT),
            "--role",
            "mapper",
            "--prompt-version",
            entry["prompt_version"],
            "--prompt-sha256",
            entry["prompt_sha256"],
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stdin is not None and process.stdout is not None
    process.stdin.write(
        json.dumps(
            {
                "type": "task",
                "task": task.model_dump(mode="json"),
                "input_sha256": task.input_hash(),
            }
        )
        + "\n"
    )
    process.stdin.flush()
    model_request = json.loads(process.stdout.readline())
    assert model_request["type"] == "model_request"
    assert model_request["input"]["prompt_sha256"] == entry["prompt_sha256"]

    process.stdin.write(
        json.dumps(
            {
                "type": "model_result",
                "request_id": model_request["request_id"],
                "ok": True,
                "payload": {
                    "status": "completed",
                    "result": {"candidates": []},
                    "evidence_ref_ids": [],
                },
            }
        )
        + "\n"
    )
    process.stdin.flush()
    handoff = json.loads(process.stdout.readline())
    process.stdin.close()
    assert process.wait(timeout=5) == 0
    assert handoff["type"] == "handoff"
    assert handoff["handoff"]["role"] == "mapper"
    assert handoff["handoff"]["input_sha256"] == task.input_hash()
    assert handoff["handoff"]["version"] == "2"
    assert handoff["handoff"]["result"]["contract_id"] == "hermes.endpoint_inventory/v2"
    assert handoff["handoff"]["result"]["contract_version"] == "2"
    assert handoff["handoff"]["result"]["payload"] == {"candidates": []}


def test_role_runtime_wraps_a_valid_v2_payload_and_legacy_result_fails_closed() -> None:
    task = TaskEnvelope(
        run_id="runtime-v2",
        task_id="gatekeeper-v2",
        role="gatekeeper",
        scope_digest="sha256:" + "a" * 64,
    )
    payload = GateDecisionV2(
        run_id=task.run_id,
        scope_digest=task.scope_digest,
        generated_by_task_id=task.task_id,
        decision="allowed",
        target="http://localhost:49152/candidate",
        resolved_ip="127.0.0.1",
        reason="the fixed loopback fixture is in scope",
    ).model_dump(mode="json")
    message = runtime._model_result(
        task.model_dump(mode="json"),
        task.input_hash(),
        {
            "type": "model_result",
            "ok": True,
            "payload": {"status": "completed", "result": payload},
        },
    )
    handoff = FinalHandoffMessage.model_validate(message)
    assert handoff.handoff.version == "2"
    assert isinstance(handoff.handoff.result, ContractEnvelope)
    assert handoff.handoff.result.payload_sha256.startswith("sha256:")

    legacy = runtime._model_result(
        task.model_dump(mode="json"),
        task.input_hash(),
        {
            "type": "model_result",
            "ok": True,
            "payload": {"status": "completed", "result": {"decision": "allowed"}},
        },
    )
    with pytest.raises(ValidationError):
        FinalHandoffMessage.model_validate(legacy)


def test_dockerfile_requires_an_operator_supplied_digest() -> None:
    dockerfile = (ROOT / "containers" / "role-runtime" / "Dockerfile").read_text(encoding="utf-8")
    assert "ARG PYTHON_BASE_IMAGE=" in dockerfile
    assert "@sha256:" + "0" * 64 in dockerfile
    with pytest.raises(ValueError, match="non-placeholder"):
        builder._immutable_image("python:3.11-slim@sha256:" + "0" * 64)


def test_recon_runtime_requests_exactly_one_host_gateway_get() -> None:
    registry = runtime.load_prompt_registry(ROOT)
    entry = registry["recon"]
    task = TaskEnvelope(
        run_id="recon-run",
        task_id="recon-1",
        role="recon",
        scope_digest="sha256:" + "a" * 64,
        payload={"target": "http://localhost:49152/candidate"},
        allowed_actions=("http_get",),
        request_budget=1,
    )
    process = subprocess.Popen(
        [
            sys.executable,
            str(ROOT / "containers" / "role-runtime" / "runtime.py"),
            "--root",
            str(ROOT),
            "--role",
            "recon",
            "--prompt-version",
            entry["prompt_version"],
            "--prompt-sha256",
            entry["prompt_sha256"],
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stdin is not None and process.stdout is not None
    process.stdin.write(
        json.dumps(
            {
                "type": "task",
                "task": task.model_dump(mode="json"),
                "input_sha256": task.input_hash(),
            }
        )
        + "\n"
    )
    process.stdin.flush()
    request = json.loads(process.stdout.readline())
    assert request["type"] == "gateway_action"
    assert request["action"]["kind"] == "http_get"
    assert request["action"]["method"] == "GET"
    evidence = {
        "id": "e1",
        "kind": "response",
        "sha256": "sha256:" + "b" * 64,
        "path": "evidence/e1.json",
        "redacted": True,
    }
    process.stdin.write(
        json.dumps(
            {
                "type": "gateway_result",
                "request_id": request["request_id"],
                "ok": True,
                "payload": {"status_code": 200, "headers": {}, "evidence_ref": evidence},
            }
        )
        + "\n"
    )
    process.stdin.flush()
    model = json.loads(process.stdout.readline())
    assert model["type"] == "model_request"
    assert model["input"]["evidence_refs"] == [evidence]
    process.stdin.write(
        json.dumps(
            {
                "type": "model_result",
                "request_id": model["request_id"],
                "ok": True,
                "payload": {
                    "result": {"observed": True},
                    "evidence_ref_ids": ["e1"],
                },
            }
        )
        + "\n"
    )
    process.stdin.flush()
    handoff = json.loads(process.stdout.readline())
    assert handoff["handoff"]["evidence_refs"] == [evidence]
    process.stdin.close()
    assert process.wait(timeout=5) == 0
