from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
from pathlib import Path
from types import ModuleType

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes.prompts_v3 import PromptRegistryV3
from hermes.runtime.agents import HandoffEnvelope, RoleManifest, RoleTrustStore

ROOT = Path(__file__).resolve().parents[1]
ROLES = {
    "gatekeeper",
    "recon",
    "mapper",
    "web-vuln",
    "api",
    "authz",
    "infra",
    "verifier",
    "reporter",
}
BRANCHES = {"web-vuln", "api", "authz", "infra"}


def _module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


builder = _module("role_builder_v3_test", ROOT / "scripts" / "build_role_image_v3.py")
v2_builder = _module("role_builder_v2_compat_test", ROOT / "scripts" / "build_role_image.py")
role_runtime = _module("role_runtime_v3_test", ROOT / "containers" / "role-runtime" / "runtime.py")


def _copy_v3_assets(destination: Path) -> None:
    shutil.copytree(ROOT / "prompts" / "v3", destination / "prompts" / "v3")
    shutil.copytree(ROOT / "agents" / "v3", destination / "agents" / "v3")


def test_v3_registry_binds_exact_nine_role_prompt_set() -> None:
    registry, collection_digest = builder.load_registry(ROOT)
    assert set(registry) == ROLES
    assert {entry["prompt_version"] for entry in registry.values()} == {"3.0", "3.1"}
    assert all(entry["prompt_sha256"].startswith("sha256:") for entry in registry.values())
    assert {registry[role]["output_contract_id"] for role in BRANCHES} == {
        "hermes.branch_operation/v3"
    }
    assert {tuple(registry[role]["operations"]) for role in BRANCHES} == {
        ("assessment", "cross_review")
    }
    document = json.loads((ROOT / "prompts" / "v3" / "registry.json").read_text())
    assert document["version"] == "3"
    assert document["collection_sha256"] == collection_digest


def test_v3_prompts_declare_identity_contract_and_branch_operations() -> None:
    registry = builder.validate_assets(ROOT)
    for role, entry in registry.items():
        prompt = (ROOT / entry["prompt_path"]).read_text(encoding="utf-8")
        assert f"Prompt ID: `hermes.{role}`" in prompt
        assert f"Prompt version: `{entry['prompt_version']}`" in prompt
        assert f"Output contract: `{entry['output_contract_id']}`" in prompt
    for role in BRANCHES:
        prompt = (ROOT / registry[role]["prompt_path"]).read_text(encoding="utf-8")
        assert "`assessment`" in prompt
        assert "`cross_review`" in prompt
        assert "Self-review" in prompt


def test_v3_registry_rejects_prompt_tamper_and_collection_tamper(tmp_path: Path) -> None:
    _copy_v3_assets(tmp_path)
    prompt = tmp_path / "prompts" / "v3" / "api.md"
    prompt.write_text(prompt.read_text(encoding="utf-8") + "tampered\n", encoding="utf-8")
    with pytest.raises(builder.V3AssetError, match="prompt digest mismatch"):
        builder.load_registry(tmp_path)

    shutil.rmtree(tmp_path)
    _copy_v3_assets(tmp_path)
    registry_path = tmp_path / "prompts" / "v3" / "registry.json"
    document = json.loads(registry_path.read_text(encoding="utf-8"))
    document["roles"]["api"]["operations"] = ["assessment"]
    registry_path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(builder.V3AssetError, match="collection digest mismatch"):
        builder.load_registry(tmp_path)


def test_v3_registry_rejects_agent_frontmatter_mismatch(tmp_path: Path) -> None:
    _copy_v3_assets(tmp_path)
    agent = tmp_path / "agents" / "v3" / "infra.md"
    agent.write_text(
        agent.read_text(encoding="utf-8").replace(
            "output_contract_id: hermes.branch_operation/v3",
            "output_contract_id: hermes.reporter_acknowledgement/v3",
        ),
        encoding="utf-8",
    )
    with pytest.raises(builder.V3AssetError, match="frontmatter"):
        builder.load_registry(tmp_path)


def test_v3_builder_signs_nine_manifests_bound_to_independent_registry(tmp_path: Path) -> None:
    private_key = Ed25519PrivateKey.generate()
    private_path = tmp_path / "publisher.pem"
    private_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    image = "registry.example.test/hermes/role-runtime@sha256:" + "c" * 64
    bundle = builder.generate_manifest_bundle(
        ROOT, image=image, key_id="publisher-v3", private_key_path=private_path
    )
    public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    trust = RoleTrustStore({"publisher-v3": public})
    registry, collection_digest = builder.load_registry(ROOT)

    assert bundle["version"] == "3"
    assert bundle["prompt_collection_sha256"] == collection_digest
    registry_bytes = (ROOT / "prompts" / "v3" / "registry.json").read_bytes()
    assert bundle["prompt_registry_sha256"] == (
        "sha256:" + hashlib.sha256(registry_bytes).hexdigest()
    )
    assert {entry["role"] for entry in bundle["roles"]} == ROLES
    for raw in bundle["roles"]:
        manifest = RoleManifest.model_validate(raw)
        trust.verify(manifest)
        PromptRegistryV3(ROOT).verify_manifest(manifest)
        entry = registry[manifest.role]
        assert manifest.prompt_id == entry["prompt_id"]
        assert manifest.prompt_version == entry["prompt_version"]
        assert manifest.prompt_sha256 == entry["prompt_sha256"]
        assert manifest.output_contract_id == entry["output_contract_id"]
        assert manifest.input_schema == "task-envelope/v3"
        assert manifest.output_schema == "handoff-envelope/v3"
        assert manifest.command[-2:] == ("--registry-path", "prompts/v3/registry.json")


def test_v3_builder_does_not_change_v2_asset_contract() -> None:
    v2_registry = v2_builder.validate_assets(ROOT)
    assert set(v2_registry) == {
        "gatekeeper",
        "recon",
        "mapper",
        "web-vuln",
        "verifier",
        "reporter",
    }
    assert all(entry["prompt_version"] == "2.0" for entry in v2_registry.values())


def test_v3_builder_rejects_placeholder_image() -> None:
    with pytest.raises(builder.V3AssetError, match="non-placeholder"):
        builder._immutable_image("python:3.11-slim@sha256:" + "0" * 64)


def test_role_runtime_loads_v3_registry_and_emits_typed_v3_handoff() -> None:
    registry = role_runtime.load_prompt_registry(ROOT, "prompts/v3/registry.json")
    assert set(registry) == ROLES
    task = {
        "version": "3",
        "run_id": "runtime-v3",
        "task_id": "phase4-assessment-api",
        "role": "api",
        "scope_digest": "sha256:" + "a" * 64,
        "payload": {"operation": "assessment"},
        "evidence_refs": [],
        "evidence_artifact_refs": [],
        "allowed_actions": [],
        "request_budget": 0,
        "evidence_required": False,
        "timeout_seconds": 180,
        "created_at": "2026-07-14T00:00:00Z",
    }
    assessment = {
        "version": "3",
        "run_id": task["run_id"],
        "scope_digest": task["scope_digest"],
        "generated_by_task_id": task["task_id"],
        "assessment_id": "assessment-api",
        "operation": "assessment",
        "branch": "api",
        "endpoint_inventory_digest": "sha256:" + "b" * 64,
        "prompt_id": "hermes.api",
        "prompt_version": "3.0",
        "prompt_sha256": "sha256:" + "c" * 64,
        "candidates": [],
        "coverage": {
            "version": "3",
            "endpoints_considered": 0,
            "candidates_emitted": 0,
            "candidates_blocked": 0,
            "candidates_inconclusive": 0,
            "not_tested_reasons": [],
        },
    }
    input_hash = role_runtime.canonical_task_hash(task)
    message = role_runtime._model_result(
        task,
        input_hash,
        {
            "type": "model_result",
            "ok": True,
            "payload": {
                "status": "completed",
                "result": assessment,
                "evidence_ref_ids": [],
            },
        },
    )

    handoff = HandoffEnvelope.model_validate(message["handoff"])
    assert handoff.version == "3"
    assert handoff.result.contract_id == "hermes.branch_assessment/v3"
    assert handoff.result.operation == "assessment"
