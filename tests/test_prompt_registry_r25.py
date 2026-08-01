from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes.prompts_r25 import PromptRegistryR25
from hermes.runtime.agents import RoleManifest, RoleTrustStore, TaskEnvelope

ROOT = Path(__file__).resolve().parents[1]
ROLES = {"researcher", "capability-planner"}


def _module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


builder = _module("r25_role_builder_test", ROOT / "scripts" / "build_r25_role_image.py")
runtime = _module("role_runtime_r25_test", ROOT / "containers" / "role-runtime" / "runtime.py")


def _copy_r25_assets(destination: Path) -> None:
    shutil.copytree(ROOT / "prompts" / "r25", destination / "prompts" / "r25")
    shutil.copytree(ROOT / "agents" / "r25", destination / "agents" / "r25")


def test_r25_registry_binds_exact_two_role_prompt_set() -> None:
    registry, collection_digest = builder.load_registry(ROOT)
    assert set(registry) == ROLES
    assert {entry["prompt_version"] for entry in registry.values()} == {"25.1"}
    assert {tuple(entry["operations"]) for entry in registry.values()} == {("research",), ("plan",)}
    assert all(entry["prompt_sha256"].startswith("sha256:") for entry in registry.values())
    document = json.loads((ROOT / "prompts" / "r25" / "registry.json").read_text())
    assert document["version"] == "25"
    assert document["collection_sha256"] == collection_digest


def test_r25_prompts_declare_identity_contract_and_provenance_rules() -> None:
    registry = builder.validate_assets(ROOT)
    for role, entry in registry.items():
        prompt = (ROOT / entry["prompt_path"]).read_text(encoding="utf-8")
        assert f"Prompt ID: `hermes.{role}`" in prompt
        assert f"Prompt version: `{entry['prompt_version']}`" in prompt
        assert f"Output contract: `{entry['output_contract_id']}`" in prompt
    researcher = (ROOT / registry["researcher"]["prompt_path"]).read_text(encoding="utf-8")
    planner = (ROOT / registry["capability-planner"]["prompt_path"]).read_text(encoding="utf-8")
    assert "source_sha256" in researcher
    assert "Return only research facts" in researcher
    assert "`line_kv_parser/v1`" in planner
    assert "max_requests = 0" in planner


def test_r25_registry_rejects_prompt_tamper_and_collection_tamper(tmp_path: Path) -> None:
    _copy_r25_assets(tmp_path)
    prompt = tmp_path / "prompts" / "r25" / "researcher.md"
    prompt.write_text(prompt.read_text(encoding="utf-8") + "tampered\n", encoding="utf-8")
    with pytest.raises(builder.R25AssetError, match="prompt digest mismatch"):
        builder.load_registry(tmp_path)

    shutil.rmtree(tmp_path)
    _copy_r25_assets(tmp_path)
    registry_path = tmp_path / "prompts" / "r25" / "registry.json"
    document = json.loads(registry_path.read_text(encoding="utf-8"))
    document["roles"]["researcher"]["operations"] = ["plan"]
    registry_path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(builder.R25AssetError, match="collection digest mismatch"):
        builder.load_registry(tmp_path)


def test_r25_registry_rejects_agent_frontmatter_mismatch(tmp_path: Path) -> None:
    _copy_r25_assets(tmp_path)
    agent = tmp_path / "agents" / "r25" / "capability-planner.md"
    agent.write_text(
        agent.read_text(encoding="utf-8").replace(
            "output_contract_id: hermes.r25.capability_spec/v2",
            "output_contract_id: hermes.r25.research_facts/v1",
        ),
        encoding="utf-8",
    )
    with pytest.raises(builder.R25AssetError, match="frontmatter"):
        builder.load_registry(tmp_path)


def test_r25_builder_signs_two_manifests_bound_to_isolated_registry(tmp_path: Path) -> None:
    private_key = Ed25519PrivateKey.generate()
    private_path = tmp_path / "wheel-publisher.pem"
    private_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    image = "registry.example.test/hermes/role-runtime@sha256:" + "d" * 64
    bundle = builder.generate_manifest_bundle(
        ROOT, image=image, key_id="wheel-publisher-r25", private_key_path=private_path
    )
    public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    trust = RoleTrustStore({"wheel-publisher-r25": public})
    registry, collection_digest = builder.load_registry(ROOT)

    assert bundle["version"] == "25"
    assert bundle["publisher_scope"] == "wheel"
    assert bundle["prompt_collection_sha256"] == collection_digest
    registry_bytes = (ROOT / "prompts" / "r25" / "registry.json").read_bytes()
    assert bundle["prompt_registry_sha256"] == (
        "sha256:" + hashlib.sha256(registry_bytes).hexdigest()
    )
    assert {entry["role"] for entry in bundle["roles"]} == ROLES
    for raw in bundle["roles"]:
        manifest = RoleManifest.model_validate(raw)
        trust.verify(manifest)
        PromptRegistryR25(ROOT).verify_manifest(manifest)
        entry = registry[manifest.role]
        assert manifest.prompt_id == entry["prompt_id"]
        assert manifest.prompt_version == entry["prompt_version"]
        assert manifest.prompt_sha256 == entry["prompt_sha256"]
        assert manifest.output_contract_id == entry["output_contract_id"]
        assert manifest.input_schema == "task-envelope/v25"
        assert manifest.output_schema == "handoff-envelope/v25"
        assert manifest.command[-2:] == ("--registry-path", "prompts/r25/registry.json")


def test_r25_builder_rejects_placeholder_image() -> None:
    with pytest.raises(builder.R25AssetError, match="non-placeholder"):
        builder._immutable_image("python:3.11-slim@sha256:" + "0" * 64)


def test_role_runtime_loads_r25_registry_and_emits_r25_handoff_shape() -> None:
    registry = runtime.load_prompt_registry(ROOT, "prompts/r25/registry.json")
    assert set(registry) == ROLES
    task = TaskEnvelope(
        version="1",
        run_id="r25-run",
        task_id="researcher-1",
        role="researcher",
        scope_digest="sha256:" + "a" * 64,
        payload={
            "learning_request_id": "learn-1",
            "source_bundle_id": "bundle-1",
            "operation": "research",
        },
    ).model_dump(mode="json")
    task["version"] = "25"
    input_hash = runtime.canonical_task_hash(task)
    message = runtime._model_result(
        task,
        input_hash,
        {
            "type": "model_result",
            "ok": True,
            "payload": {
                "status": "completed",
                "result": {"facts": [], "rationale": "sources were insufficient"},
                "evidence_ref_ids": [],
            },
        },
    )

    handoff = message["handoff"]
    assert handoff["version"] == "25"
    assert handoff["result"]["contract_id"] == "hermes.r25.research_facts/v1"
    assert handoff["result"]["contract_version"] == "1"
    assert handoff["result"]["payload"] == {"facts": [], "rationale": "sources were insufficient"}


def test_role_runtime_process_smoke_supports_r25_registry_path() -> None:
    registry = runtime.load_prompt_registry(ROOT, "prompts/r25/registry.json")
    entry = registry["capability-planner"]
    task = TaskEnvelope(
        version="1",
        run_id="r25-process",
        task_id="planner-1",
        role="capability-planner",
        scope_digest="sha256:" + "b" * 64,
        payload={"operation": "plan", "template_id": "line_kv_parser/v1"},
    ).model_dump(mode="json")
    task["version"] = "25"
    process = subprocess.Popen(
        [
            sys.executable,
            str(ROOT / "containers" / "role-runtime" / "runtime.py"),
            "--root",
            str(ROOT),
            "--role",
            "capability-planner",
            "--prompt-version",
            entry["prompt_version"],
            "--prompt-sha256",
            entry["prompt_sha256"],
            "--registry-path",
            "prompts/r25/registry.json",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stdin is not None and process.stdout is not None
    process.stdin.write(
        json.dumps(
            {"type": "task", "task": task, "input_sha256": runtime.canonical_task_hash(task)}
        )
        + "\n"
    )
    process.stdin.flush()
    model_request = json.loads(process.stdout.readline())
    assert model_request["type"] == "model_request"
    assert model_request["input"]["role"] == "capability-planner"
    assert model_request["input"]["prompt_sha256"] == entry["prompt_sha256"]
    assert model_request["operation"] == "extract"
    process.stdin.write(
        json.dumps(
            {
                "type": "model_result",
                "request_id": model_request["request_id"],
                "ok": True,
                "payload": {
                    "status": "completed",
                    "result": {"template_id": "line_kv_parser/v1", "rules": []},
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
    assert handoff["handoff"]["version"] == "25"
    assert handoff["handoff"]["result"]["contract_id"] == "hermes.r25.capability_spec/v2"
    assert handoff["handoff"]["result"]["contract_version"] == "2"
