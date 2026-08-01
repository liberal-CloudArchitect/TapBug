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

from hermes.prompts_v4 import PromptRegistryV4
from hermes.runtime.agents import RoleManifest, RoleTrustStore

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


builder = _module("role_builder_v4_test", ROOT / "scripts" / "build_role_image_v4.py")
role_runtime = _module("role_runtime_v4_test", ROOT / "containers" / "role-runtime" / "runtime.py")


def _copy_v4_assets(destination: Path) -> None:
    shutil.copytree(ROOT / "prompts" / "v4", destination / "prompts" / "v4")
    shutil.copytree(ROOT / "agents" / "v4", destination / "agents" / "v4")


def test_v4_registry_binds_exact_nine_role_prompt_set() -> None:
    registry, collection_digest = builder.load_registry(ROOT)
    assert set(registry) == ROLES
    assert {entry["prompt_version"] for entry in registry.values()} == {"4.0", "4.1"}
    assert all(entry["prompt_sha256"].startswith("sha256:") for entry in registry.values())
    assert {registry[role]["output_contract_id"] for role in BRANCHES} == {
        "hermes.branch_operation/v4"
    }
    assert {tuple(registry[role]["operations"]) for role in BRANCHES} == {
        ("assessment", "cross_review")
    }
    document = json.loads((ROOT / "prompts" / "v4" / "registry.json").read_text())
    assert document["version"] == "4"
    assert document["collection_sha256"] == collection_digest


def test_v4_registry_rejects_prompt_tamper_and_collection_tamper(tmp_path: Path) -> None:
    _copy_v4_assets(tmp_path)
    prompt = tmp_path / "prompts" / "v4" / "api.md"
    prompt.write_text(prompt.read_text(encoding="utf-8") + "tampered\n", encoding="utf-8")
    with pytest.raises(builder.V4AssetError, match="prompt digest mismatch"):
        builder.load_registry(tmp_path)

    shutil.rmtree(tmp_path)
    _copy_v4_assets(tmp_path)
    registry_path = tmp_path / "prompts" / "v4" / "registry.json"
    document = json.loads(registry_path.read_text(encoding="utf-8"))
    document["roles"]["api"]["operations"] = ["assessment"]
    registry_path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(builder.V4AssetError, match="collection digest mismatch"):
        builder.load_registry(tmp_path)


def test_v4_builder_signs_nine_manifests_bound_to_independent_registry(tmp_path: Path) -> None:
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
        ROOT, image=image, key_id="publisher-v4", private_key_path=private_path
    )
    public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    trust = RoleTrustStore({"publisher-v4": public})
    registry, collection_digest = builder.load_registry(ROOT)

    assert bundle["version"] == "4"
    assert bundle["prompt_collection_sha256"] == collection_digest
    registry_bytes = (ROOT / "prompts" / "v4" / "registry.json").read_bytes()
    assert bundle["prompt_registry_sha256"] == (
        "sha256:" + hashlib.sha256(registry_bytes).hexdigest()
    )
    assert {entry["role"] for entry in bundle["roles"]} == ROLES
    for raw in bundle["roles"]:
        manifest = RoleManifest.model_validate(raw)
        trust.verify(manifest)
        PromptRegistryV4(ROOT).verify_manifest(manifest)
        entry = registry[manifest.role]
        assert manifest.prompt_id == entry["prompt_id"]
        assert manifest.prompt_version == entry["prompt_version"]
        assert manifest.prompt_sha256 == entry["prompt_sha256"]
        assert manifest.output_contract_id == entry["output_contract_id"]
        assert manifest.input_schema == "task-envelope/v4"
        assert manifest.output_schema == "handoff-envelope/v4"
        assert manifest.command[-2:] == ("--registry-path", "prompts/v4/registry.json")


def test_role_runtime_loads_v4_registry() -> None:
    registry = role_runtime.load_prompt_registry(ROOT, "prompts/v4/registry.json")
    assert set(registry) == ROLES
