#!/usr/bin/env python3
"""Validate prompt assets, build the common role image, and sign role manifests."""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
IMAGE_PATTERN = re.compile(r"^(?:.+@)?sha256:([0-9a-f]{64})$")
EXPECTED_ROLES = {"gatekeeper", "recon", "mapper", "web-vuln", "verifier", "reporter"}
OUTPUT_CONTRACT_IDS = {
    "gatekeeper": "hermes.gate_decision/v2",
    "recon": "hermes.asset_inventory/v2",
    "mapper": "hermes.endpoint_inventory/v2",
    "web-vuln": "hermes.candidate_set/v2",
    "verifier": "hermes.verification_outcome/v2",
    "reporter": "hermes.reporter_acknowledgement/v2",
}


def _runtime_module(root: Path) -> ModuleType:
    path = root / "containers" / "role-runtime" / "runtime.py"
    spec = importlib.util.spec_from_file_location("hermes_role_runtime_assets", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not import role runtime from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _frontmatter(path: Path) -> dict[str, str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0] != "---":
        raise ValueError(f"agent definition has no frontmatter: {path}")
    try:
        end = lines.index("---", 1)
    except ValueError as exc:
        raise ValueError(f"agent frontmatter is not terminated: {path}") from exc
    result: dict[str, str] = {}
    for line in lines[1:end]:
        key, separator, value = line.partition(":")
        if not separator or not key.strip() or not value.strip():
            raise ValueError(f"unsupported agent frontmatter line in {path}: {line!r}")
        result[key.strip()] = value.strip().strip("\"'")
    return result


def validate_assets(root: Path = PROJECT_ROOT) -> dict[str, dict[str, Any]]:
    registry = _runtime_module(root).load_prompt_registry(root)
    if set(registry) != EXPECTED_ROLES:
        raise ValueError("prompt registry must contain exactly the six baseline roles")
    for role, entry in registry.items():
        agent = _frontmatter(root / entry["agent_path"])
        expected = {
            "name": role,
            "prompt_version": entry["prompt_version"],
            "prompt_sha256": entry["prompt_sha256"],
            "output_contract_id": entry["output_contract_id"],
        }
        actual = {key: agent.get(key) for key in expected}
        if actual != expected:
            raise ValueError(f"agent frontmatter does not bind registered prompt for {role!r}")
    return registry


def _immutable_image(value: str) -> str:
    match = IMAGE_PATTERN.fullmatch(value)
    if match is None or set(match.group(1)) == {"0"}:
        raise ValueError("image must use a non-placeholder immutable sha256 digest")
    return value


def build_image(root: Path, *, base_image: str, tag: str) -> None:
    validate_assets(root)
    _immutable_image(base_image)
    subprocess.run(
        [
            "docker",
            "build",
            "--file",
            str(root / "containers" / "role-runtime" / "Dockerfile"),
            "--build-arg",
            f"PYTHON_BASE_IMAGE={base_image}",
            "--tag",
            tag,
            str(root),
        ],
        check=True,
    )


def _load_signer(private_key_path: Path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = serialization.load_pem_private_key(private_key_path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("role manifest signer must be an Ed25519 private key")
    return key.sign


def generate_manifest_bundle(
    root: Path,
    *,
    image: str,
    key_id: str,
    private_key_path: Path,
) -> dict[str, Any]:
    registry = validate_assets(root)
    image = _immutable_image(image)
    if re.fullmatch(r"[A-Za-z0-9._-]{1,128}", key_id) is None:
        raise ValueError("invalid manifest key ID")
    sign = _load_signer(private_key_path)
    roles: list[dict[str, Any]] = []
    for role in sorted(registry):
        entry = registry[role]
        manifest: dict[str, Any] = {
            "version": "1",
            "protocol_version": "1",
            "role": role,
            "prompt_id": f"hermes.{role}",
            "prompt_version": entry["prompt_version"],
            "prompt_sha256": entry["prompt_sha256"],
            "output_contract_id": OUTPUT_CONTRACT_IDS[role],
            "signed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "image": image,
            "command": [
                "--role",
                role,
                "--prompt-version",
                entry["prompt_version"],
                "--prompt-sha256",
                entry["prompt_sha256"],
            ],
            "allowed_ipc": entry["allowed_ipc"],
            "input_schema": "task-envelope/v1",
            "output_schema": "handoff-envelope/v1",
            "limits": {
                "timeout_seconds": 180,
                "cpu_count": 1.0,
                "memory_mib": 256,
                "pids_limit": 64,
                "nofile_limit": 128,
                "max_output_bytes": 65536,
                "tmpfs_mib": 16,
            },
            "key_id": key_id,
        }
        payload = json.dumps(
            manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        manifest["signature"] = base64.urlsafe_b64encode(sign(payload)).decode("ascii").rstrip("=")
        roles.append(manifest)
    return {
        "version": "1",
        "prompt_registry_sha256": (
            "sha256:"
            + hashlib.sha256((root / "prompts" / "registry.json").read_bytes()).hexdigest()
        ),
        "roles": roles,
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--root", type=Path, default=PROJECT_ROOT)
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("validate")
    build = commands.add_parser("build")
    build.add_argument("--base-image", required=True)
    build.add_argument("--tag", required=True)
    manifest = commands.add_parser("manifest")
    manifest.add_argument("--image", required=True)
    manifest.add_argument("--key-id", required=True)
    manifest.add_argument("--private-key", required=True, type=Path)
    manifest.add_argument("--output", required=True, type=Path)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    root = args.root.resolve()
    if args.command == "validate":
        validate_assets(root)
    elif args.command == "build":
        build_image(root, base_image=args.base_image, tag=args.tag)
    else:
        bundle = generate_manifest_bundle(
            root,
            image=args.image,
            key_id=args.key_id,
            private_key_path=args.private_key,
        )
        args.output.write_text(
            json.dumps(bundle, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
