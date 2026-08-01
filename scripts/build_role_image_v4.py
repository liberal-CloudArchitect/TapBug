#!/usr/bin/env python3
"""Validate the isolated V4 prompt set and build/sign its nine role manifests."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = Path("prompts/v4/registry.json")
IMAGE_PATTERN = re.compile(r"^(?:.+@)?sha256:([0-9a-f]{64})$")
DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
ROLE_PATTERN = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
EXPECTED_ROLES = {
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
OUTPUT_CONTRACT_IDS = {
    "gatekeeper": "hermes.gate_decision/v4",
    "recon": "hermes.asset_inventory/v4",
    "mapper": "hermes.surface_map/v4",
    "web-vuln": "hermes.branch_operation/v4",
    "api": "hermes.branch_operation/v4",
    "authz": "hermes.branch_operation/v4",
    "infra": "hermes.branch_operation/v4",
    "verifier": "hermes.verification_outcome_set/v4",
    "reporter": "hermes.reporter_acknowledgement/v4",
}
OPERATIONS = {
    "gatekeeper": ("gate",),
    "recon": ("recon",),
    "mapper": ("map",),
    "web-vuln": ("assessment", "cross_review"),
    "api": ("assessment", "cross_review"),
    "authz": ("assessment", "cross_review"),
    "infra": ("assessment", "cross_review"),
    "verifier": ("verification",),
    "reporter": ("reporting",),
}
ENTRY_FIELDS = {
    "agent_path",
    "prompt_path",
    "prompt_id",
    "prompt_version",
    "prompt_sha256",
    "output_contract_id",
    "operations",
    "allowed_ipc",
}


class V4AssetError(ValueError):
    """The V4 registry, prompt set, or agent binding is not trustworthy."""


def _canonical_digest(value: object) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _file_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _contained_file(root: Path, relative: object, required_parent: Path) -> Path:
    if not isinstance(relative, str) or not relative:
        raise V4AssetError("registry path must be a non-empty relative string")
    path = (root / relative).resolve()
    expected_parent = (root / required_parent).resolve()
    try:
        path.relative_to(expected_parent)
    except ValueError as exc:
        raise V4AssetError(f"registry path escapes {required_parent}: {relative!r}") from exc
    if not path.is_file():
        raise V4AssetError(f"registered asset is not a file: {relative!r}")
    return path


def _frontmatter(path: Path) -> dict[str, str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0] != "---":
        raise V4AssetError(f"agent definition has no frontmatter: {path}")
    try:
        end = lines.index("---", 1)
    except ValueError as exc:
        raise V4AssetError(f"agent frontmatter is not terminated: {path}") from exc
    result: dict[str, str] = {}
    for line in lines[1:end]:
        key, separator, value = line.partition(":")
        if not separator or not key.strip() or not value.strip():
            raise V4AssetError(f"unsupported agent frontmatter line in {path}: {line!r}")
        key = key.strip()
        if key in result:
            raise V4AssetError(f"duplicate agent frontmatter key in {path}: {key!r}")
        result[key] = value.strip().strip("\"'")
    return result


def load_registry(root: Path = PROJECT_ROOT) -> tuple[dict[str, dict[str, Any]], str]:
    """Load and fully validate the V4 registry without consulting workflow code."""

    registry_path = root / REGISTRY_PATH
    try:
        document = json.loads(registry_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise V4AssetError(f"could not load V4 prompt registry: {exc}") from exc
    if not isinstance(document, dict) or set(document) != {
        "version",
        "collection_sha256",
        "roles",
    }:
        raise V4AssetError("V4 prompt registry has unexpected top-level fields")
    roles = document.get("roles")
    if document.get("version") != "4" or not isinstance(roles, dict):
        raise V4AssetError("V4 prompt registry must be a version-4 role mapping")
    if set(roles) != EXPECTED_ROLES:
        raise V4AssetError("V4 prompt registry must contain exactly the nine Phase 5 roles")
    collection_digest = _canonical_digest(roles)
    if document.get("collection_sha256") != collection_digest:
        raise V4AssetError("V4 prompt registry collection digest mismatch")

    verified: dict[str, dict[str, Any]] = {}
    for role, raw in roles.items():
        if ROLE_PATTERN.fullmatch(role) is None or not isinstance(raw, dict):
            raise V4AssetError(f"invalid V4 role entry: {role!r}")
        if set(raw) != ENTRY_FIELDS:
            raise V4AssetError(f"V4 registry entry has unexpected fields for {role!r}")
        prompt = _contained_file(root, raw["prompt_path"], Path("prompts/v4"))
        agent = _contained_file(root, raw["agent_path"], Path("agents/v4"))
        digest = raw["prompt_sha256"]
        if not isinstance(digest, str) or DIGEST_PATTERN.fullmatch(digest) is None:
            raise V4AssetError(f"invalid V4 prompt digest for {role!r}")
        if _file_digest(prompt) != digest:
            raise V4AssetError(f"V4 prompt digest mismatch for {role!r}")
        prompt_version = raw["prompt_version"]
        if raw["prompt_id"] != f"hermes.{role}":
            raise V4AssetError(f"invalid V4 prompt ID for {role!r}")
        if (
            not isinstance(prompt_version, str)
            or re.fullmatch(r"4\.[0-9]+", prompt_version) is None
        ):
            raise V4AssetError(f"invalid V4 prompt version for {role!r}")
        if raw["output_contract_id"] != OUTPUT_CONTRACT_IDS[role]:
            raise V4AssetError(f"invalid V4 output contract for {role!r}")
        if raw["operations"] != list(OPERATIONS[role]):
            raise V4AssetError(f"invalid V4 operation declaration for {role!r}")
        ipc = raw["allowed_ipc"]
        if (
            not isinstance(ipc, list)
            or not ipc
            or len(ipc) != len(set(ipc))
            or any(item not in {"model_request", "gateway_action"} for item in ipc)
        ):
            raise V4AssetError(f"invalid V4 IPC declaration for {role!r}")
        expected = {
            "name": role,
            "prompt_id": f"hermes.{role}",
            "prompt_version": prompt_version,
            "prompt_sha256": digest,
            "output_contract_id": OUTPUT_CONTRACT_IDS[role],
        }
        if {key: _frontmatter(agent).get(key) for key in expected} != expected:
            raise V4AssetError(f"V4 agent frontmatter does not bind prompt for {role!r}")
        verified[role] = dict(raw)
    return verified, collection_digest


def validate_assets(root: Path = PROJECT_ROOT) -> dict[str, dict[str, Any]]:
    return load_registry(root)[0]


def _immutable_image(value: str) -> str:
    match = IMAGE_PATTERN.fullmatch(value)
    if match is None or set(match.group(1)) == {"0"}:
        raise V4AssetError("image must use a non-placeholder immutable sha256 digest")
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
        raise V4AssetError("role manifest signer must be an Ed25519 private key")
    return key.sign


def generate_manifest_bundle(
    root: Path,
    *,
    image: str,
    key_id: str,
    private_key_path: Path,
) -> dict[str, Any]:
    registry, collection_digest = load_registry(root)
    image = _immutable_image(image)
    if re.fullmatch(r"[A-Za-z0-9._-]{1,128}", key_id) is None:
        raise V4AssetError("invalid manifest key ID")
    sign = _load_signer(private_key_path)
    roles: list[dict[str, Any]] = []
    signed_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    for role in sorted(registry):
        entry = registry[role]
        manifest: dict[str, Any] = {
            "version": "1",
            "protocol_version": "1",
            "role": role,
            "prompt_id": entry["prompt_id"],
            "prompt_version": entry["prompt_version"],
            "prompt_sha256": entry["prompt_sha256"],
            "output_contract_id": entry["output_contract_id"],
            "signed_at": signed_at,
            "image": image,
            "command": [
                "--role",
                role,
                "--prompt-version",
                entry["prompt_version"],
                "--prompt-sha256",
                entry["prompt_sha256"],
                "--registry-path",
                REGISTRY_PATH.as_posix(),
            ],
            "allowed_ipc": entry["allowed_ipc"],
            "input_schema": "task-envelope/v4",
            "output_schema": "handoff-envelope/v4",
            "limits": {
                "timeout_seconds": 300,
                "cpu_count": 1.0,
                "memory_mib": 256,
                "pids_limit": 64,
                "nofile_limit": 128,
                "max_output_bytes": 65_536,
                "tmpfs_mib": 16,
            },
            "key_id": key_id,
        }
        payload = json.dumps(
            manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        manifest["signature"] = base64.urlsafe_b64encode(sign(payload)).decode("ascii").rstrip("=")
        roles.append(manifest)
    registry_path = root / REGISTRY_PATH
    return {
        "version": "4",
        "prompt_registry_sha256": _file_digest(registry_path),
        "prompt_collection_sha256": collection_digest,
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
