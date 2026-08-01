"""Host-side verification for the isolated Phase 5 V4 prompt registry."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .domain_contracts import canonical_digest
from .runtime.agents import RoleManifest, RoleManifestError
from .runtime.agents.contracts import ROLE_OUTPUT_CONTRACT_IDS_V4

V4_REGISTRY_RELATIVE = Path("prompts/v4/registry.json")
V4_ROLES = frozenset(ROLE_OUTPUT_CONTRACT_IDS_V4)
V4_BRANCH_ROLES = frozenset({"web-vuln", "api", "authz", "infra"})


class PromptRegistryV4:
    """Verify V4 prompt content, collection digest, operations and manifests."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        path = (self.root / V4_REGISTRY_RELATIVE).resolve()
        try:
            path.relative_to(self.root)
            raw = path.read_bytes()
            document = json.loads(raw)
            roles = document["roles"]
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RoleManifestError(f"could not load V4 prompt registry: {exc}") from exc
        if (
            set(document) != {"version", "collection_sha256", "roles"}
            or document.get("version") != "4"
            or not isinstance(roles, dict)
            or set(roles) != V4_ROLES
        ):
            raise RoleManifestError("V4 prompt registry must bind the exact nine-role set")
        if document.get("collection_sha256") != canonical_digest(roles):
            raise RoleManifestError("V4 prompt collection digest mismatch")
        self.digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        self.collection_digest = str(document["collection_sha256"])
        self.roles: dict[str, dict[str, Any]] = {}
        for role, raw_entry in roles.items():
            if not isinstance(raw_entry, dict):
                raise RoleManifestError(f"V4 prompt entry for {role!r} is malformed")
            entry = dict(raw_entry)
            prompt_path = (self.root / str(entry.get("prompt_path", ""))).resolve()
            agent_path = (self.root / str(entry.get("agent_path", ""))).resolve()
            try:
                prompt_path.relative_to((self.root / "prompts/v4").resolve())
            except ValueError as exc:
                raise RoleManifestError(f"V4 prompt path for {role!r} escapes its root") from exc
            try:
                agent_path.relative_to((self.root / "agents/v4").resolve())
            except ValueError as exc:
                raise RoleManifestError(f"V4 agent path for {role!r} escapes its root") from exc
            if not prompt_path.is_file():
                raise RoleManifestError(f"V4 prompt path for {role!r} is invalid")
            if not agent_path.is_file():
                raise RoleManifestError(f"V4 agent path for {role!r} is invalid")
            actual = "sha256:" + hashlib.sha256(prompt_path.read_bytes()).hexdigest()
            if actual != entry.get("prompt_sha256"):
                raise RoleManifestError(f"V4 prompt hash mismatch for {role!r}")
            expected_operations = (
                ["assessment", "cross_review"]
                if role in V4_BRANCH_ROLES
                else {
                    "gatekeeper": ["gate"],
                    "recon": ["recon"],
                    "mapper": ["map"],
                    "verifier": ["verification"],
                    "reporter": ["reporting"],
                }[role]
            )
            if (
                entry.get("prompt_id") != f"hermes.{role}"
                or not isinstance(entry.get("prompt_version"), str)
                or re.fullmatch(r"4\.[0-9]+", entry["prompt_version"]) is None
                or entry.get("output_contract_id") != ROLE_OUTPUT_CONTRACT_IDS_V4[role]
                or entry.get("operations") != expected_operations
            ):
                raise RoleManifestError(f"V4 prompt identity is invalid for {role!r}")
            self.roles[role] = entry

    def verify_manifest(self, manifest: RoleManifest) -> None:
        entry = self.roles.get(manifest.role)
        if entry is None:
            raise RoleManifestError(f"role {manifest.role!r} is absent from V4 prompt registry")
        expected = (
            entry["prompt_id"],
            entry["prompt_version"],
            entry["prompt_sha256"],
            entry["output_contract_id"],
            "task-envelope/v4",
            "handoff-envelope/v4",
        )
        actual = (
            manifest.prompt_id,
            manifest.prompt_version,
            manifest.prompt_sha256,
            manifest.output_contract_id,
            manifest.input_schema,
            manifest.output_schema,
        )
        if actual != expected:
            raise RoleManifestError("V4 manifest prompt or contract binding was rejected")
        command = manifest.command
        try:
            index = command.index("--registry-path")
        except ValueError as exc:
            raise RoleManifestError("V4 manifest omitted its isolated registry path") from exc
        if index + 1 >= len(command) or command[index + 1] != V4_REGISTRY_RELATIVE.as_posix():
            raise RoleManifestError("V4 manifest registry path was rejected")


__all__ = ["PromptRegistryV4", "V4_BRANCH_ROLES", "V4_REGISTRY_RELATIVE", "V4_ROLES"]
