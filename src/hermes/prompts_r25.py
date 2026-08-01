"""Prompt registry verifier for the isolated R2.5 learning roles."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .domain_contracts import canonical_digest
from .runtime.agents import RoleManifest, RoleManifestError

R25_REGISTRY_RELATIVE = Path("prompts/r25/registry.json")
R25_OUTPUT_CONTRACT_IDS = {
    "researcher": "hermes.r25.research_facts/v1",
    "capability-planner": "hermes.r25.capability_spec/v2",
}
R25_OPERATIONS = {
    "researcher": ["research"],
    "capability-planner": ["plan"],
}


class PromptRegistryR25:
    """Verify prompt identity and manifest binding for learning roles only."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        path = (self.root / R25_REGISTRY_RELATIVE).resolve()
        try:
            path.relative_to(self.root)
            raw = path.read_bytes()
            document = json.loads(raw)
            roles = document["roles"]
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RoleManifestError(f"could not load R2.5 prompt registry: {exc}") from exc
        if (
            set(document) != {"version", "collection_sha256", "roles"}
            or document.get("version") != "25"
            or not isinstance(roles, dict)
            or set(roles) != set(R25_OUTPUT_CONTRACT_IDS)
        ):
            raise RoleManifestError("R2.5 prompt registry must bind the exact two-role set")
        if document.get("collection_sha256") != canonical_digest(roles):
            raise RoleManifestError("R2.5 prompt collection digest mismatch")
        self.digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        self.collection_digest = str(document["collection_sha256"])
        self.roles: dict[str, dict[str, Any]] = {}
        for role, raw_entry in roles.items():
            if not isinstance(raw_entry, dict):
                raise RoleManifestError(f"R2.5 prompt entry for {role!r} is malformed")
            entry = dict(raw_entry)
            agent_path = (self.root / str(entry.get("agent_path", ""))).resolve()
            try:
                agent_path.relative_to((self.root / "agents/r25").resolve())
            except ValueError as exc:
                raise RoleManifestError(f"R2.5 agent path for {role!r} escapes its root") from exc
            if not agent_path.is_file():
                raise RoleManifestError(f"R2.5 agent path for {role!r} is invalid")
            prompt_path = (self.root / str(entry.get("prompt_path", ""))).resolve()
            try:
                prompt_path.relative_to((self.root / "prompts/r25").resolve())
            except ValueError as exc:
                raise RoleManifestError(f"R2.5 prompt path for {role!r} escapes its root") from exc
            if not prompt_path.is_file():
                raise RoleManifestError(f"R2.5 prompt path for {role!r} is invalid")
            actual = "sha256:" + hashlib.sha256(prompt_path.read_bytes()).hexdigest()
            if actual != entry.get("prompt_sha256"):
                raise RoleManifestError(f"R2.5 prompt hash mismatch for {role!r}")
            if (
                entry.get("prompt_id") != f"hermes.{role}"
                or not isinstance(entry.get("prompt_version"), str)
                or entry["prompt_version"] != "25.1"
                or entry.get("output_contract_id") != R25_OUTPUT_CONTRACT_IDS[role]
                or entry.get("operations") != R25_OPERATIONS[role]
                or entry.get("allowed_ipc") != ["model_request"]
            ):
                raise RoleManifestError(f"R2.5 prompt identity is invalid for {role!r}")
            self.roles[role] = entry

    def verify_manifest(self, manifest: RoleManifest) -> None:
        entry = self.roles.get(manifest.role)
        if entry is None:
            raise RoleManifestError(f"role {manifest.role!r} is absent from the R2.5 registry")
        expected = (
            entry["prompt_id"],
            entry["prompt_version"],
            entry["prompt_sha256"],
            entry["output_contract_id"],
            "task-envelope/v25",
            "handoff-envelope/v25",
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
            raise RoleManifestError("R2.5 manifest prompt or contract binding was rejected")
        command = manifest.command
        try:
            index = command.index("--registry-path")
        except ValueError as exc:
            raise RoleManifestError("R2.5 manifest omitted its isolated registry path") from exc
        if index + 1 >= len(command) or command[index + 1] != R25_REGISTRY_RELATIVE.as_posix():
            raise RoleManifestError("R2.5 manifest registry path was rejected")


__all__ = [
    "PromptRegistryR25",
    "R25_OUTPUT_CONTRACT_IDS",
    "R25_OPERATIONS",
    "R25_REGISTRY_RELATIVE",
]
