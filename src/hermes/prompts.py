"""Host-side prompt registry verification for signed role manifests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .runtime.agents import RoleManifest, RoleManifestError
from .runtime.agents.contracts import ROLE_OUTPUT_CONTRACT_IDS


class PromptRegistry:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        path = self.root / "prompts" / "registry.json"
        try:
            raw = path.read_bytes()
            document = json.loads(raw)
            roles = document["roles"]
        except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise RoleManifestError(f"could not load prompt registry: {exc}") from exc
        if document.get("version") != "1" or not isinstance(roles, dict):
            raise RoleManifestError("prompt registry must be a version-1 role mapping")
        self.digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        self.roles: dict[str, dict[str, Any]] = {}
        for role, entry in roles.items():
            if not isinstance(role, str) or not isinstance(entry, dict):
                raise RoleManifestError("prompt registry entry is malformed")
            prompt_path = (self.root / str(entry.get("prompt_path", ""))).resolve()
            if self.root not in prompt_path.parents or not prompt_path.is_file():
                raise RoleManifestError(f"prompt path for {role!r} is invalid")
            actual = "sha256:" + hashlib.sha256(prompt_path.read_bytes()).hexdigest()
            if actual != entry.get("prompt_sha256"):
                raise RoleManifestError(f"prompt hash mismatch for {role!r}")
            self.roles[role] = entry

    def verify_manifest(self, manifest: RoleManifest) -> None:
        entry = self.roles.get(manifest.role)
        if entry is None:
            raise RoleManifestError(f"role {manifest.role!r} is absent from prompt registry")
        expected = (
            f"hermes.{manifest.role}",
            entry.get("prompt_version"),
            entry.get("prompt_sha256"),
            ROLE_OUTPUT_CONTRACT_IDS.get(manifest.role),
        )
        actual = (
            manifest.prompt_id,
            manifest.prompt_version,
            manifest.prompt_sha256,
            manifest.output_contract_id,
        )
        if actual != expected:
            raise RoleManifestError("manifest prompt or output contract binding was rejected")
