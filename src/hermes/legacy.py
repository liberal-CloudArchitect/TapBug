"""Read-only access to pre-V2 run artifacts.

Version-1 artifacts predate the complete evidence binding used for promotion and
formal reporting.  They remain useful for audit, but no executable workflow may
silently reinterpret them as version-2 evidence.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .runtime import RunContext


class LegacyRunReadOnlyError(RuntimeError):
    """Raised when an executable operation is attempted on a V1 run."""

    code = "legacy_run_read_only"

    def __init__(self) -> None:
        super().__init__(self.code)


class LegacyAuditSummary(BaseModel):
    """Non-promotable metadata exported from a version-1 run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "1"
    run_id: str
    scope_digest: str
    artifact_count: int = Field(ge=0)
    artifacts: tuple[str, ...]
    artifact_sha256: dict[str, str]
    promotable: bool = False
    limitation: str = (
        "V1 evidence lacks the complete V2 task/action/approval binding and is audit-only."
    )


def run_schema_version(context: RunContext) -> str:
    """Return the declared run-plan schema, treating absent metadata as V1."""

    path = context.artifact_path("plan/run-plan.json")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return "1"
    if not isinstance(document, dict):
        return "1"
    version = document.get("version", "1")
    return version if version in {"1", "2"} else "1"


def require_v2_run(context: RunContext) -> None:
    """Fail closed before any state-changing or report operation on legacy runs."""

    if run_schema_version(context) != "2":
        raise LegacyRunReadOnlyError


class LegacyArtifactReader:
    """List and hash existing V1 artifacts without rewriting any run file."""

    def __init__(self, context: RunContext) -> None:
        if run_schema_version(context) != "1":
            raise ValueError("legacy reader only accepts version-1 runs")
        self.context = context

    def audit_summary(self) -> LegacyAuditSummary:
        paths = tuple(
            sorted(
                path.relative_to(self.context.path).as_posix()
                for path in self.context.path.rglob("*")
                if path.is_file() and path.name != ".lock"
            )
        )
        digests = {
            relative: "sha256:"
            + hashlib.sha256(self.context.artifact_path(relative).read_bytes()).hexdigest()
            for relative in paths
        }
        return LegacyAuditSummary(
            run_id=self.context.run_id,
            scope_digest=self.context.scope_digest,
            artifact_count=len(paths),
            artifacts=paths,
            artifact_sha256=digests,
        )


def legacy_evidence_is_promotable(_document: dict[str, Any]) -> bool:
    """Make the V1 evidence limitation explicit at all conversion call sites."""

    return False


__all__ = [
    "LegacyArtifactReader",
    "LegacyAuditSummary",
    "LegacyRunReadOnlyError",
    "legacy_evidence_is_promotable",
    "require_v2_run",
    "run_schema_version",
]
