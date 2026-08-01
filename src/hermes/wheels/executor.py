"""The only runtime-facing entry point for governed capability artifacts.

Hermes never imports a generated artifact.  Runtime JSON is accepted only from
the fixed ``DockerSandbox.execute_json`` protocol; an older fixture-only
sandbox is not silently treated as a host-execution fallback.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Protocol, cast

from .models import WheelManifest
from .registry import WheelRegistryError
from .selector import RuntimeSelector


class CapabilityExecutionError(WheelRegistryError):
    """A wheel failed isolation, output validation, or runtime policy."""


class _SandboxResult(Protocol):
    passed: bool
    exit_code: int | None
    timed_out: bool
    stdout_preview: str
    stderr_preview: str
    stdout_sha256: str
    stderr_sha256: str
    failure_reason: str | None


class _SandboxExecutor(Protocol):
    def execute(self, artifact_root: Path, *, test_target: str = ...) -> _SandboxResult: ...


class _JsonSandboxResult(Protocol):
    passed: bool
    output_json: str
    failure_reason: str | None
    stdout_sha256: str
    stderr_sha256: str


class _JsonSandboxExecutor(Protocol):
    def execute_json(
        self, artifact_root: Path, *, entrypoint: str, input_json: str
    ) -> _JsonSandboxResult: ...


@dataclass(frozen=True)
class CapabilityExecution:
    """A JSON result emitted by a selected artifact in its Docker boundary."""

    manifest: WheelManifest
    output: dict[str, Any]
    output_sha256: str


class CapabilityHost:
    """Select and execute wheels only through the mandatory sandbox boundary."""

    def __init__(
        self,
        selector: RuntimeSelector,
        sandbox: object,
        *,
        actor: str = "capability-host",
    ) -> None:
        if not actor:
            raise ValueError("actor must be non-empty")
        self._selector = selector
        self._sandbox = sandbox
        self._actor = actor

    def validate_fixture(
        self,
        wheel_id: str,
        version: str,
        *,
        artifact_root: Path,
        required_capability: str | None = None,
        test_target: str = "/wheel/tests",
    ) -> CapabilityExecution:
        """Run the reviewed fixture suite; no generated code reaches the host."""
        manifest = self._selector.select(
            wheel_id,
            version,
            artifact_root=artifact_root,
            required_capability=required_capability,
        )
        try:
            result = cast(_SandboxExecutor, self._sandbox).execute(
                artifact_root, test_target=test_target
            )
        except Exception as exc:
            self._record_failure(manifest, "sandbox_violation", str(exc))
            raise CapabilityExecutionError(
                "capability sandbox did not return a valid result"
            ) from exc
        if not result.passed:
            outcome = "resource_limit" if result.timed_out else "sandbox_violation"
            detail = result.failure_reason or result.stderr_preview
            self._record_failure(manifest, outcome, detail)
            raise CapabilityExecutionError("capability fixture validation failed")
        self._selector.registry.record_usage(
            manifest.id,
            manifest.version,
            outcome="fixture_validated",
            output_sha256=result.stdout_sha256,
            detail_sha256=result.stderr_sha256,
            actor=self._actor,
        )
        return CapabilityExecution(
            manifest=manifest,
            output={},
            output_sha256=result.stdout_sha256,
        )

    def execute(
        self,
        wheel_id: str,
        version: str,
        *,
        artifact_root: Path,
        input_payload: Mapping[str, Any],
        required_capability: str | None = None,
    ) -> CapabilityExecution:
        """Run JSON-only input through the fixed, isolated JSON-I/O protocol."""
        manifest = self._selector.select(
            wheel_id,
            version,
            artifact_root=artifact_root,
            required_capability=required_capability,
        )
        try:
            input_json = json.dumps(
                dict(input_payload), ensure_ascii=False, sort_keys=True, separators=(",", ":")
            )
        except (TypeError, ValueError) as exc:
            raise CapabilityExecutionError("capability input must be JSON serializable") from exc
        execute_json = getattr(self._sandbox, "execute_json", None)
        if not callable(execute_json):
            raise CapabilityExecutionError(
                "runtime capability execution requires a versioned sandbox JSON-I/O protocol"
            )
        try:
            result = cast(_JsonSandboxExecutor, self._sandbox).execute_json(
                artifact_root, entrypoint=manifest.entrypoint, input_json=input_json
            )
        except Exception as exc:
            self._record_failure(manifest, "sandbox_violation", str(exc))
            raise CapabilityExecutionError(
                "capability sandbox did not return a valid result"
            ) from exc
        if not result.passed:
            self._record_failure(manifest, "sandbox_violation", result.failure_reason or "")
            raise CapabilityExecutionError("capability sandbox execution failed")
        try:
            output = json.loads(result.output_json)
        except (TypeError, json.JSONDecodeError) as exc:
            self._record_failure(manifest, "invalid_output", str(result.output_json))
            raise CapabilityExecutionError("capability output is not JSON") from exc
        if not isinstance(output, dict):
            self._record_failure(manifest, "invalid_output", result.output_json)
            raise CapabilityExecutionError("capability output must be a JSON object")
        output_hash = _digest(result.output_json)
        self._selector.registry.record_usage(
            manifest.id,
            manifest.version,
            outcome="success",
            output_sha256=output_hash,
            detail_sha256=result.stderr_sha256,
            actor=self._actor,
        )
        return CapabilityExecution(manifest=manifest, output=output, output_sha256=output_hash)

    def record_human_review(
        self,
        wheel_id: str,
        version: str,
        *,
        false_positive: bool,
        detail: str = "",
    ) -> None:
        """Feed a reviewed outcome into automatic quality quarantine rules."""
        self._selector.registry.record_usage(
            wheel_id,
            version,
            outcome="false_positive" if false_positive else "reviewed_success",
            detail_sha256=_digest(detail) if detail else None,
            human_reviewed=True,
            false_positive=false_positive,
            actor=self._actor,
        )

    def _record_failure(self, manifest: WheelManifest, outcome: str, detail: str) -> None:
        self._selector.registry.record_usage(
            manifest.id,
            manifest.version,
            outcome=outcome,
            detail_sha256=_digest(detail) if detail else None,
            actor=self._actor,
        )


class WheelExecutor(CapabilityHost):
    """Compatibility name for the sole governed wheel execution boundary."""


def _digest(value: str) -> str:
    return f"sha256:{sha256(value.encode('utf-8', errors='replace')).hexdigest()}"
