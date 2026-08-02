"""Governed Wheel consumption for CAP-07 assessment gap resolution.

When a resumed assessment reaches the knowledge gap that paused it, it may invoke
the single active, approved Wheel that CAP-07 learned — but only through the same
immutable, no-network, non-root, digest-pinned Docker sandbox R2.5 uses, and only
to produce a *bound structured observation*, never a trusted finding.

``resolve_gap_with_wheel`` is the hook. It fails closed unless a single active
Wheel addresses the paused ``problem_card_id`` and matches the request's manifest
digest, and unless the gap input hashes to the digest the request froze. It then
runs the Wheel's entrypoint in the sandbox and returns a
``WheelResolvedObservationV1`` bound to the request, the Wheel manifest, and the
exact input/output digests. That observation is a *candidate* the governed
assessment consumes; it cannot promote itself to a finding, and a sandbox
violation or malformed output is a resolution failure, never a silent pass.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import Field, field_validator

from .learning_contracts import LearningContract
from .learning_recovery import ActiveWheelView

_DIGEST = r"^sha256:[0-9a-f]{64}$"
_ID = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"


class WheelConsumptionError(RuntimeError):
    """A gap resolution failed its governance guards or the Wheel misbehaved."""


@runtime_checkable
class SandboxJsonResult(Protocol):
    passed: bool
    output_json: str
    failure_reason: str | None


@runtime_checkable
class SandboxExecutor(Protocol):
    """The governed sandbox surface a gap resolution needs; ``DockerSandbox`` satisfies it."""

    def execute_json(
        self, artifact_root: Any, *, entrypoint: str, input_json: str
    ) -> SandboxJsonResult: ...


class GapResolutionRequestV1(LearningContract):
    """A resumed assessment's request to resolve its paused gap with a Wheel."""

    version: Literal["1"] = "1"
    resume_run_id: str = Field(pattern=_ID)
    paused_run_id: str = Field(pattern=_ID)
    scope_digest: str = Field(pattern=_DIGEST)
    problem_card_id: str = Field(pattern=_ID)
    wheel_manifest_digest: str = Field(pattern=_DIGEST)
    wheel_activation_digest: str = Field(pattern=_DIGEST)
    gap_input_sha256: str = Field(pattern=_DIGEST)


class WheelResolvedObservationV1(LearningContract):
    """The bound structured observation a Wheel produced for an assessment gap."""

    version: Literal["1"] = "1"
    request_digest: str = Field(pattern=_DIGEST)
    resume_run_id: str = Field(pattern=_ID)
    problem_card_id: str = Field(pattern=_ID)
    wheel_manifest_digest: str = Field(pattern=_DIGEST)
    input_digest: str = Field(pattern=_DIGEST)
    output_digest: str = Field(pattern=_DIGEST)
    matched: bool
    fields: dict[str, str] = Field(default_factory=dict)
    status: Literal["resolved", "unresolved"]
    resolved_at: datetime

    @field_validator("resolved_at")
    @classmethod
    def aware_resolved_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("resolved_at must be timezone-aware")
        return value


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def gap_input_digest(gap_input: dict[str, Any]) -> str:
    """The digest an assessment must freeze into the request for its gap input."""
    return _sha256(_canonical(gap_input))


def resolve_gap_with_wheel(
    request: GapResolutionRequestV1,
    active_wheel: ActiveWheelView,
    sandbox: SandboxExecutor,
    *,
    wheel_artifact_root: Any,
    entrypoint: str,
    gap_input: dict[str, Any],
    now: datetime,
) -> WheelResolvedObservationV1:
    """Invoke the active Wheel in the sandbox to resolve the paused gap.

    Fail-closed on every governance edge: the Wheel must be active, address the
    paused problem card, and match the request's manifest digest; the gap input
    must hash to the frozen digest; and the sandbox run must pass and return a
    ``{"matched": bool, "fields": {...}}`` object. Anything else raises.
    """
    if active_wheel.status != "active":
        raise WheelConsumptionError("only an active approved Wheel may resolve an assessment gap")
    if active_wheel.wheel_manifest_digest != request.wheel_manifest_digest:
        raise WheelConsumptionError("active Wheel does not match the gap resolution request")
    if request.problem_card_id not in active_wheel.problem_card_ids:
        raise WheelConsumptionError("active Wheel does not address the paused problem card")
    input_bytes = _canonical(gap_input)
    if _sha256(input_bytes) != request.gap_input_sha256:
        raise WheelConsumptionError("gap input does not match the request's frozen digest")

    result = sandbox.execute_json(
        wheel_artifact_root, entrypoint=entrypoint, input_json=input_bytes.decode("utf-8")
    )
    if not result.passed:
        raise WheelConsumptionError(
            f"Wheel sandbox execution did not pass: {result.failure_reason or 'unknown'}"
        )
    try:
        parsed = json.loads(result.output_json)
    except (json.JSONDecodeError, TypeError) as exc:
        raise WheelConsumptionError("Wheel returned non-JSON output") from exc
    if not isinstance(parsed, dict) or not isinstance(parsed.get("matched"), bool):
        raise WheelConsumptionError("Wheel output is not a {matched, fields} observation")
    raw_fields = parsed.get("fields") or {}
    if not isinstance(raw_fields, dict):
        raise WheelConsumptionError("Wheel observation fields must be an object")

    matched = bool(parsed["matched"])
    fields = {str(k): str(v) for k, v in raw_fields.items()}
    output_digest = _sha256(_canonical({"matched": matched, "fields": fields}))
    return WheelResolvedObservationV1(
        request_digest=request.digest,
        resume_run_id=request.resume_run_id,
        problem_card_id=request.problem_card_id,
        wheel_manifest_digest=request.wheel_manifest_digest,
        input_digest=request.gap_input_sha256,
        output_digest=output_digest,
        matched=matched,
        fields=fields,
        status="resolved" if matched else "unresolved",
        resolved_at=now,
    )
