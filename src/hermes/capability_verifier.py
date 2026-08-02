"""Wheel-consumption at the V3 Verifier role's execution-graph node.

The isolated Verifier normally derives a deterministic verdict from parent-owned
evidence (see ``vertical_v3``). One candidate class, ``line_kv_capability_gap``,
is deliberately *unresolvable that way*: its evidence is a ``line_kv`` structure
the parent cannot interpret without a learned capability. Such a candidate is a
coverage gap — ``inconclusive`` — unless CAP-07 has produced an active, approved
Wheel for it, in which case the Verifier resolves it by invoking that Wheel
through the governed sandbox (``hermes.wheel_consumption``) and, only on a bound
match, promotes the verdict to ``validated`` with the Wheel's structured
observation as its assertion.

This is the hook wired into a real role: the *verdict of a real candidate*
depends on the Wheel, and every governance edge in ``resolve_gap_with_wheel``
still applies (active Wheel, addressed gap, input bound by digest, sandbox pass).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal

from .learning_recovery import ActiveWheelView
from .wheel_consumption import (
    GapResolutionRequestV1,
    SandboxExecutor,
    WheelResolvedObservationV1,
    gap_input_digest,
    resolve_gap_with_wheel,
)


@dataclass(frozen=True)
class CapabilityGapResolver:
    """Everything the Verifier needs to resolve a capability gap with a Wheel.

    Assembled by the parent runtime from the CAP-07 recovery: the active Wheel,
    the governed sandbox, the read-only Wheel artifact root, the manifest
    entrypoint, and the run/scope/problem-card the resolution is bound to. The
    ``gap_text`` is the exact ``line_kv`` value the paused assessment could not
    parse; the request freezes its digest so a different input cannot be spliced.
    """

    active_wheel: ActiveWheelView
    sandbox: SandboxExecutor
    wheel_artifact_root: Path
    entrypoint: str
    problem_card_id: str
    resume_run_id: str
    paused_run_id: str
    scope_digest: str
    wheel_activation_digest: str
    gap_text: str


def capability_gap_verdict(
    resolver: CapabilityGapResolver | None,
    *,
    now: datetime,
) -> tuple[Literal["validated", "inconclusive"], str, WheelResolvedObservationV1 | None]:
    """Decide a ``line_kv_capability_gap`` candidate's verdict via the Wheel.

    Without an active approved Wheel the gap is unresolved (``inconclusive``) — the
    assessment honestly reports a coverage gap. With one, the Wheel runs in the
    sandbox; a bound match validates the candidate, no match stays inconclusive.
    """
    if resolver is None:
        return (
            "inconclusive",
            "capability gap unresolved: no active approved Wheel for this candidate",
            None,
        )
    gap_input = {"text": resolver.gap_text}
    request = GapResolutionRequestV1(
        resume_run_id=resolver.resume_run_id,
        paused_run_id=resolver.paused_run_id,
        scope_digest=resolver.scope_digest,
        problem_card_id=resolver.problem_card_id,
        wheel_manifest_digest=resolver.active_wheel.wheel_manifest_digest,
        wheel_activation_digest=resolver.wheel_activation_digest,
        gap_input_sha256=gap_input_digest(gap_input),
    )
    observation = resolve_gap_with_wheel(
        request,
        resolver.active_wheel,
        resolver.sandbox,
        wheel_artifact_root=resolver.wheel_artifact_root,
        entrypoint=resolver.entrypoint,
        gap_input=gap_input,
        now=now,
    )
    if observation.matched:
        return (
            "validated",
            (
                f"capability gap resolved by governed Wheel "
                f"{resolver.active_wheel.wheel_id!r}: {observation.fields}"
            ),
            observation,
        )
    return (
        "inconclusive",
        f"capability gap Wheel {resolver.active_wheel.wheel_id!r} produced no match",
        observation,
    )
