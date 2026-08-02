"""CAP-07 governed assessment recovery — contract and guard layer.

The two Hermes loops (assessment and capability learning) have, until now, had
no sanctioned join: R2.5 can learn and run a passive Wheel as an isolated child
continuation, but a paused V3/V4 assessment could not be resumed from that
learning.  This module supplies the missing **contract + deterministic guard**
layer for CAP-07 (PRD §6.3) while preserving every safety invariant:

* a paused assessment is recorded append-only and **never mutated in place**;
* resume is **gated on an active, approved Wheel** that addresses the exact
  ``ProblemCard`` the assessment paused on — an approved-but-not-active,
  quarantined or revoked Wheel can never unblock it;
* recovery always binds a **new** run to the frozen inputs (``resume_run_id !=
  paused_run_id``); in-place forward rewrite of the original run is forbidden
  (docs/08 §8, docs/15 §5 P1);
* the actual effect is fed back for registry effect / false-positive tracking.

Scope of this module: the frozen contracts and the pure guard functions, fully
unit-tested without Docker/ACP.  Wiring these into the live ``workflow.py`` DAG
and proving the end-to-end pause→learn→resume cycle on a real V3/V4 run still
requires the acceptance infrastructure tracked in docs/15 §10.3, and is not
claimed here.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Literal

from pydantic import Field, field_validator, model_validator

from .learning_contracts import LearningContract
from .r25_contracts import ContinuationOutcomeV1

# Contract id/digest patterns, matching learning_contracts.py.
_DIGEST = r"^sha256:[0-9a-f]{64}$"
_ID = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"

# Mirrors ``WheelManifestV2.status`` (learning_contracts.py); only ``active``
# is eligible to unblock a paused assessment.
WheelLifecycleStatus = Literal[
    "draft",
    "researched",
    "specified",
    "generated",
    "validated",
    "candidate",
    "approved",
    "active",
    "quarantined",
    "revoked",
]

# The continuation outcomes that count as the gap being safely resolved vs not;
# a quarantined Wheel outcome is never a resolution.
_EFFECT_BY_OUTCOME: dict[str, Literal["resolved", "inconclusive", "failed"]] = {
    "resolved": "resolved",
    "inconclusive": "inconclusive",
    "failed": "failed",
    "quarantined": "failed",
}


class RecoveryBlocked(Exception):
    """Raised when a resume is not permitted; the assessment stays paused."""


class AssessmentPauseRecordV1(LearningContract):
    """Append-only record that a V3/V4 assessment paused on a knowledge gap.

    It deliberately carries no findings, observations or forward state — it only
    freezes what is needed to resume later under a new run.  ``extra="forbid"``
    (inherited) rejects any attempt to smuggle assessment forward state in.
    """

    version: Literal["1"] = "1"
    paused_run_id: str = Field(pattern=_ID)
    scope_digest: str = Field(pattern=_DIGEST)
    paused_task_id: str = Field(pattern=_ID)
    problem_card_id: str = Field(pattern=_ID)
    problem_card_digest: str = Field(pattern=_DIGEST)
    # Hash of the precise, frozen inputs the resume run must be bound to.
    frozen_input_sha256: str = Field(pattern=_DIGEST)
    reason: str = Field(min_length=1, max_length=2_000)
    paused_at: datetime

    @field_validator("paused_at")
    @classmethod
    def aware_paused_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("pause time must be timezone-aware")
        return value


class ActiveWheelView(LearningContract):
    """The minimal, registry-derived view the recovery guard needs about a Wheel."""

    wheel_id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,63}$")
    wheel_manifest_digest: str = Field(pattern=_DIGEST)
    activation_digest: str = Field(pattern=_DIGEST)
    status: WheelLifecycleStatus
    # The knowledge gaps (ProblemCard ids) this Wheel is approved to address.
    problem_card_ids: tuple[str, ...] = ()


class AssessmentResumeBindingV1(LearningContract):
    """Binds a new assessment run to a paused run + approved Wheel + frozen input."""

    version: Literal["1"] = "1"
    resume_run_id: str = Field(pattern=_ID)
    paused_run_id: str = Field(pattern=_ID)
    scope_digest: str = Field(pattern=_DIGEST)
    problem_card_id: str = Field(pattern=_ID)
    pause_record_digest: str = Field(pattern=_DIGEST)
    wheel_manifest_digest: str = Field(pattern=_DIGEST)
    activation_digest: str = Field(pattern=_DIGEST)
    frozen_input_sha256: str = Field(pattern=_DIGEST)
    bound_at: datetime

    @field_validator("bound_at")
    @classmethod
    def aware_bound_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("resume binding time must be timezone-aware")
        return value

    @model_validator(mode="after")
    def forbid_in_place_resume(self) -> AssessmentResumeBindingV1:
        if self.resume_run_id == self.paused_run_id:
            raise ValueError(
                "in-place resume is forbidden; CAP-07 requires a new bound run id"
            )
        return self


class AssessmentRecoveryFeedbackV1(LearningContract):
    """The measured effect of a recovery, for registry effect / FP tracking."""

    version: Literal["1"] = "1"
    resume_run_id: str = Field(pattern=_ID)
    paused_run_id: str = Field(pattern=_ID)
    problem_card_id: str = Field(pattern=_ID)
    wheel_manifest_digest: str = Field(pattern=_DIGEST)
    resume_binding_digest: str = Field(pattern=_DIGEST)
    continuation_outcome_digest: str = Field(pattern=_DIGEST)
    effect: Literal["resolved", "inconclusive", "failed"]
    summary: str = Field(min_length=1, max_length=2_000)
    recorded_at: datetime

    @field_validator("recorded_at")
    @classmethod
    def aware_recorded_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("feedback time must be timezone-aware")
        return value


def select_active_wheel(
    active_wheels: Sequence[ActiveWheelView], problem_card_id: str
) -> ActiveWheelView:
    """Return the single active Wheel approved to address ``problem_card_id``.

    Only ``status == "active"`` qualifies: approved-but-not-yet-active,
    quarantined and revoked Wheels can never unblock a paused assessment.
    Ambiguity (more than one active Wheel for the same gap) is refused rather
    than resolved heuristically.
    """
    eligible = [
        wheel
        for wheel in active_wheels
        if wheel.status == "active" and problem_card_id in wheel.problem_card_ids
    ]
    if not eligible:
        raise RecoveryBlocked(
            f"no active approved Wheel addresses problem card {problem_card_id!r}"
        )
    if len(eligible) > 1:
        raise RecoveryBlocked(
            f"ambiguous recovery: {len(eligible)} active Wheels address "
            f"problem card {problem_card_id!r}"
        )
    return eligible[0]


def plan_assessment_resume(
    pause: AssessmentPauseRecordV1,
    active_wheels: Sequence[ActiveWheelView],
    *,
    resume_run_id: str,
    now: datetime,
) -> AssessmentResumeBindingV1:
    """Guarded planner: produce a resume binding or refuse (fail-closed).

    Refuses unless a single active approved Wheel addresses the paused gap and
    the resume run is a genuinely new run bound to the frozen inputs.
    """
    if resume_run_id == pause.paused_run_id:
        raise RecoveryBlocked(
            "in-place resume is forbidden; CAP-07 requires a new bound run id"
        )
    wheel = select_active_wheel(active_wheels, pause.problem_card_id)
    return AssessmentResumeBindingV1(
        resume_run_id=resume_run_id,
        paused_run_id=pause.paused_run_id,
        scope_digest=pause.scope_digest,
        problem_card_id=pause.problem_card_id,
        pause_record_digest=pause.digest,
        wheel_manifest_digest=wheel.wheel_manifest_digest,
        activation_digest=wheel.activation_digest,
        frozen_input_sha256=pause.frozen_input_sha256,
        bound_at=now,
    )


def record_recovery_feedback(
    binding: AssessmentResumeBindingV1,
    continuation_outcome: ContinuationOutcomeV1,
    *,
    summary: str,
    now: datetime,
) -> AssessmentRecoveryFeedbackV1:
    """Map an R2.5 continuation outcome to registry feedback for the recovery.

    The continuation must have run against the same Wheel the resume bound, or
    the feedback is refused (a mismatched Wheel is not evidence of this gap's
    resolution).
    """
    if continuation_outcome.wheel_manifest_digest != binding.wheel_manifest_digest:
        raise RecoveryBlocked(
            "continuation outcome Wheel does not match the resume binding"
        )
    return AssessmentRecoveryFeedbackV1(
        resume_run_id=binding.resume_run_id,
        paused_run_id=binding.paused_run_id,
        problem_card_id=binding.problem_card_id,
        wheel_manifest_digest=binding.wheel_manifest_digest,
        resume_binding_digest=binding.digest,
        continuation_outcome_digest=continuation_outcome.digest,
        effect=_EFFECT_BY_OUTCOME[continuation_outcome.outcome],
        summary=summary,
        recorded_at=now,
    )
