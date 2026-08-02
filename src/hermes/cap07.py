"""CAP-07 governed assessment recovery — orchestration over the R2.5 loop.

This is the join between Hermes's two loops (assessment and capability learning),
built entirely on the governed records in ``learning_recovery`` so no safety
invariant is bypassed:

    paused V3/V4 assessment (AssessmentPauseRecordV1)
      -> R2.5 learning produces a signed, ACTIVE Wheel + a ContinuationOutcomeV1
      -> resume is BOUND to the frozen inputs + approved Wheel as a NEW run
         (AssessmentResumeBindingV1, never in place)
      -> measured effect is fed back for registry effect / FP tracking
         (AssessmentRecoveryFeedbackV1)

The R2.5 learning itself (research, capability spec, Wheel generation/validation/
signing, continuation) is unchanged and provided by ``r25_workflow``. This module
only composes its outputs into a governed recovery and re-verifies the linkage.

Scope boundary (kept honest): it composes R2.5's Wheel-based *continuation* into a
governed assessment recovery. Re-running a full V3/V4 assessment campaign with the
newly approved Wheel is a further step and is not claimed here.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Literal

from .learning_contracts import LearningContract
from .learning_recovery import (
    ActiveWheelView,
    AssessmentPauseRecordV1,
    AssessmentRecoveryFeedbackV1,
    AssessmentResumeBindingV1,
    plan_assessment_resume,
    record_recovery_feedback,
)
from .r25_contracts import ContinuationOutcomeV1


class Cap07Error(RuntimeError):
    """A recovery cannot be composed or fails its linkage invariants."""


class Cap07RecoveryBundle(LearningContract):
    """The three governed records of one assessment recovery, bound together."""

    version: Literal["1"] = "1"
    pause: AssessmentPauseRecordV1
    binding: AssessmentResumeBindingV1
    feedback: AssessmentRecoveryFeedbackV1


def orchestrate_recovery(
    pause: AssessmentPauseRecordV1,
    continuation_outcome: ContinuationOutcomeV1,
    active_wheels: Sequence[ActiveWheelView],
    *,
    resume_run_id: str,
    summary: str,
    now: datetime,
) -> Cap07RecoveryBundle:
    """Compose a governed recovery from a paused assessment + an R2.5 result.

    Fail-closed: the resume binding is only produced if a single active approved
    Wheel addresses the paused gap (``plan_assessment_resume``); the continuation
    must have run against the paused assessment and the same Wheel
    (``record_recovery_feedback``); the resume run must be a new run.
    """
    if continuation_outcome.parent_run_id != pause.paused_run_id:
        raise Cap07Error(
            "continuation outcome is not bound to the paused assessment run "
            f"({continuation_outcome.parent_run_id!r} != {pause.paused_run_id!r})"
        )
    binding = plan_assessment_resume(
        pause, active_wheels, resume_run_id=resume_run_id, now=now
    )
    feedback = record_recovery_feedback(
        binding, continuation_outcome, summary=summary, now=now
    )
    bundle = Cap07RecoveryBundle(pause=pause, binding=binding, feedback=feedback)
    verify_recovery_bundle(bundle)
    return bundle


def verify_recovery_bundle(bundle: Cap07RecoveryBundle) -> None:
    """Re-check the pause<->resume<->feedback linkage — for preflight and audit.

    A preflight can call this on a persisted bundle to confirm nobody spliced a
    different pause, binding, or continuation into the recovery.
    """
    if bundle.binding.resume_run_id == bundle.pause.paused_run_id:
        raise Cap07Error("in-place resume is forbidden; recovery must use a new run")
    if bundle.binding.pause_record_digest != bundle.pause.digest:
        raise Cap07Error("resume binding does not reference this exact pause record")
    if bundle.binding.frozen_input_sha256 != bundle.pause.frozen_input_sha256:
        raise Cap07Error("resume binding did not preserve the frozen assessment input")
    if bundle.binding.problem_card_id != bundle.pause.problem_card_id:
        raise Cap07Error("resume binding addresses a different problem card")
    if bundle.feedback.resume_binding_digest != bundle.binding.digest:
        raise Cap07Error("feedback does not reference this exact resume binding")
    if bundle.feedback.paused_run_id != bundle.pause.paused_run_id:
        raise Cap07Error("feedback is not bound to the paused assessment run")
    if bundle.feedback.wheel_manifest_digest != bundle.binding.wheel_manifest_digest:
        raise Cap07Error("feedback Wheel does not match the resume binding")
