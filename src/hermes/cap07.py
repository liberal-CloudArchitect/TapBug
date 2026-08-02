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

from pydantic import Field, field_validator, model_validator

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

_DIGEST = r"^sha256:[0-9a-f]{64}$"
_ID = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"


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


class Cap07CampaignResumeRecordV1(LearningContract):
    """Binds a full assessment campaign run as the governed resume of a recovery.

    The resume of a paused assessment is a *new* full V3/V4 assessment run — never
    an in-place rewrite of the paused run — carried out only after the recovery
    approved a Wheel for the gap. This record ties that campaign run back to the
    recovery so an auditor can follow paused-assessment -> recovery -> resumed
    campaign as one governed chain.

    Scope boundary (kept honest): this records the campaign *ran as the bound
    resume*. Making the campaign actually invoke the approved Wheel to resolve the
    specific gap needs a purpose-built fixture whose assessment cannot proceed
    without the Wheel, plus a governed Wheel-invocation hook in the assessment
    roles — a further, still-open step (docs/15 §11.6 / §11.7).
    """

    version: Literal["1"] = "1"
    recovery_bundle_digest: str = Field(pattern=_DIGEST)
    paused_run_id: str = Field(pattern=_ID)
    resume_run_id: str = Field(pattern=_ID)
    resume_workflow: Literal["v3", "v4"]
    resume_execution_state: Literal["completed", "completed_with_gaps"]
    resume_findings: int = Field(ge=0)
    wheel_manifest_digest: str = Field(pattern=_DIGEST)
    bound_at: datetime

    @field_validator("bound_at")
    @classmethod
    def aware_bound_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("campaign resume time must be timezone-aware")
        return value

    @model_validator(mode="after")
    def forbid_in_place_resume(self) -> Cap07CampaignResumeRecordV1:
        if self.resume_run_id == self.paused_run_id:
            raise ValueError("in-place resume is forbidden; a resume is a new run")
        return self


def bind_campaign_resume(
    bundle: Cap07RecoveryBundle,
    *,
    resume_run_id: str,
    resume_workflow: Literal["v3", "v4"],
    resume_execution_state: Literal["completed", "completed_with_gaps"],
    resume_findings: int,
    now: datetime,
) -> Cap07CampaignResumeRecordV1:
    """Bind a completed assessment campaign run as the resume of ``bundle``.

    Fail-closed: the campaign run must be a new run (not the paused run). The
    record carries the recovery bundle digest and the approved Wheel so the whole
    paused -> recovery -> resumed-campaign chain is verifiable.
    """
    if resume_run_id == bundle.pause.paused_run_id:
        raise Cap07Error("resume campaign run must not be the paused run (no in-place resume)")
    return Cap07CampaignResumeRecordV1(
        recovery_bundle_digest=bundle.digest,
        paused_run_id=bundle.pause.paused_run_id,
        resume_run_id=resume_run_id,
        resume_workflow=resume_workflow,
        resume_execution_state=resume_execution_state,
        resume_findings=resume_findings,
        wheel_manifest_digest=bundle.binding.wheel_manifest_digest,
        bound_at=now,
    )


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
