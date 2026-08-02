"""CAP-07 governed assessment recovery — contract and guard invariants.

These lock the safety properties of the pause -> approved-Wheel -> new-bound-
resume -> registry-feedback flow without any Docker/ACP (the end-to-end wiring
on a real V3/V4 run is tracked in docs/15 §10.3).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from hermes.learning_recovery import (
    ActiveWheelView,
    AssessmentPauseRecordV1,
    AssessmentResumeBindingV1,
    RecoveryBlocked,
    plan_assessment_resume,
    record_recovery_feedback,
    select_active_wheel,
)
from hermes.r25_contracts import ContinuationOutcomeV1

_D = "sha256:" + "0" * 64
_D2 = "sha256:" + "1" * 64
_D3 = "sha256:" + "2" * 64
_NOW = datetime(2026, 8, 1, tzinfo=UTC)


def _pause(**overrides: object) -> AssessmentPauseRecordV1:
    payload: dict[str, object] = {
        "paused_run_id": "assess-001",
        "scope_digest": _D,
        "paused_task_id": "verify-api-01",
        "problem_card_id": "gap-jwt-kid-confusion",
        "problem_card_digest": _D2,
        "frozen_input_sha256": _D3,
        "reason": "unknown JWT kid handling; needs a governed parser",
        "paused_at": _NOW,
    }
    payload.update(overrides)
    return AssessmentPauseRecordV1(**payload)  # type: ignore[arg-type]


def _wheel(
    status: str = "active", cards: tuple[str, ...] = ("gap-jwt-kid-confusion",)
) -> ActiveWheelView:
    return ActiveWheelView(
        wheel_id="jwt-kid-parser",
        wheel_manifest_digest=_D,
        activation_digest=_D2,
        status=status,  # type: ignore[arg-type]
        problem_card_ids=cards,
    )


def _continuation(wheel_digest: str = _D) -> ContinuationOutcomeV1:
    return ContinuationOutcomeV1(
        continuation_run_id="resume-002-child",
        learning_run_id="learn-001",
        parent_run_id="resume-002",
        scope_digest=_D,
        wheel_manifest_digest=wheel_digest,
        wheel_activation_digest=_D2,
        execution_receipt_digest=_D2,
        structured_observation_digest=_D3,
        outcome="resolved",
        generated_at=_NOW,
    )


# --- pause record ---------------------------------------------------------


def test_pause_record_rejects_forward_state() -> None:
    # extra="forbid" must reject any attempt to smuggle assessment findings in.
    with pytest.raises(ValidationError):
        _pause(findings=["leaked"])


def test_pause_record_requires_aware_time() -> None:
    with pytest.raises(ValidationError):
        _pause(paused_at=datetime(2026, 8, 1))  # naive


# --- Wheel selection gate -------------------------------------------------


def test_select_requires_active_status() -> None:
    for status in ("approved", "validated", "candidate", "quarantined", "revoked", "draft"):
        with pytest.raises(RecoveryBlocked):
            select_active_wheel([_wheel(status=status)], "gap-jwt-kid-confusion")


def test_select_requires_matching_problem_card() -> None:
    with pytest.raises(RecoveryBlocked):
        select_active_wheel([_wheel(cards=("gap-something-else",))], "gap-jwt-kid-confusion")


def test_select_refuses_ambiguous_active_wheels() -> None:
    with pytest.raises(RecoveryBlocked):
        select_active_wheel([_wheel(), _wheel()], "gap-jwt-kid-confusion")


def test_select_returns_the_single_active_wheel() -> None:
    wheel = select_active_wheel([_wheel(status="revoked"), _wheel()], "gap-jwt-kid-confusion")
    assert wheel.status == "active"


# --- resume binding invariants -------------------------------------------


def test_plan_resume_forbids_in_place() -> None:
    with pytest.raises(RecoveryBlocked):
        plan_assessment_resume(
            _pause(), [_wheel()], resume_run_id="assess-001", now=_NOW
        )


def test_binding_model_also_forbids_in_place() -> None:
    # Defence in depth: even direct construction must reject equal run ids.
    with pytest.raises(ValidationError):
        AssessmentResumeBindingV1(
            resume_run_id="assess-001",
            paused_run_id="assess-001",
            scope_digest=_D,
            problem_card_id="gap-x",
            pause_record_digest=_D,
            wheel_manifest_digest=_D,
            activation_digest=_D2,
            frozen_input_sha256=_D3,
            bound_at=_NOW,
        )


def test_plan_resume_blocks_without_active_wheel() -> None:
    with pytest.raises(RecoveryBlocked):
        plan_assessment_resume(
            _pause(), [_wheel(status="approved")], resume_run_id="assess-002", now=_NOW
        )


def test_plan_resume_binds_frozen_input_and_wheel() -> None:
    pause = _pause()
    binding = plan_assessment_resume(
        pause, [_wheel()], resume_run_id="assess-002", now=_NOW
    )
    assert binding.resume_run_id == "assess-002"
    assert binding.paused_run_id == "assess-001"
    # The exact frozen input is carried through unchanged.
    assert binding.frozen_input_sha256 == pause.frozen_input_sha256
    assert binding.pause_record_digest == pause.digest
    assert binding.wheel_manifest_digest == _D
    assert binding.activation_digest == _D2


# --- feedback -------------------------------------------------------------


def test_feedback_maps_outcome_to_effect() -> None:
    binding = plan_assessment_resume(_pause(), [_wheel()], resume_run_id="assess-002", now=_NOW)
    feedback = record_recovery_feedback(
        binding, _continuation(), summary="gap resolved by governed parser", now=_NOW
    )
    assert feedback.effect == "resolved"
    assert feedback.resume_binding_digest == binding.digest
    assert feedback.continuation_outcome_digest == _continuation().digest


def test_feedback_refuses_mismatched_wheel() -> None:
    binding = plan_assessment_resume(_pause(), [_wheel()], resume_run_id="assess-002", now=_NOW)
    with pytest.raises(RecoveryBlocked):
        record_recovery_feedback(
            binding, _continuation(wheel_digest=_D2), summary="x", now=_NOW
        )
