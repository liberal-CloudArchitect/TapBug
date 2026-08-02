"""CAP-07 orchestration — composes a paused assessment + R2.5 result into a
governed recovery bundle, with fail-closed guards and linkage verification.

No Docker/ACP: the R2.5 learning that produces the continuation + active Wheel is
verified separately (test_r25_workflow / real E2E); here we lock the composition
and its invariants.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from hermes.cap07 import (
    Cap07Error,
    Cap07RecoveryBundle,
    orchestrate_recovery,
    verify_recovery_bundle,
)
from hermes.learning_recovery import (
    ActiveWheelView,
    AssessmentPauseRecordV1,
    RecoveryBlocked,
)
from hermes.r25_contracts import ContinuationOutcomeV1

_D = "sha256:" + "0" * 64
_D2 = "sha256:" + "1" * 64
_D3 = "sha256:" + "2" * 64
_NOW = datetime(2026, 8, 2, tzinfo=UTC)
_GAP = "gap-jwt-kid-confusion"
_PARENT = "assess-parent-001"


def _pause(**over: object) -> AssessmentPauseRecordV1:
    payload: dict[str, object] = {
        "paused_run_id": _PARENT,
        "scope_digest": _D,
        "paused_task_id": "verify-api-01",
        "problem_card_id": _GAP,
        "problem_card_digest": _D2,
        "frozen_input_sha256": _D3,
        "reason": "unknown JWT kid handling; needs a governed parser",
        "paused_at": _NOW,
    }
    payload.update(over)
    return AssessmentPauseRecordV1(**payload)  # type: ignore[arg-type]


def _wheel(status: str = "active") -> ActiveWheelView:
    return ActiveWheelView(
        wheel_id="jwt-kid-parser",
        wheel_manifest_digest=_D,
        activation_digest=_D2,
        status=status,  # type: ignore[arg-type]
        problem_card_ids=(_GAP,),
    )


def _continuation(*, parent: str = _PARENT, wheel_digest: str = _D) -> ContinuationOutcomeV1:
    return ContinuationOutcomeV1(
        continuation_run_id="resume-002-child",
        learning_run_id="learn-001",
        parent_run_id=parent,
        scope_digest=_D,
        wheel_manifest_digest=wheel_digest,
        wheel_activation_digest=_D2,
        execution_receipt_digest=_D2,
        structured_observation_digest=_D3,
        outcome="resolved",
        generated_at=_NOW,
    )


def _bundle() -> Cap07RecoveryBundle:
    return orchestrate_recovery(
        _pause(),
        _continuation(),
        [_wheel()],
        resume_run_id="assess-resume-002",
        summary="gap resolved by governed parser",
        now=_NOW,
    )


# --- happy path ----------------------------------------------------------


def test_orchestrate_produces_a_verified_bundle() -> None:
    bundle = _bundle()
    assert bundle.pause.paused_run_id == _PARENT
    assert bundle.binding.resume_run_id == "assess-resume-002"
    assert bundle.binding.pause_record_digest == bundle.pause.digest
    assert bundle.binding.frozen_input_sha256 == _D3
    assert bundle.feedback.effect == "resolved"
    assert bundle.feedback.resume_binding_digest == bundle.binding.digest
    # verify passes on a well-formed bundle
    verify_recovery_bundle(bundle)


# --- fail-closed guards --------------------------------------------------


def test_no_active_wheel_blocks_recovery() -> None:
    with pytest.raises(RecoveryBlocked):
        orchestrate_recovery(
            _pause(), _continuation(), [_wheel(status="approved")],
            resume_run_id="assess-resume-002", summary="x", now=_NOW,
        )


def test_continuation_must_bind_the_paused_run() -> None:
    with pytest.raises(Cap07Error):
        orchestrate_recovery(
            _pause(), _continuation(parent="some-other-run"), [_wheel()],
            resume_run_id="assess-resume-002", summary="x", now=_NOW,
        )


def test_in_place_resume_is_forbidden() -> None:
    with pytest.raises(RecoveryBlocked):
        orchestrate_recovery(
            _pause(), _continuation(), [_wheel()],
            resume_run_id=_PARENT, summary="x", now=_NOW,
        )


def test_wheel_mismatch_between_continuation_and_binding_is_refused() -> None:
    with pytest.raises(RecoveryBlocked):
        orchestrate_recovery(
            _pause(), _continuation(wheel_digest=_D2), [_wheel()],
            resume_run_id="assess-resume-002", summary="x", now=_NOW,
        )


# --- tamper detection by verify_recovery_bundle --------------------------


def test_verify_detects_spliced_pause() -> None:
    good = _bundle()
    # Rebuild a bundle whose pause differs from the one the binding references.
    tampered = Cap07RecoveryBundle(
        pause=_pause(reason="a different pause record entirely"),
        binding=good.binding,
        feedback=good.feedback,
    )
    with pytest.raises(Cap07Error):
        verify_recovery_bundle(tampered)


def test_bundle_is_frozen() -> None:
    bundle = _bundle()
    with pytest.raises(ValidationError):
        bundle.pause = _pause()  # type: ignore[misc]
