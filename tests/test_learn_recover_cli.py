"""`hermes learn recover` CLI: composes a CAP-07 recovery from artifact files.

Offline — no Docker/ACP. Reuses the CAP-07 contract fixtures and drives the real
CLI entry point end to end, plus the fail-closed refusal path.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from hermes import cli
from hermes.cap07 import Cap07RecoveryBundle
from hermes.learning_recovery import ActiveWheelView, AssessmentPauseRecordV1
from hermes.r25_contracts import ContinuationOutcomeV1

_D = "sha256:" + "0" * 64
_D2 = "sha256:" + "1" * 64
_D3 = "sha256:" + "2" * 64
_NOW = datetime(2026, 8, 2, tzinfo=UTC)
_GAP = "gap-jwt-kid-confusion"
_PARENT = "assess-parent-001"


def _pause() -> AssessmentPauseRecordV1:
    return AssessmentPauseRecordV1(
        paused_run_id=_PARENT,
        scope_digest=_D,
        paused_task_id="verify-api-01",
        problem_card_id=_GAP,
        problem_card_digest=_D2,
        frozen_input_sha256=_D3,
        reason="unknown JWT kid handling; needs a governed parser",
        paused_at=_NOW,
    )


def _continuation() -> ContinuationOutcomeV1:
    return ContinuationOutcomeV1(
        continuation_run_id="resume-002-child",
        learning_run_id="learn-001",
        parent_run_id=_PARENT,
        scope_digest=_D,
        wheel_manifest_digest=_D,
        wheel_activation_digest=_D2,
        execution_receipt_digest=_D2,
        structured_observation_digest=_D3,
        outcome="resolved",
        generated_at=_NOW,
    )


def _wheel(status: str = "active") -> ActiveWheelView:
    return ActiveWheelView(
        wheel_id="jwt-kid-parser",
        wheel_manifest_digest=_D,
        activation_digest=_D2,
        status=status,  # type: ignore[arg-type]
        problem_card_ids=(_GAP,),
    )


def _write(tmp: Path, *, wheel_status: str = "active") -> tuple[Path, Path, Path]:
    p = tmp / "pause.json"
    c = tmp / "continuation.json"
    w = tmp / "wheels.json"
    p.write_text(_pause().model_dump_json(), encoding="utf-8")
    c.write_text(_continuation().model_dump_json(), encoding="utf-8")
    w.write_text(json.dumps([_wheel(wheel_status).model_dump(mode="json")]), encoding="utf-8")
    return p, c, w


def test_learn_recover_composes_and_writes_bundle(tmp_path: Path) -> None:
    p, c, w = _write(tmp_path)
    out = tmp_path / "bundle.json"
    code = cli.main([
        "--json", "learn", "recover",
        "--pause", str(p), "--continuation", str(c), "--wheels", str(w),
        "--resume-run-id", "assess-resume-002",
        "--summary", "gap resolved by governed parser",
        "--out", str(out),
    ])
    assert code == 0
    bundle = Cap07RecoveryBundle.model_validate_json(out.read_text(encoding="utf-8"))
    assert bundle.binding.resume_run_id == "assess-resume-002"
    assert bundle.binding.paused_run_id == _PARENT
    assert bundle.binding.resume_run_id != bundle.binding.paused_run_id  # never in-place


def test_learn_recover_is_fail_closed_on_inactive_wheel(tmp_path: Path) -> None:
    p, c, w = _write(tmp_path, wheel_status="approved")  # approved != active -> refused
    code = cli.main([
        "--json", "learn", "recover",
        "--pause", str(p), "--continuation", str(c), "--wheels", str(w),
        "--resume-run-id", "assess-resume-002",
        "--summary", "should be refused",
    ])
    assert code == 2
