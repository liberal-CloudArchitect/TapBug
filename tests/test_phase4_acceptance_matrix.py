from __future__ import annotations

from pathlib import Path

import pytest

from hermes.preflight_v3 import ReportPreflightV3Error
from hermes.runtime import RunContext
from hermes.runtime.agents import AgentRunner, TaskEnvelope, TaskResult
from hermes.vertical_v3 import (
    ExecutionStateV3,
    NetworkStateV3,
    VerticalStateV3,
    VerticalWorkflowV3,
)

_TAMPER_CLASSES = (
    "route",
    "dedup_provenance",
    "cross_review",
    "approval",
    "consumption",
    "action_ledger",
    "budget_ledger",
    "evidence",
    "cleanup",
    "coverage",
    "human_signature",
    "reporter_receipt",
    "reporter_ack",
)

_FORMAL_REPORT_PATHS = (
    "report/reporter-launch-v3.json",
    "report/reporter-ack-v3.json",
    "report/report-v3.md",
    "report/findings-v3.json",
    "report/report-write-receipt-v3.json",
)


class _CountingRunner(AgentRunner):
    def __init__(self) -> None:
        self.calls = 0

    def run(self, task: TaskEnvelope) -> TaskResult:  # pragma: no cover - must stay unreachable
        self.calls += 1
        raise AssertionError(f"Reporter started despite failed preflight: {task.task_id}")


class _RejectedPreflight:
    def __init__(self, tamper_class: str) -> None:
        self.tamper_class = tamper_class
        self.calls = 0

    def authorize_reporter(self) -> None:
        self.calls += 1
        raise ReportPreflightV3Error(f"{self.tamper_class} artifact failed canonical preflight")


def _awaiting_review_run(tmp_path: Path) -> tuple[RunContext, VerticalWorkflowV3, _CountingRunner]:
    context = RunContext(
        tmp_path / "runs",
        {"profile": "local-lab", "hosts": ["localhost"]},
        run_id="phase4-preflight-matrix",
    )
    context.write_json(
        "state.json",
        VerticalStateV3(
            run_id=context.run_id,
            execution_state=ExecutionStateV3.AWAITING_REVIEW,
            network_state=NetworkStateV3.USED,
            requests_planned=15,
            requests_used=15,
            requests_blocked=0,
            current_role=None,
            next_required_action="review_sign",
            routed_branches=("web", "api", "authz", "infra"),
            succeeded_branches=("web", "api", "authz", "infra"),
            cleanup_state="restored",
            last_successful_checkpoint="verification_promoted_v3",
        ).model_dump(mode="json"),
    )
    runner = _CountingRunner()
    return context, VerticalWorkflowV3(context, runner), runner


@pytest.mark.parametrize("tamper_class", _TAMPER_CLASSES)
def test_every_authority_tamper_blocks_reporter_and_leaves_no_formal_report(
    tmp_path: Path,
    tamper_class: str,
) -> None:
    """The workflow boundary must never rely on a later report-write check.

    Lower-level tests prove that each named artifact class is detected by its
    canonical verifier.  This matrix locks the orchestration invariant common
    to all of them: a failed launch preflight means zero Reporter invocations
    and zero formal-output artifacts.
    """

    context, workflow, runner = _awaiting_review_run(tmp_path)
    preflight = _RejectedPreflight(tamper_class)

    with pytest.raises(ReportPreflightV3Error, match=tamper_class):
        workflow.complete_report(preflight)  # type: ignore[arg-type]

    assert preflight.calls == 1
    assert runner.calls == 0
    assert workflow.state().execution_state is ExecutionStateV3.AWAITING_REVIEW
    assert all(not context.artifact_path(path).exists() for path in _FORMAL_REPORT_PATHS)


def test_reporter_cannot_start_before_human_review_state(tmp_path: Path) -> None:
    context, workflow, runner = _awaiting_review_run(tmp_path)
    context.write_json(
        "state.json",
        workflow.state()
        .model_copy(
            update={
                "execution_state": ExecutionStateV3.CLEANUP_REQUIRED,
                "next_required_action": "approve_or_reject:cleanup",
                "cleanup_state": "required",
            }
        )
        .model_dump(mode="json"),
    )
    preflight = _RejectedPreflight("must-not-be-called")

    with pytest.raises(RuntimeError, match="not awaiting human review"):
        workflow.complete_report(preflight)  # type: ignore[arg-type]

    assert preflight.calls == 0
    assert runner.calls == 0
    assert all(not context.artifact_path(path).exists() for path in _FORMAL_REPORT_PATHS)
