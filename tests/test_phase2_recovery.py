from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from hermes.cli import _parser
from hermes.runtime import RunContext
from hermes.runtime.agents import (
    AgentRunner,
    EvidenceRef,
    HandoffEnvelope,
    TaskEnvelope,
    TaskResult,
)
from hermes.vertical import (
    ExecutionState,
    NetworkState,
    VerticalState,
    VerticalWorkflow,
    VerticalWorkflowError,
)
from hermes.vertical_contracts import ReconObservation

SCOPE = "sha256:" + "a" * 64


class FailingRunner(AgentRunner):
    def run(self, task: TaskEnvelope) -> TaskResult:
        now = datetime.now(UTC)
        return TaskResult(
            task=task,
            lifecycle="failed",
            input_sha256=task.input_hash(),
            started_at=now,
            finished_at=now,
            stderr_sha256="sha256:" + "b" * 64,
            error="container exited before handoff",
            failure_layer="docker",
            failure_code="container_exit_nonzero",
            retryable=True,
            exit_code=17,
        )


def test_failed_role_writes_redacted_failure_and_actionable_state(tmp_path) -> None:
    context = RunContext(tmp_path / "runs", {"scope": "fixture"}, run_id="failed-run")
    workflow = VerticalWorkflow(context, FailingRunner())
    workflow._save_state(  # noqa: SLF001 - focused recovery contract test
        VerticalState(
            run_id=context.run_id,
            execution_state=ExecutionState.RUNNING,
            network_state=NetworkState.ENABLED_IDLE,
            requests_planned=3,
            requests_used=0,
            requests_blocked=0,
            current_role="verifier",
            last_successful_checkpoint="candidate_ready",
        )
    )

    with pytest.raises(VerticalWorkflowError, match="container exited") as raised:
        workflow._run_role("verifier", {})  # noqa: SLF001
    failed = workflow.mark_failed(raised.value)

    assert failed.execution_state is ExecutionState.FAILED
    assert failed.failure_stage == "verifier"
    assert failed.failure_code == "container_exit_nonzero"
    assert failed.next_required_action == "retry_as_new_run_and_reapprove"
    failure = json.loads(context.artifact_path("failure.json").read_text())
    assert failure["layer"] == "docker"
    assert failure["exit_code"] == 17
    assert failure["stderr_sha256"] == "sha256:" + "b" * 64
    assert "stderr" not in failure


def test_vertical_state_remains_compatible_with_pre_failure_metadata() -> None:
    state = VerticalState.model_validate(
        {
            "run_id": "old-run",
            "execution_state": "awaiting_approval",
            "network_state": "used",
            "requests_planned": 3,
            "requests_used": 1,
            "requests_blocked": 0,
            "current_role": "web-vuln",
            "next_required_action": "approve_or_reject",
            "artifacts": {},
        }
    )

    assert state.failure_code is None
    assert state.last_successful_checkpoint is None


def test_retry_command_requires_an_explicit_failed_run_identity() -> None:
    args = _parser().parse_args(["retry", "--config", "config.json", "--run-id", "failed-run"])

    assert args.command == "retry"
    assert args.run_id == "failed-run"


def test_mapper_evidence_id_is_normalized_to_the_host_supplied_reference() -> None:
    evidence = EvidenceRef(
        id="evidence-1",
        kind="response",
        sha256="sha256:" + "b" * 64,
        path="evidence/evidence-1.json",
    )
    recon = ReconObservation(
        url="http://localhost:8080/candidate",
        status_code=200,
        headers={"Link": '</control>; rel="negative-control"'},
        evidence=evidence,
    )

    surface = VerticalWorkflow._validated_attack_surface(  # noqa: SLF001
        {
            "target_url": recon.url,
            "negative_control_url": "http://localhost:8080/control",
            "source_evidence": evidence.id,
        },
        recon,
    )

    assert surface.source_evidence == evidence


def test_verifier_details_string_is_normalized_and_evidence_order_is_bound() -> None:
    target = EvidenceRef(
        id="target",
        kind="response",
        sha256="sha256:" + "b" * 64,
        path="evidence/target.json",
    )
    control = EvidenceRef(
        id="control",
        kind="response",
        sha256="sha256:" + "c" * 64,
        path="evidence/control.json",
    )
    task = TaskEnvelope(
        run_id="run-1",
        task_id="phase2-verifier",
        role="verifier",
        scope_digest=SCOPE,
    )
    handoff = HandoffEnvelope(
        run_id=task.run_id,
        task_id=task.task_id,
        role=task.role,
        scope_digest=task.scope_digest,
        input_sha256=task.input_hash(),
        status="completed",
        evidence_refs=(target, control),
    )
    now = datetime.now(UTC)
    result = TaskResult(
        task=task,
        handoff=handoff,
        lifecycle="completed",
        input_sha256=task.input_hash(),
        started_at=now,
        finished_at=now,
    )

    outcome = VerticalWorkflow._validated_verification_outcome(  # noqa: SLF001
        {
            "outcome_id": "outcome-1",
            "candidate_id": "candidate-1",
            "run_id": task.run_id,
            "scope_digest": task.scope_digest,
            "status": "validated",
            "target_evidence": target.model_dump(mode="json"),
            "control_evidence": control.model_dump(mode="json"),
            "differential_assertion": "Target omits nosniff and control includes it.",
            "details": "Validated from the ordered target and control observations.",
        },
        result,
    )

    assert outcome.details == {
        "summary": "Validated from the ordered target and control observations."
    }


def test_reporter_single_result_alias_is_bound_to_the_expected_finding() -> None:
    assert (
        VerticalWorkflow._validated_reporter_ack(  # noqa: SLF001
            {"result": "finding-1"}, "finding-1"
        )
        == "finding-1"
    )
    with pytest.raises(VerticalWorkflowError, match="not bound"):
        VerticalWorkflow._validated_reporter_ack(  # noqa: SLF001
            {"result": "another-finding"}, "finding-1"
        )
