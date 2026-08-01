from __future__ import annotations

from pathlib import Path

import pytest

from hermes.runtime import RunContext
from hermes.runtime.agents import FixtureAgentRunner, HandoffEnvelope, TaskEnvelope
from hermes.workflow import WorkflowBlocked, WorkflowEngine

SCOPE = "sha256:" + "a" * 64


def _context(tmp_path: Path) -> RunContext:
    return RunContext(tmp_path / "runs", {"scope": "fixture"}, run_id="workflow-run")


def test_workflow_invokes_independent_roles_and_persists_handoffs(tmp_path: Path) -> None:
    calls: list[str] = []

    def complete(task: TaskEnvelope) -> HandoffEnvelope:
        calls.append(task.role)
        return HandoffEnvelope(
            run_id=task.run_id,
            task_id=task.task_id,
            role=task.role,
            scope_digest=task.scope_digest,
            input_sha256=task.input_hash(),
            status="completed",
            result={"role": task.role},
        )

    engine = WorkflowEngine(
        _context(tmp_path),
        FixtureAgentRunner(
            {
                "gatekeeper": complete,
                "recon": complete,
                "mapper": complete,
            }
        ),
    )

    results = engine.run_roles(("gatekeeper", "recon", "mapper"), {"target": "fixture"})

    assert calls == ["gatekeeper", "recon", "mapper"]
    assert [result.handoff.role for result in results if result.handoff] == calls
    assert (engine.context.path / "handoffs" / "000-gatekeeper.json").exists()
    first_handoff = (engine.context.path / "handoffs" / "001-recon.json").read_text()
    assert '"allowed_actions":["http_get"]' in first_handoff


def test_invalid_handoff_blocks_downstream_roles(tmp_path: Path) -> None:
    calls: list[str] = []

    def invalid(task: TaskEnvelope) -> HandoffEnvelope:
        calls.append(task.role)
        return HandoffEnvelope(
            run_id="wrong-run",
            task_id=task.task_id,
            role=task.role,
            scope_digest=task.scope_digest,
            input_sha256=task.input_hash(),
            status="completed",
        )

    engine = WorkflowEngine(_context(tmp_path), FixtureAgentRunner({"gatekeeper": invalid}))

    with pytest.raises(WorkflowBlocked, match="gatekeeper"):
        engine.run_roles(("gatekeeper", "recon"), {"target": "fixture"})
    assert calls == ["gatekeeper"]


def test_verifier_handoff_requires_redacted_evidence(tmp_path: Path) -> None:
    def complete_without_evidence(task: TaskEnvelope) -> HandoffEnvelope:
        return HandoffEnvelope(
            run_id=task.run_id,
            task_id=task.task_id,
            role=task.role,
            scope_digest=task.scope_digest,
            input_sha256=task.input_hash(),
            status="completed",
        )

    engine = WorkflowEngine(
        _context(tmp_path), FixtureAgentRunner({"verifier": complete_without_evidence})
    )

    with pytest.raises(WorkflowBlocked, match="required evidence"):
        engine.run_roles(("verifier",), {"candidate": "candidate-1", "approval_id": "approval-1"})


def test_verifier_is_not_invoked_without_an_approval(tmp_path: Path) -> None:
    engine = WorkflowEngine(_context(tmp_path), FixtureAgentRunner({}))

    with pytest.raises(WorkflowBlocked, match="approval_id"):
        engine.run_roles(("verifier",), {"candidate": "candidate-1"})
