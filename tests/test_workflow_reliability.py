from __future__ import annotations

from pathlib import Path

from hermes.runtime import RunContext
from hermes.runtime.agents import FixtureAgentRunner, HandoffEnvelope, TaskEnvelope
from hermes.workflow import WorkflowEngine


def _complete(task: TaskEnvelope) -> HandoffEnvelope:
    return HandoffEnvelope(
        run_id=task.run_id,
        task_id=task.task_id,
        role=task.role,
        scope_digest=task.scope_digest,
        input_sha256=task.input_hash(),
        status="completed",
        result={"role": task.role},
    )


def test_resume_reuses_hash_identical_completed_task(tmp_path: Path) -> None:
    context = RunContext(tmp_path / "runs", {"scope": "fixture"}, run_id="reliable-run")
    WorkflowEngine(context, FixtureAgentRunner({"gatekeeper": _complete})).run_roles(
        ("gatekeeper",), {"target": "fixture"}
    )

    resumed = RunContext.open_existing(tmp_path / "runs", {"scope": "fixture"}, "reliable-run")
    results = WorkflowEngine(resumed, FixtureAgentRunner({})).run_roles(
        ("gatekeeper",), {"target": "fixture"}
    )

    assert results[0].handoff is not None
    assert '"event":"task_resumed"' in (resumed.path / "workflow" / "events.jsonl").read_text(
        encoding="utf-8"
    )
