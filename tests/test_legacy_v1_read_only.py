from __future__ import annotations

import pytest

from hermes.legacy import (
    LegacyArtifactReader,
    LegacyRunReadOnlyError,
    legacy_evidence_is_promotable,
    require_v2_run,
)
from hermes.runtime import RunContext
from hermes.vertical import ExecutionState, NetworkState, VerticalState, VerticalWorkflow


def test_v1_run_can_be_audited_but_never_promoted(tmp_path) -> None:
    context = RunContext(tmp_path / "runs", {"profile": "local-lab"}, run_id="legacy-run")
    context.write_json(
        "plan/run-plan.json",
        {"version": "1", "run_id": context.run_id},
        immutable=True,
    )
    context.write_json(
        "evidence/legacy.json",
        {"request_hash": "sha256:" + "a" * 64},
        immutable=True,
    )

    before = {
        path.relative_to(context.path).as_posix(): path.read_bytes()
        for path in context.path.rglob("*")
        if path.is_file()
    }
    summary = LegacyArtifactReader(context).audit_summary()
    after = {
        path.relative_to(context.path).as_posix(): path.read_bytes()
        for path in context.path.rglob("*")
        if path.is_file()
    }

    assert summary.schema_version == "1"
    assert summary.promotable is False
    assert summary.artifact_count == 3  # scope, plan, evidence
    assert before == after
    assert legacy_evidence_is_promotable({}) is False
    with pytest.raises(LegacyRunReadOnlyError, match="legacy_run_read_only"):
        require_v2_run(context)


def test_v2_run_is_rejected_by_the_legacy_reader(tmp_path) -> None:
    context = RunContext(tmp_path / "runs", {}, run_id="v2-run")
    context.write_json("plan/run-plan.json", {"version": "2"}, immutable=True)

    require_v2_run(context)
    with pytest.raises(ValueError, match="only accepts version-1"):
        LegacyArtifactReader(context)


def test_legacy_vertical_entrypoint_fails_before_starting_reporter(tmp_path) -> None:
    context = RunContext(tmp_path / "runs", {}, run_id="legacy-resume")
    context.write_json("plan/run-plan.json", {"version": "1"}, immutable=True)

    class CountingRunner:
        calls = 0

        def run(self, _task):
            self.calls += 1
            raise AssertionError("legacy execution must not start an agent")

    runner = CountingRunner()

    start_context = RunContext(tmp_path / "start-runs", {}, run_id="legacy-start")
    start_workflow = VerticalWorkflow(start_context, runner)  # type: ignore[arg-type]
    with pytest.raises(RuntimeError, match="legacy_run_read_only"):
        start_workflow.start(
            target="http://localhost:8080/candidate",
            engine=object(),  # type: ignore[arg-type]
            provider="legacy",
            model="legacy",
            prompt_registry_digest="sha256:" + "a" * 64,
        )
    assert not start_context.artifact_path("plan/run-plan.json").exists()

    workflow = VerticalWorkflow(context, runner)  # type: ignore[arg-type]
    workflow._save_state(  # noqa: SLF001
        VerticalState(
            run_id=context.run_id,
            execution_state=ExecutionState.AWAITING_REVIEW,
            network_state=NetworkState.USED,
            requests_planned=3,
            requests_used=3,
            requests_blocked=0,
            current_role="verifier",
        )
    )

    with pytest.raises(RuntimeError, match="legacy_run_read_only"):
        workflow.resume_after_approval(
            approval_store=object(),  # type: ignore[arg-type]
            review_store=object(),  # type: ignore[arg-type]
        )

    assert runner.calls == 0
