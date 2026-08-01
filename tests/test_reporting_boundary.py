from __future__ import annotations

import inspect
from types import SimpleNamespace
from typing import Any

import pytest

import hermes.vertical_v2 as vertical_module
from hermes.legacy import LegacyRunReadOnlyError
from hermes.preflight import ReportPreflightError
from hermes.reporting import write_report
from hermes.runtime import RunContext
from hermes.vertical_v2 import ExecutionState, NetworkState, VerticalState, VerticalWorkflowV2


class _MustNotRunVerifier:
    def verify(self) -> Any:
        raise AssertionError("preflight must not run for a legacy artifact set")


def test_report_api_has_no_public_records_or_finding_bypass() -> None:
    assert tuple(inspect.signature(write_report).parameters) == (
        "context",
        "verifier",
        "reporter_ack",
    )


def test_legacy_run_cannot_regenerate_a_formal_report(tmp_path) -> None:
    context = RunContext(tmp_path / "runs", {}, run_id="legacy-report")
    context.write_json("plan/run-plan.json", {"version": "1"}, immutable=True)

    with pytest.raises(LegacyRunReadOnlyError, match="legacy_run_read_only"):
        write_report(context, _MustNotRunVerifier(), None)  # type: ignore[arg-type]

    assert not context.artifact_path("report/report.md").exists()
    assert not context.artifact_path("report/findings.json").exists()


def test_preflight_failure_happens_before_reporter_and_creates_no_formal_output(
    tmp_path, monkeypatch
) -> None:
    context = RunContext(tmp_path / "runs", {}, run_id="blocked-report")
    context.write_text("report/outcome.json", "{}", immutable=True)
    context.write_text("reviews/signed.json", "{}", immutable=True)
    context.write_text("report/draft.md", "draft", immutable=True)
    outcome = SimpleNamespace(candidate_id="candidate-1", digest="sha256:" + "a" * 64)
    outcome.status = "validated"
    review = SimpleNamespace(
        version="2",
        report_draft_digest="sha256:" + "b" * 64,
        verdict="accepted",
    )

    class OutcomeParser:
        model_validate_json = staticmethod(lambda _value: outcome)

    class ReviewParser:
        model_validate_json = staticmethod(lambda _value: review)

    class Promotion:
        def __init__(self, *_args, **_kwargs):
            pass

        def promote(self):
            return SimpleNamespace(), SimpleNamespace()

    class FailingPreflight:
        def __init__(self, *_args, **_kwargs):
            pass

        def authorize(self):
            raise ReportPreflightError("tampered evidence")

    monkeypatch.setattr(vertical_module, "VerificationOutcome", OutcomeParser)
    monkeypatch.setattr(vertical_module, "SignedHumanReview", ReviewParser)
    monkeypatch.setattr(vertical_module, "PromotionService", Promotion)
    monkeypatch.setattr(vertical_module, "ReportPreflightVerifier", FailingPreflight)
    monkeypatch.setattr(vertical_module, "file_sha256", lambda _path: review.report_draft_digest)
    monkeypatch.setattr(vertical_module, "verify_human_review", lambda *_a, **_kw: None)

    class CountingRunner:
        calls = 0

        def run(self, _task):
            self.calls += 1
            raise AssertionError("Reporter must not start")

    runner = CountingRunner()
    workflow = object.__new__(VerticalWorkflowV2)
    workflow.context = context
    workflow.runner = runner
    workflow.evidence_store = SimpleNamespace()
    workflow.publisher_store = SimpleNamespace()
    workflow.prompt_registry = SimpleNamespace()
    state = VerticalState(
        run_id=context.run_id,
        execution_state=ExecutionState.AWAITING_REVIEW,
        network_state=NetworkState.USED,
        requests_planned=3,
        requests_used=3,
        requests_blocked=0,
        current_role="verifier",
    )

    with pytest.raises(ReportPreflightError, match="tampered evidence"):
        workflow._resume_reporter(state, SimpleNamespace(), SimpleNamespace())  # type: ignore[arg-type]

    assert runner.calls == 0
    for relative in (
        "report/authorization.json",
        "report/reporter-acknowledgement.json",
        "report/findings.json",
        "report/report.md",
    ):
        assert not context.artifact_path(relative).exists()
