from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from hermes.domain_contracts_v3 import (
    CoverageReportV3,
    FindingSet,
    ReporterAckV3,
    ReporterLaunchReceiptV3,
    RunPlanV3,
    SignedReviewBatchV3,
)
from hermes.ledgers_v3 import ActiveTimeLedger, BudgetLedger
from hermes.preflight_v3 import (
    ReportPreflightV3Error,
    ReportPreflightVerifierV3,
)
from hermes.runtime import RunContext
from hermes.security_v3 import coverage_gap_digests


def digest(character: str) -> str:
    return "sha256:" + character * 64


def context(tmp_path: Path) -> RunContext:
    return RunContext(
        tmp_path,
        {"hosts": ["localhost"], "ports": [8123], "profile": "local-lab-v3"},
        run_id="phase4-preflight-test",
    )


def verifier(
    run: RunContext, *, review_calls: list[str] | None = None
) -> ReportPreflightVerifierV3:
    def verify_review(
        review: SignedReviewBatchV3, findings: FindingSet, coverage: CoverageReportV3
    ) -> None:
        del findings, coverage
        if review_calls is not None:
            review_calls.append(review.review_id)

    return ReportPreflightVerifierV3(
        run,
        approval_signature_verifier=lambda approval, campaign: None,
        review_signature_verifier=verify_review,
    )


def findings(run: RunContext) -> FindingSet:
    return FindingSet(
        run_id=run.run_id,
        scope_digest=run.scope_digest,
        generated_by_task_id="phase4-promotion",
        finding_set_id="findings-v3",
        candidate_collection_digest=digest("1"),
        cross_review_set_digest=digest("2"),
        verification_outcome_set_digest=digest("3"),
        findings=(),
    )


def coverage(run: RunContext, *, gaps: tuple[str, ...]) -> CoverageReportV3:
    return CoverageReportV3(
        run_id=run.run_id,
        scope_digest=run.scope_digest,
        generated_by_task_id="phase4-coverage",
        report_id="coverage-v3",
        route_decision_digest=digest("1"),
        candidate_collection_digest=digest("2"),
        cross_review_set_digest=digest("3"),
        campaign_digest=digest("4"),
        outcome_set_digest=digest("5"),
        finding_set_digest=digest("6"),
        branches_routed=1,
        branches_succeeded=0 if gaps else 1,
        branches_failed=1 if gaps else 0,
        branches_timed_out=0,
        raw_candidates=1,
        canonical_candidates=1,
        duplicate_candidates=0,
        raw_blocked_or_inconclusive=0,
        candidates_validated=1,
        candidates_disproved=0,
        candidates_inconclusive=0,
        candidates_blocked=0,
        actions_planned=2,
        actions_executed=2,
        actions_blocked=0,
        actions_skipped=0,
        requests_planned=3,
        requests_used=3,
        model_attempts_reserved=8,
        model_attempts_used=7,
        estimated_cost_microusd=2_000_000,
        active_elapsed_ms=1,
        completion="completed_with_gaps" if gaps else "completed",
        gaps=gaps,
    )


def test_missing_canonical_graph_never_creates_report_or_receipt(tmp_path: Path) -> None:
    run = context(tmp_path)

    with pytest.raises(ReportPreflightV3Error, match="missing or invalid"):
        verifier(run).authorize_reporter()

    assert not run.artifact_path("report/reporter-launch-v3.json").exists()
    assert not run.artifact_path("report/formal-v3").exists()


def test_preflight_requires_coverage_active_time_snapshot_to_match_ledger(
    tmp_path: Path,
) -> None:
    run = context(tmp_path)
    plan = RunPlanV3(
        run_id=run.run_id,
        target="http://localhost:8123/",
        scope_digest=run.scope_digest,
        provider_id="hermes-acp-restricted",
        model_id="test-model",
        prompt_registry_digest=digest("1"),
        role_manifest_set_digest=digest("2"),
        roles=(
            "gatekeeper",
            "recon",
            "mapper",
            "web-vuln",
            "api",
            "authz",
            "infra",
            "verifier",
            "reporter",
        ),
        created_at=datetime.now(UTC),
    )
    snapshot = ActiveTimeLedger(run).record_snapshot("coverage-v3")
    matching = coverage(run, gaps=()).model_copy(
        update={"active_elapsed_ms": snapshot.active_elapsed_ms}
    )
    verifier(run)._verify_active_time(plan, matching)

    with pytest.raises(ReportPreflightV3Error, match="does not match"):
        verifier(run)._verify_active_time(
            plan, matching.model_copy(update={"active_elapsed_ms": 2})
        )


def test_human_review_requires_exact_gap_set_and_calls_signature_verifier(
    tmp_path: Path,
) -> None:
    run = context(tmp_path)
    finding_set = findings(run)
    coverage_report = coverage(run, gaps=("branch:api:failed:timeout",))
    run.write_text("report/draft-v3.md", "# bounded report\n", immutable=True)
    calls: list[str] = []
    review = SignedReviewBatchV3(
        run_id=run.run_id,
        scope_digest=run.scope_digest,
        generated_by_task_id="phase4-human-review",
        review_id="review-v3",
        finding_set_digest=finding_set.digest,
        coverage_report_digest=coverage_report.digest,
        report_draft_digest="sha256:"
        + __import__("hashlib").sha256(b"# bounded report\n").hexdigest(),
        gap_digests=coverage_gap_digests(coverage_report),
        verdict="accepted_with_gaps",
        reviewer_key_id="reviewer-v3",
        reviewed_at=datetime.now(UTC),
        rationale="accept the exact visible assessment gap",
        signature_b64="signed-review-value",
    )

    verifier(run, review_calls=calls)._verify_human_review(finding_set, coverage_report, review)
    assert calls == ["review-v3"]

    tampered = review.model_copy(update={"gap_digests": (digest("f"),)})
    with pytest.raises(ReportPreflightV3Error, match="verdict"):
        verifier(run)._verify_human_review(finding_set, coverage_report, tampered)


def test_invalid_reporter_ack_cannot_create_any_formal_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = context(tmp_path)
    finding_set = findings(run)
    coverage_report = coverage(run, gaps=())
    launch = ReporterLaunchReceiptV3(
        run_id=run.run_id,
        scope_digest=run.scope_digest,
        generated_by_task_id="phase4-preflight-launch",
        receipt_id="launch-v3",
        finding_set_digest=finding_set.digest,
        coverage_report_digest=coverage_report.digest,
        signed_review_digest=digest("1"),
        action_ledger_head_digest=digest("2"),
        budget_ledger_head_digest=digest("3"),
        reporter_budget_reservation_digest=digest("4"),
        verified_at=datetime.now(UTC),
    )
    run.write_json("report/reporter-launch-v3.json", launch.model_dump(mode="json"), immutable=True)
    run.write_json(
        "provider/phase4-reporter.json",
        {"run_id": run.run_id, "task_id": "phase4-reporter"},
        immutable=True,
    )
    fake = SimpleNamespace(
        findings=finding_set,
        coverage=coverage_report,
    )
    subject = verifier(run)
    monkeypatch.setattr(subject, "verify_launch", lambda: fake)
    ack = ReporterAckV3(
        run_id=run.run_id,
        scope_digest=run.scope_digest,
        generated_by_task_id="phase4-reporter",
        launch_receipt_digest=launch.digest,
        finding_set_digest=finding_set.digest,
        coverage_report_digest=coverage_report.digest,
        provider_metadata_digest=digest("f"),
    )
    run.write_json("report/reporter-ack-v3.json", ack.model_dump(mode="json"), immutable=True)

    with pytest.raises(ReportPreflightV3Error, match="acknowledgement"):
        subject.verify_for_write(ack)

    assert not run.artifact_path("report/report-v3.md").exists()
    assert not run.artifact_path("report/findings-v3.json").exists()
    assert not run.artifact_path("report/report-write-receipt-v3.json").exists()


def test_launch_budget_head_allows_only_reporter_settlement_and_repair(
    tmp_path: Path,
) -> None:
    run = context(tmp_path)
    ledger = BudgetLedger(run)
    reservation = ledger.reserve_prompt(
        task_id="phase4-reporter",
        role="reporter",
        attempt_kind="reporter",
        reservation_id="phase4-reporter:reporter",
    )
    launch_head = ledger.events()[-1]["event_hash"]
    launch = ReporterLaunchReceiptV3(
        run_id=run.run_id,
        scope_digest=run.scope_digest,
        generated_by_task_id="phase4-preflight-launch",
        receipt_id="launch-v3",
        finding_set_digest=digest("1"),
        coverage_report_digest=digest("2"),
        signed_review_digest=digest("3"),
        action_ledger_head_digest=digest("4"),
        budget_ledger_head_digest=launch_head,
        reporter_budget_reservation_digest=digest("5"),
        verified_at=datetime.now(UTC),
    )
    ledger.settle(reservation.reservation_id)
    subject = verifier(run)

    subject._verify_launch_budget_ancestor(launch, ledger.events())

    ledger.reserve_prompt(
        task_id="unexpected-task",
        role="api",
        reservation_id="unexpected-task:initial",
    )
    with pytest.raises(ReportPreflightV3Error, match="outside"):
        subject._verify_launch_budget_ancestor(launch, ledger.events())
