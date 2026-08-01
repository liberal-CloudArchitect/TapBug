from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from hermes.domain_contracts_v3 import (
    Branch,
    BranchCandidateV3,
    CandidateCollection,
    CandidateTypeV3,
    CanonicalCandidateV3,
    CleanupActionResult,
    CleanupReceipt,
    CoverageReportV3,
    CrossReview,
    CrossReviewSet,
    DedupDecision,
    FindingSet,
    ReporterAckV3,
    ReporterLaunchReceiptV3,
    VerificationCandidateOutcome,
    VerificationOutcomeSet,
)
from hermes.evidence import EvidenceArtifactRef
from hermes.promotion_v3 import PromotionV3Error, promote_findings_v3
from hermes.reporting_v3 import (
    ReportWriteV3Error,
    VerifiedReportWriteV3,
    write_report_v3,
)
from hermes.runtime import RunContext

NOW = datetime.now(UTC)
RUN = "promotion-run"
SCOPE = "sha256:" + "a" * 64


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _evidence(number: int) -> EvidenceArtifactRef:
    return EvidenceArtifactRef(
        evidence_id=f"evidence-{number}",
        manifest_path=f"evidence/evidence-{number}/manifest.json",
        manifest_sha256=_digest(format(number, "x")[-1]),
    )


def _chain(
    *, mutation: bool = False
) -> tuple[CandidateCollection, CrossReviewSet, VerificationOutcomeSet, CleanupReceipt | None]:
    candidate_id = "api-graphql" if mutation else "web-xcto"
    candidate_type: CandidateTypeV3 = (
        "unauthorized_graphql_mutation" if mutation else "missing_x_content_type_options"
    )
    producer: Branch = "api" if mutation else "web"
    raw = BranchCandidateV3(
        candidate_id=candidate_id,
        candidate_type=candidate_type,
        producer_branch=producer,
        target_endpoint_id=f"endpoint-{candidate_id}",
        control_endpoint_ids=(f"control-{candidate_id}",),
        target_url=f"http://localhost:8080/{candidate_id}",
        method="POST" if mutation else "GET",
        request_body_sha256=_digest("b") if mutation else None,
        identity_binding_digest=_digest("c") if mutation else None,
        expected_assertion="local fixture security assertion",
        rationale="bounded local fixture candidate",
        semantic_fingerprint=_digest("1"),
    )
    canonical = CanonicalCandidateV3(
        candidate_id=candidate_id,
        candidate_type=candidate_type,
        semantic_fingerprint=raw.semantic_fingerprint,
        provenance=(producer,),
        source_candidate_ids=(candidate_id,),
    )
    collection = CandidateCollection(
        run_id=RUN,
        scope_digest=SCOPE,
        generated_by_task_id="phase4-fan-in",
        collection_id="collection",
        route_decision_digest=_digest("2"),
        branch_result_digests=(_digest("1"), _digest("2"), _digest("3"), _digest("4")),
        raw_candidates=(raw,),
        canonical_candidates=(canonical,),
        dedup_decisions=(
            DedupDecision(
                canonical_candidate_id=candidate_id,
                semantic_fingerprint=raw.semantic_fingerprint,
                merged_candidate_ids=(candidate_id,),
                provenance=(producer,),
            ),
        ),
    )
    review = CrossReview(
        review_id="independent-review",
        candidate_id=candidate_id,
        producer_branches=(producer,),
        reviewer_branch="infra" if producer != "infra" else "web",
        reviewer_task_id="cross-review-task",
        verdict="concur",
        rationale="independent reviewer concurs",
    )
    reviews = CrossReviewSet(
        run_id=RUN,
        scope_digest=SCOPE,
        generated_by_task_id="phase4-review-fan-in",
        review_set_id="review-set",
        candidate_collection_digest=collection.digest,
        reviews=(review,),
    )
    outcome = VerificationCandidateOutcome(
        outcome_id="verification-outcome",
        candidate_id=candidate_id,
        verifier_task_id="verifier-task",
        status="validated",
        action_digests=(_digest("5"), _digest("6")),
        action_ledger_entry_digests=(_digest("7"), _digest("8")),
        evidence=(_evidence(1), _evidence(2)),
        assertion_summary="candidate and strict negative control differ",
    )
    outcomes = VerificationOutcomeSet(
        run_id=RUN,
        scope_digest=SCOPE,
        generated_by_task_id="phase4-verification-fan-in",
        outcome_set_id="outcome-set",
        campaign_digest=_digest("9"),
        approval_batch_digests=(_digest("a"),),
        outcomes=(outcome,),
    )
    cleanup = None
    if mutation:
        cleanup = CleanupReceipt(
            run_id=RUN,
            scope_digest=SCOPE,
            generated_by_task_id="phase4-compensation",
            receipt_id="cleanup-receipt",
            campaign_digest=outcomes.campaign_digest,
            results=(
                CleanupActionResult(
                    forward_action_digest=_digest("5"),
                    cleanup_action_digest=_digest("b"),
                    cleanup_check_action_digest=_digest("c"),
                    status="cleaned",
                    evidence=(_evidence(3), _evidence(4)),
                ),
            ),
            initial_state_sha256=_digest("d"),
            final_state_sha256=_digest("d"),
            state_restored=True,
            completed_at=NOW,
        )
    return collection, reviews, outcomes, cleanup


def _coverage(finding_set: FindingSet) -> CoverageReportV3:
    return CoverageReportV3(
        run_id=RUN,
        scope_digest=SCOPE,
        generated_by_task_id="phase4-coverage",
        report_id="coverage",
        route_decision_digest=_digest("1"),
        candidate_collection_digest=finding_set.candidate_collection_digest,
        cross_review_set_digest=finding_set.cross_review_set_digest,
        campaign_digest=_digest("9"),
        outcome_set_digest=finding_set.verification_outcome_set_digest,
        finding_set_digest=finding_set.digest,
        cleanup_receipt_digest=finding_set.cleanup_receipt_digest,
        branches_routed=1,
        branches_succeeded=1,
        branches_failed=0,
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
        model_attempts_reserved=6,
        model_attempts_used=6,
        estimated_cost_microusd=1_500_000,
        active_elapsed_ms=50,
        completion="completed",
    )


class _Verifier:
    def __init__(self, verified: VerifiedReportWriteV3 | Exception):
        self.verified = verified
        self.calls = 0

    def verify_for_write(self, reporter_ack: ReporterAckV3) -> VerifiedReportWriteV3:
        self.calls += 1
        if isinstance(self.verified, Exception):
            raise self.verified
        return self.verified


def test_promotion_recomputes_only_validated_concurred_finding_and_exact_evidence() -> None:
    collection, reviews, outcomes, cleanup = _chain()
    findings = promote_findings_v3(collection, reviews, outcomes, cleanup)
    assert len(findings.findings) == 1
    assert findings.findings[0].evidence == outcomes.outcomes[0].evidence
    assert findings.findings[0].verification_outcome_digest == outcomes.outcomes[0].digest
    assert findings.findings[0].cross_review_digest == reviews.reviews[0].digest

    rejected = reviews.model_copy(
        update={
            "reviews": (reviews.reviews[0].model_copy(update={"verdict": "reject"}),),
        }
    )
    with pytest.raises(PromotionV3Error, match="rejected or inconclusive"):
        promote_findings_v3(collection, rejected, outcomes, cleanup)


def test_mutation_promotion_requires_continuous_restored_cleanup() -> None:
    collection, reviews, outcomes, cleanup = _chain(mutation=True)
    assert cleanup is not None
    findings = promote_findings_v3(collection, reviews, outcomes, cleanup)
    assert findings.cleanup_receipt_digest == cleanup.digest

    with pytest.raises(PromotionV3Error, match="require a cleanup"):
        promote_findings_v3(collection, reviews, outcomes, None)
    foreign_campaign = cleanup.model_copy(update={"campaign_digest": _digest("f")})
    with pytest.raises(PromotionV3Error, match="continue the verification campaign"):
        promote_findings_v3(collection, reviews, outcomes, foreign_campaign)
    unresolved = cleanup.model_copy(update={"state_restored": False, "final_state_sha256": None})
    with pytest.raises(PromotionV3Error, match="not restored"):
        promote_findings_v3(collection, reviews, outcomes, unresolved)


def test_report_write_rechecks_preflight_and_commits_three_bound_artifacts(tmp_path: Path) -> None:
    context = RunContext(tmp_path, {"fixture": "phase4"}, run_id=RUN)
    context.scope_digest = SCOPE
    collection, reviews, outcomes, cleanup = _chain()
    findings = promote_findings_v3(collection, reviews, outcomes, cleanup)
    coverage = _coverage(findings)
    launch = ReporterLaunchReceiptV3(
        run_id=RUN,
        scope_digest=context.scope_digest,
        generated_by_task_id="phase4-preflight-launch",
        receipt_id="launch",
        finding_set_digest=findings.digest,
        coverage_report_digest=coverage.digest,
        signed_review_digest=_digest("b"),
        action_ledger_head_digest=_digest("c"),
        budget_ledger_head_digest=_digest("d"),
        reporter_budget_reservation_digest=_digest("e"),
        verified_at=NOW,
    )
    metadata_digest = _digest("f")
    ack = ReporterAckV3(
        run_id=RUN,
        scope_digest=context.scope_digest,
        generated_by_task_id="phase4-reporter",
        launch_receipt_digest=launch.digest,
        finding_set_digest=findings.digest,
        coverage_report_digest=coverage.digest,
        provider_metadata_digest=metadata_digest,
    )
    verified = VerifiedReportWriteV3(
        launch_receipt=launch,
        finding_set=findings,
        coverage=coverage,
        provider_metadata_digest=metadata_digest,
        final_budget_ledger_head_digest=_digest("1"),
    )
    verifier = _Verifier(verified)
    report = write_report_v3(context, verifier, ack)
    assert verifier.calls == 1
    assert report.exists()
    findings_path = context.artifact_path("report/findings-v3.json")
    receipt_path = context.artifact_path("report/report-write-receipt-v3.json")
    assert findings_path.exists() and receipt_path.exists()
    persisted = json.loads(findings_path.read_text(encoding="utf-8"))
    assert persisted["finding_set_id"] == findings.finding_set_id


@pytest.mark.parametrize("failure", ["preflight", "ack", "provider"])
def test_report_failure_leaves_no_formal_files(tmp_path: Path, failure: str) -> None:
    context = RunContext(tmp_path, {"fixture": "phase4"}, run_id=RUN)
    context.scope_digest = SCOPE
    collection, reviews, outcomes, cleanup = _chain()
    findings = promote_findings_v3(collection, reviews, outcomes, cleanup)
    coverage = _coverage(findings)
    launch = ReporterLaunchReceiptV3(
        run_id=RUN,
        scope_digest=context.scope_digest,
        generated_by_task_id="phase4-preflight-launch",
        receipt_id="launch",
        finding_set_digest=findings.digest,
        coverage_report_digest=coverage.digest,
        signed_review_digest=_digest("b"),
        action_ledger_head_digest=_digest("c"),
        budget_ledger_head_digest=_digest("d"),
        reporter_budget_reservation_digest=_digest("e"),
        verified_at=NOW,
    )
    metadata = _digest("f")
    ack = ReporterAckV3(
        run_id=RUN,
        scope_digest=context.scope_digest,
        generated_by_task_id="phase4-reporter",
        launch_receipt_digest=launch.digest,
        finding_set_digest=findings.digest,
        coverage_report_digest=coverage.digest,
        provider_metadata_digest=metadata if failure != "ack" else _digest("0"),
    )
    verified = VerifiedReportWriteV3(
        launch_receipt=launch,
        finding_set=findings,
        coverage=coverage,
        provider_metadata_digest=metadata,
        final_budget_ledger_head_digest=_digest("1"),
    )
    verifier = _Verifier(
        ReportWriteV3Error("missing provider metadata") if failure == "preflight" else verified
    )
    if failure == "provider":
        verifier = _Verifier(
            VerifiedReportWriteV3(
                launch_receipt=launch,
                finding_set=findings,
                coverage=coverage,
                provider_metadata_digest=_digest("0"),
                final_budget_ledger_head_digest=_digest("1"),
            )
        )
    with pytest.raises(ReportWriteV3Error):
        write_report_v3(context, verifier, ack)
    assert not context.artifact_path("report/report-v3.md").exists()
    assert not context.artifact_path("report/findings-v3.json").exists()
    assert not context.artifact_path("report/report-write-receipt-v3.json").exists()
