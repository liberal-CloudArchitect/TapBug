from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from hermes.domain_contracts_v3 import (
    ActionLedgerEntry,
    ApprovalBatchV3,
    AssetInventoryV3,
    AssetV3,
    BranchAssessment,
    BranchCandidateV3,
    BranchCoverage,
    BranchResult,
    BudgetLedgerEntry,
    CandidateCollection,
    CanonicalCandidateV3,
    CleanupActionResult,
    CleanupReceipt,
    ContractEnvelopeV3,
    CoverageReportV3,
    CrossReview,
    CrossReviewSet,
    DedupDecision,
    EndpointInventoryV3,
    EndpointV3,
    ExecutionBudgetV3,
    FindingSet,
    FindingV3,
    GateDecisionV3,
    ReporterAckV3,
    ReporterLaunchReceiptV3,
    ReportWriteReceiptV3,
    RouteBranchDecision,
    RouteDecision,
    RunPlanV3,
    SignedReviewBatchV3,
    VerificationActionV3,
    VerificationCampaignPlan,
    VerificationCandidateOutcome,
    VerificationOutcomeSet,
)
from hermes.evidence import EvidenceArtifactRef

RUN = "run-v3"
TASK = "host-v3"
DIGEST = "sha256:" + "a" * 64
NOW = datetime.now(UTC)


def digest(character: str = "a") -> str:
    return "sha256:" + character * 64


def evidence(number: int) -> EvidenceArtifactRef:
    character = format(number, "x")[-1]
    return EvidenceArtifactRef(
        evidence_id=f"ev-{number}",
        manifest_path=f"evidence/ev-{number}/manifest.json",
        manifest_sha256=digest(character),
    )


def run_fields(task: str = TASK) -> dict[str, str]:
    return {"run_id": RUN, "scope_digest": DIGEST, "generated_by_task_id": task}


def candidate(
    candidate_id: str,
    candidate_type: str,
    branch: str,
    fingerprint: str,
) -> BranchCandidateV3:
    mutation = candidate_type in {"unauthorized_graphql_mutation", "privilege_escalation"}
    return BranchCandidateV3(
        candidate_id=candidate_id,
        candidate_type=candidate_type,
        producer_branch=branch,
        target_endpoint_id=f"endpoint-{candidate_id}",
        control_endpoint_ids=(f"control-{candidate_id}",),
        target_url=f"http://localhost:8080/{candidate_id}",
        method="POST" if mutation else "GET",
        request_body_sha256=digest("b") if mutation else None,
        identity_binding_digest=digest("c") if mutation else None,
        expected_assertion="fixture security assertion",
        rationale="bounded local fixture candidate",
        semantic_fingerprint=fingerprint,
    )


def raw_candidates() -> tuple[BranchCandidateV3, ...]:
    return (
        candidate("web-xcto", "missing_x_content_type_options", "web", digest("1")),
        candidate(
            "api-graphql",
            "unauthorized_graphql_mutation",
            "api",
            digest("2"),
        ),
        candidate("authz-escalation", "privilege_escalation", "authz", digest("3")),
        candidate("infra-debug", "exposed_debug_endpoint", "infra", digest("4")),
        candidate("infra-xcto-copy", "missing_x_content_type_options", "infra", digest("1")),
    )


def collection() -> CandidateCollection:
    raw = raw_candidates()
    canonical = (
        CanonicalCandidateV3(
            candidate_id="web-xcto",
            candidate_type="missing_x_content_type_options",
            semantic_fingerprint=digest("1"),
            provenance=("web", "infra"),
            source_candidate_ids=("web-xcto", "infra-xcto-copy"),
        ),
        CanonicalCandidateV3(
            candidate_id="api-graphql",
            candidate_type="unauthorized_graphql_mutation",
            semantic_fingerprint=digest("2"),
            provenance=("api",),
            source_candidate_ids=("api-graphql",),
        ),
        CanonicalCandidateV3(
            candidate_id="authz-escalation",
            candidate_type="privilege_escalation",
            semantic_fingerprint=digest("3"),
            provenance=("authz",),
            source_candidate_ids=("authz-escalation",),
        ),
        CanonicalCandidateV3(
            candidate_id="infra-debug",
            candidate_type="exposed_debug_endpoint",
            semantic_fingerprint=digest("4"),
            provenance=("infra",),
            source_candidate_ids=("infra-debug",),
        ),
    )
    decisions = tuple(
        DedupDecision(
            canonical_candidate_id=item.candidate_id,
            semantic_fingerprint=item.semantic_fingerprint,
            merged_candidate_ids=item.source_candidate_ids,
            provenance=item.provenance,
        )
        for item in canonical
    )
    return CandidateCollection(
        **run_fields(),
        collection_id="collection-1",
        route_decision_digest=digest("5"),
        branch_result_digests=(digest("1"), digest("2"), digest("3"), digest("4")),
        raw_candidates=raw,
        canonical_candidates=canonical,
        dedup_decisions=decisions,
    )


def test_budget_and_run_plan_are_strict_frozen_and_hash_bound() -> None:
    budget = ExecutionBudgetV3()
    plan = RunPlanV3(
        run_id=RUN,
        target="http://localhost:8080/",
        scope_digest=DIGEST,
        provider_id="hermes-acp",
        model_id="fixture-model",
        prompt_registry_digest=digest("b"),
        role_manifest_set_digest=digest("c"),
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
        identity_binding_digests={"member": digest("d")},
        budget=budget,
        created_at=NOW,
    )
    assert plan.digest == RunPlanV3.model_validate_json(plan.model_dump_json()).digest
    with pytest.raises(ValidationError):
        ExecutionBudgetV3(max_model_attempts=41)
    with pytest.raises(ValidationError):
        RunPlanV3(**plan.model_dump(), unexpected=True)
    with pytest.raises(ValidationError):
        plan.run_id = "changed"  # type: ignore[misc]


def test_dynamic_inventory_route_and_branch_failure_are_typed() -> None:
    asset = AssetInventoryV3(
        **run_fields("recon-v3"),
        inventory_id="assets-v3",
        target="http://localhost:8080/",
        assets=(
            AssetV3(
                asset_id="asset-1",
                scheme="http",
                port=8080,
                resolved_ips=("127.0.0.1",),
                status_code=200,
                observed_relations=("graphql", "role-change", "debug"),
                observed_links=(),
            ),
        ),
        source_evidence=(evidence(1),),
    )
    endpoints = EndpointInventoryV3(
        **run_fields("mapper-v3"),
        inventory_id="endpoints-v3",
        asset_inventory_digest=asset.digest,
        endpoints=(
            EndpointV3(
                endpoint_id="graphql",
                asset_id="asset-1",
                canonical_url="http://localhost:8080/graphql",
                method="POST",
                relation="graphql",
                auth_contexts=("member",),
                evidence=(evidence(1),),
            ),
            EndpointV3(
                endpoint_id="debug",
                asset_id="asset-1",
                canonical_url="http://localhost:8080/debug",
                method="GET",
                relation="debug",
                evidence=(evidence(1),),
            ),
        ),
    )
    route = RouteDecision(
        **run_fields("router-v3"),
        decision_id="route-1",
        endpoint_inventory_digest=endpoints.digest,
        branches=(
            RouteBranchDecision(branch="web", routed=False, reason="no HTML endpoint"),
            RouteBranchDecision(branch="api", routed=True, feature_ids=("graphql",), reason="API"),
            RouteBranchDecision(branch="authz", routed=False, reason="no role-change endpoint"),
            RouteBranchDecision(
                branch="infra", routed=True, feature_ids=("debug",), reason="debug"
            ),
        ),
    )
    failed = BranchResult(
        **run_fields("api-v3"),
        branch="api",
        status="failed",
        provider_metadata_digest=digest("e"),
        started_at=NOW,
        finished_at=NOW + timedelta(seconds=1),
        reason="isolated provider failure",
    )
    assert route.routed_branches == ("api", "infra")
    assert failed.status == "failed"
    with pytest.raises(ValidationError):
        BranchResult(**{**failed.model_dump(), "status": "indeterminate"})


def test_assessment_collection_conserves_real_duplicate() -> None:
    raw = raw_candidates()
    assessment = BranchAssessment(
        **run_fields("infra-v3"),
        assessment_id="assessment-infra",
        branch="infra",
        endpoint_inventory_digest=DIGEST,
        prompt_id="infra",
        prompt_version="3.0",
        prompt_sha256=digest("f"),
        candidates=(raw[3], raw[4]),
        coverage=BranchCoverage(endpoints_considered=2, candidates_emitted=2),
    )
    candidates = collection()
    assert len(candidates.raw_candidates) == 5
    assert len(candidates.canonical_candidates) == 4
    assert assessment.coverage.candidates_emitted == 2
    with pytest.raises(ValidationError, match="raw candidate count"):
        CandidateCollection(**{**candidates.model_dump(), "raw_candidates": raw[:4]})


def test_cross_review_forbids_self_review() -> None:
    review = CrossReview(
        review_id="review-web",
        candidate_id="web-xcto",
        producer_branches=("web", "infra"),
        reviewer_branch="api",
        reviewer_task_id="review-task-api",
        verdict="concur",
        rationale="independent contract review concurs",
    )
    reviews = CrossReviewSet(
        **run_fields("review-coordinator"),
        review_set_id="reviews-1",
        candidate_collection_digest=collection().digest,
        reviews=(review,),
    )
    assert reviews.operation == "cross_review"
    with pytest.raises(ValidationError, match="producer branch"):
        CrossReview(**{**review.model_dump(), "reviewer_branch": "web"})


def test_campaign_approval_and_ledgers_enforce_binding() -> None:
    forward = VerificationActionV3(
        action_id="graphql-forward",
        candidate_id="api-graphql",
        candidate_consumers=("api-graphql",),
        purpose="candidate",
        risk_group="mutation",
        action_kind="validation_http_request",
        method="POST",
        target_url="http://localhost:8080/graphql",
        body_sha256=digest("b"),
        identity_binding_digest=digest("c"),
        action_digest=digest("1"),
    )
    cleanup = VerificationActionV3(
        action_id="graphql-cleanup",
        candidate_id="api-graphql",
        candidate_consumers=("api-graphql",),
        purpose="cleanup",
        risk_group="mutation",
        action_kind="validation_http_request",
        method="POST",
        target_url="http://localhost:8080/graphql",
        body_sha256=digest("d"),
        identity_binding_digest=digest("c"),
        action_digest=digest("2"),
        depends_on=("graphql-forward",),
        cleanup_of="graphql-forward",
    )
    campaign = VerificationCampaignPlan(
        **run_fields("planner-v3"),
        campaign_id="campaign-1",
        candidate_collection_digest=collection().digest,
        cross_review_set_digest=digest("3"),
        actions=(forward, cleanup),
        request_budget=2,
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
    )
    approval = ApprovalBatchV3(
        **run_fields("approver-v3"),
        approval_id="approval-mutation",
        campaign_digest=campaign.digest,
        risk_group="mutation",
        verdict="approved",
        candidate_ids=("api-graphql",),
        action_digests=(forward.action_digest, cleanup.action_digest),
        key_id="approver-key",
        signed_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        rationale="approve bounded fixture mutation and cleanup",
        signature_b64="c2lnbmF0dXJlLWZpeHR1cmU=",
    )
    action_entry = ActionLedgerEntry(
        **run_fields("verifier-v3"),
        ledger_entry_id="action-entry-1",
        sequence=1,
        action_id=forward.action_id,
        action_digest=forward.action_digest,
        action_fingerprint=digest("4"),
        candidate_consumers=("api-graphql",),
        state="evidence_committed",
        approval_batch_digest=approval.digest,
        consumption_digest=digest("5"),
        evidence=evidence(2),
        occurred_at=NOW,
    )
    budget_entry = BudgetLedgerEntry(
        **run_fields("verifier-v3"),
        ledger_entry_id="budget-entry-1",
        sequence=1,
        task_id="verifier-v3",
        role="verifier",
        attempt_number=40,
        event="reserved",
        reserved_microusd=250_000,
        occurred_at=NOW,
    )
    assert action_entry.evidence == evidence(2)
    assert budget_entry.actual_cost_microusd is None
    with pytest.raises(ValidationError):
        BudgetLedgerEntry(**{**budget_entry.model_dump(), "attempt_number": 41})


def test_outcome_cleanup_finding_and_coverage_conserve_counts() -> None:
    outcome = VerificationCandidateOutcome(
        outcome_id="outcome-api",
        candidate_id="api-graphql",
        verifier_task_id="verifier-api",
        status="validated",
        action_digests=(digest("1"), digest("2")),
        action_ledger_entry_digests=(digest("3"), digest("4")),
        evidence=(evidence(2), evidence(3)),
        assertion_summary="unauthorized mutation differs from strict control",
    )
    outcomes = VerificationOutcomeSet(
        **run_fields("outcome-coordinator"),
        outcome_set_id="outcomes-1",
        campaign_digest=digest("5"),
        approval_batch_digests=(digest("6"),),
        outcomes=(outcome,),
    )
    cleanup_result = CleanupActionResult(
        forward_action_digest=digest("1"),
        cleanup_action_digest=digest("2"),
        cleanup_check_action_digest=digest("3"),
        status="cleaned",
        evidence=(evidence(4), evidence(5)),
    )
    cleanup = CleanupReceipt(
        **run_fields("compensation-manager"),
        receipt_id="cleanup-1",
        campaign_digest=digest("5"),
        results=(cleanup_result,),
        initial_state_sha256=digest("7"),
        final_state_sha256=digest("7"),
        state_restored=True,
        completed_at=NOW,
    )
    finding = FindingV3(
        finding_id="api-graphql",
        candidate_id="api-graphql",
        candidate_type="unauthorized_graphql_mutation",
        verification_outcome_digest=outcome.digest,
        cross_review_digest=digest("8"),
        evidence=(evidence(2), evidence(3)),
        title="Fixture GraphQL authorization gap",
        summary="Local fixture accepts a forbidden mutation.",
        severity="informational",
    )
    findings = FindingSet(
        **run_fields("promotion-v3"),
        finding_set_id="findings-1",
        candidate_collection_digest=collection().digest,
        cross_review_set_digest=digest("8"),
        verification_outcome_set_digest=outcomes.digest,
        cleanup_receipt_digest=cleanup.digest,
        findings=(finding,),
    )
    coverage = CoverageReportV3(
        **run_fields("coverage-v3"),
        report_id="coverage-1",
        route_decision_digest=digest("1"),
        candidate_collection_digest=collection().digest,
        cross_review_set_digest=digest("2"),
        campaign_digest=digest("3"),
        outcome_set_digest=outcomes.digest,
        finding_set_digest=findings.digest,
        cleanup_receipt_digest=cleanup.digest,
        branches_routed=4,
        branches_succeeded=4,
        branches_failed=0,
        branches_timed_out=0,
        raw_candidates=5,
        canonical_candidates=4,
        duplicate_candidates=1,
        raw_blocked_or_inconclusive=0,
        candidates_validated=4,
        candidates_disproved=0,
        candidates_inconclusive=0,
        candidates_blocked=0,
        actions_planned=14,
        actions_executed=14,
        actions_blocked=0,
        actions_skipped=0,
        requests_planned=15,
        requests_used=15,
        model_attempts_reserved=16,
        model_attempts_used=16,
        estimated_cost_microusd=4_000_000,
        active_elapsed_ms=100,
        completion="completed",
    )
    assert coverage.digest.startswith("sha256:")
    with pytest.raises(ValidationError, match="routed branches"):
        CoverageReportV3(**{**coverage.model_dump(), "branches_failed": 1})


def test_signed_review_receipts_and_v3_envelope_are_closed() -> None:
    review = SignedReviewBatchV3(
        **run_fields("reviewer-human"),
        review_id="human-review-1",
        finding_set_digest=digest("1"),
        coverage_report_digest=digest("2"),
        report_draft_digest=digest("3"),
        verdict="accepted",
        reviewer_key_id="reviewer-key",
        reviewed_at=NOW,
        rationale="accepted local teaching fixture report",
        signature_b64="c2lnbmF0dXJlLWZpeHR1cmU=",
    )
    launch = ReporterLaunchReceiptV3(
        **run_fields("preflight-v3"),
        receipt_id="launch-1",
        finding_set_digest=review.finding_set_digest,
        coverage_report_digest=review.coverage_report_digest,
        signed_review_digest=review.digest,
        action_ledger_head_digest=digest("4"),
        budget_ledger_head_digest=digest("5"),
        reporter_budget_reservation_digest=digest("6"),
        verified_at=NOW,
    )
    ack = ReporterAckV3(
        **run_fields("reporter-v3"),
        launch_receipt_digest=launch.digest,
        finding_set_digest=review.finding_set_digest,
        coverage_report_digest=review.coverage_report_digest,
        provider_metadata_digest=digest("7"),
    )
    write = ReportWriteReceiptV3(
        **run_fields("preflight-v3-final"),
        receipt_id="write-1",
        launch_receipt_digest=launch.digest,
        reporter_ack_digest=ack.digest,
        final_budget_ledger_head_digest=digest("8"),
        report_sha256=digest("9"),
        findings_sha256=digest("a"),
        written_at=NOW,
    )
    envelope = ContractEnvelopeV3.for_payload(ack)
    gate = GateDecisionV3(
        **run_fields("gate-v3"),
        decision="allowed",
        target="http://localhost:8080/",
        resolved_ips=("127.0.0.1",),
        reason="loopback fixture is in scope",
    )
    assert envelope.contract_id == "hermes.reporter_acknowledgement/v3"
    assert write.reporter_ack_digest == ack.digest
    assert ContractEnvelopeV3.for_payload(gate).operation == "gate"
    with pytest.raises(ValidationError, match="payload hash"):
        ContractEnvelopeV3(
            contract_id=envelope.contract_id,
            operation=envelope.operation,
            payload=ack,
            payload_sha256=DIGEST,
        )
