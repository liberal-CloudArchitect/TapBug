from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from hermes.campaign_v3 import (
    ActionLedgerSummary,
    BudgetCoverageSummary,
    CampaignV3Error,
    build_coverage_report,
    build_verification_campaign,
    materialized_body_digest,
    summarize_action_ledger,
)
from hermes.domain_contracts_v3 import (
    ActionLedgerEntry,
    BranchCandidateV3,
    BranchResult,
    CandidateCollection,
    CanonicalCandidateV3,
    CrossReview,
    CrossReviewSet,
    DedupDecision,
    FindingSet,
    FindingV3,
    VerificationCandidateOutcome,
    VerificationOutcomeSet,
)
from hermes.evidence import EvidenceArtifactRef

RUN = "run-phase4"
SCOPE = "sha256:" + "a" * 64
NOW = datetime(2026, 7, 14, 8, 0, tzinfo=UTC)
BASE = "http://localhost:8080/"
IDENTITIES = {"member": "sha256:" + "b" * 64, "fixture-admin": "sha256:" + "c" * 64}


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _evidence(number: int) -> EvidenceArtifactRef:
    character = format(number % 16, "x")
    return EvidenceArtifactRef(
        evidence_id=f"evidence-{number}",
        manifest_path=f"evidence/evidence-{number}/manifest.json",
        manifest_sha256=_digest(character),
    )


def _branch_results(*, api_status: str = "succeeded") -> tuple[BranchResult, ...]:
    results: list[BranchResult] = []
    for index, branch in enumerate(("web", "api", "authz", "infra"), start=1):
        status = api_status if branch == "api" else "succeeded"
        results.append(
            BranchResult(
                run_id=RUN,
                scope_digest=SCOPE,
                generated_by_task_id=f"assessment-{branch}",
                branch=branch,
                status=status,
                assessment_digest=_digest(str(index)) if status == "succeeded" else None,
                provider_metadata_digest=_digest(format(index + 9, "x")),
                started_at=NOW,
                finished_at=NOW + timedelta(seconds=1),
                reason=None if status == "succeeded" else "isolated provider failure",
            )
        )
    return tuple(results)  # type: ignore[return-value]


def _raw_candidates(*, include_api: bool = True) -> tuple[BranchCandidateV3, ...]:
    specifications = [
        (
            "web-xcto",
            "missing_x_content_type_options",
            "web",
            "/candidate",
            "GET",
            None,
            None,
            _digest("1"),
        ),
        (
            "authz-escalation",
            "privilege_escalation",
            "authz",
            "/authz/elevate",
            "POST",
            materialized_body_digest("privilege_escalation", "candidate"),
            IDENTITIES["member"],
            _digest("3"),
        ),
        (
            "infra-debug",
            "exposed_debug_endpoint",
            "infra",
            "/debug",
            "GET",
            None,
            None,
            _digest("4"),
        ),
        (
            "infra-xcto-copy",
            "missing_x_content_type_options",
            "infra",
            "/candidate",
            "GET",
            None,
            None,
            _digest("1"),
        ),
    ]
    if include_api:
        specifications.insert(
            1,
            (
                "api-graphql",
                "unauthorized_graphql_mutation",
                "api",
                "/graphql/mutate",
                "POST",
                materialized_body_digest("unauthorized_graphql_mutation", "candidate"),
                IDENTITIES["member"],
                _digest("2"),
            ),
        )
    return tuple(
        BranchCandidateV3(
            candidate_id=candidate_id,
            candidate_type=candidate_type,
            producer_branch=branch,
            target_endpoint_id=f"endpoint-{candidate_id}",
            control_endpoint_ids=(f"control-{candidate_id}",),
            target_url=f"http://localhost:8080{path}",
            method=method,
            request_body_sha256=body,
            identity_binding_digest=identity,
            expected_assertion="fixed Phase 4 fixture assertion",
            rationale="bounded local teaching fixture candidate",
            semantic_fingerprint=fingerprint,
        )
        for (
            candidate_id,
            candidate_type,
            branch,
            path,
            method,
            body,
            identity,
            fingerprint,
        ) in specifications
    )


def _collection(
    results: tuple[BranchResult, ...], *, include_api: bool = True
) -> CandidateCollection:
    raw = _raw_candidates(include_api=include_api)
    groups = (
        (
            "web-xcto",
            "missing_x_content_type_options",
            _digest("1"),
            ("web", "infra"),
            ("web-xcto", "infra-xcto-copy"),
        ),
        *(
            (
                (
                    "api-graphql",
                    "unauthorized_graphql_mutation",
                    _digest("2"),
                    ("api",),
                    ("api-graphql",),
                ),
            )
            if include_api
            else ()
        ),
        (
            "authz-escalation",
            "privilege_escalation",
            _digest("3"),
            ("authz",),
            ("authz-escalation",),
        ),
        ("infra-debug", "exposed_debug_endpoint", _digest("4"), ("infra",), ("infra-debug",)),
    )
    canonical = tuple(
        CanonicalCandidateV3(
            candidate_id=candidate_id,
            candidate_type=candidate_type,
            semantic_fingerprint=fingerprint,
            provenance=provenance,
            source_candidate_ids=sources,
        )
        for candidate_id, candidate_type, fingerprint, provenance, sources in groups
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
        run_id=RUN,
        scope_digest=SCOPE,
        generated_by_task_id="fan-in",
        collection_id="phase4-candidates",
        route_decision_digest=_digest("9"),
        branch_result_digests=tuple(item.digest for item in results),
        raw_candidates=raw,
        canonical_candidates=canonical,
        dedup_decisions=decisions,
    )


def _reviews(
    collection: CandidateCollection, verdicts: dict[str, str] | None = None
) -> CrossReviewSet:
    verdicts = verdicts or {}
    reviewer_by_candidate = {
        "web-xcto": "api",
        "api-graphql": "authz",
        "authz-escalation": "infra",
        "infra-debug": "web",
    }
    return CrossReviewSet(
        run_id=RUN,
        scope_digest=SCOPE,
        generated_by_task_id="cross-review-coordinator",
        review_set_id="phase4-cross-reviews",
        candidate_collection_digest=collection.digest,
        reviews=tuple(
            CrossReview(
                review_id=f"review-{item.candidate_id}",
                candidate_id=item.candidate_id,
                producer_branches=item.provenance,
                reviewer_branch=reviewer_by_candidate[item.candidate_id],
                reviewer_task_id=f"review-task-{item.candidate_id}",
                verdict=verdicts.get(item.candidate_id, "concur"),
                rationale="independent expert review",
            )
            for item in collection.canonical_candidates
        ),
    )


def _outcomes_and_findings(
    collection: CandidateCollection,
    reviews: CrossReviewSet,
    campaign_digest: str,
    *,
    selected_candidate_ids: set[str] | None = None,
) -> tuple[VerificationOutcomeSet, FindingSet]:
    outcomes_list: list[VerificationCandidateOutcome] = []
    findings_list: list[FindingV3] = []
    type_by_id = {
        item.candidate_id: item.candidate_type for item in collection.canonical_candidates
    }
    selected = set(type_by_id) if selected_candidate_ids is None else selected_candidate_ids
    for index, candidate_id in enumerate(type_by_id, start=1):
        if candidate_id not in selected:
            continue
        evidence = (_evidence(index),)
        outcome = VerificationCandidateOutcome(
            outcome_id=f"outcome-{candidate_id}",
            candidate_id=candidate_id,
            verifier_task_id=f"verifier-{candidate_id}",
            status="validated",
            action_digests=(_digest(format(index, "x")),),
            action_ledger_entry_digests=(_digest(format(index + 4, "x")),),
            evidence=evidence,
            assertion_summary="fixture differential assertion validated",
        )
        outcomes_list.append(outcome)
        review = next(item for item in reviews.reviews if item.candidate_id == candidate_id)
        findings_list.append(
            FindingV3(
                finding_id=candidate_id,
                candidate_id=candidate_id,
                candidate_type=type_by_id[candidate_id],
                verification_outcome_digest=outcome.digest,
                cross_review_digest=review.digest,
                evidence=evidence,
                title=f"Fixture finding {candidate_id}",
                summary="Validated only in the local Phase 4 teaching fixture.",
                severity="informational",
            )
        )
    outcomes = VerificationOutcomeSet(
        run_id=RUN,
        scope_digest=SCOPE,
        generated_by_task_id="outcome-coordinator",
        outcome_set_id="phase4-outcomes",
        campaign_digest=campaign_digest,
        approval_batch_digests=(_digest("e"),),
        outcomes=tuple(outcomes_list),
    )
    findings = FindingSet(
        run_id=RUN,
        scope_digest=SCOPE,
        generated_by_task_id="promotion",
        finding_set_id="phase4-findings",
        candidate_collection_digest=collection.digest,
        cross_review_set_digest=reviews.digest,
        verification_outcome_set_digest=outcomes.digest,
        cleanup_receipt_digest=(
            _digest("f")
            if any(
                candidate_id in selected
                and candidate_type in {"unauthorized_graphql_mutation", "privilege_escalation"}
                for candidate_id, candidate_type in type_by_id.items()
            )
            else None
        ),
        findings=tuple(findings_list),
    )
    return outcomes, findings


def test_full_campaign_is_deterministic_and_has_exact_risk_batches() -> None:
    results = _branch_results()
    collection = _collection(results)
    reviews = _reviews(collection)
    campaign = build_verification_campaign(
        collection,
        reviews,
        endpoint_base=BASE,
        identity_binding_digests=IDENTITIES,
        generated_by_task_id="campaign-planner",
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
    )
    repeated = build_verification_campaign(
        collection,
        reviews,
        endpoint_base=BASE,
        identity_binding_digests=IDENTITIES,
        generated_by_task_id="campaign-planner",
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
    )

    assert campaign.digest == repeated.digest
    assert campaign.request_budget == 14
    assert [item.candidate_id for item in campaign.actions] == (
        ["web-xcto"] * 2 + ["infra-debug"] * 2 + ["api-graphql"] * 5 + ["authz-escalation"] * 5
    )
    assert sum(item.risk_group == "readonly" for item in campaign.actions) == 4
    assert sum(item.risk_group == "mutation" for item in campaign.actions) == 10
    for candidate_id in ("api-graphql", "authz-escalation"):
        actions = {
            item.purpose: item for item in campaign.actions if item.candidate_id == candidate_id
        }
        assert actions["cleanup"].depends_on == (actions["candidate"].action_id,)
        assert actions["cleanup"].cleanup_of == actions["candidate"].action_id
        assert actions["cleanup_check"].depends_on == (actions["cleanup"].action_id,)


def test_web_infra_dynamic_subset_has_exact_five_request_campaign() -> None:
    results = _branch_results()
    full = _collection(results)
    selected = {"web-xcto", "infra-debug"}
    subset = full.model_copy(
        update={
            "raw_candidates": tuple(
                item for item in full.raw_candidates if item.producer_branch in {"web", "infra"}
            ),
            "canonical_candidates": tuple(
                item for item in full.canonical_candidates if item.candidate_id in selected
            ),
            "dedup_decisions": tuple(
                item for item in full.dedup_decisions if item.canonical_candidate_id in selected
            ),
        }
    )
    reviews = _reviews(subset)
    campaign = build_verification_campaign(
        subset,
        reviews,
        endpoint_base=BASE,
        identity_binding_digests={},
        generated_by_task_id="campaign-planner",
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
    )

    assert campaign.request_budget == 4
    assert {item.candidate_id for item in campaign.actions} == selected
    assert all(item.risk_group == "readonly" for item in campaign.actions)
    assert campaign.request_budget + 1 == 5


def test_rejected_review_is_blocked_before_campaign_and_identity_changes_digest() -> None:
    results = _branch_results()
    collection = _collection(results)
    reviews = _reviews(collection, {"api-graphql": "reject"})
    campaign = build_verification_campaign(
        collection,
        reviews,
        endpoint_base=BASE,
        identity_binding_digests=IDENTITIES,
        generated_by_task_id="campaign-planner",
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
    )
    assert campaign.request_budget == 9
    assert "api-graphql" not in {item.candidate_id for item in campaign.actions}

    all_concur = _reviews(collection)
    changed = build_verification_campaign(
        collection,
        all_concur,
        endpoint_base=BASE,
        identity_binding_digests={**IDENTITIES, "member": _digest("d")},
        generated_by_task_id="campaign-planner",
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
    )
    original = build_verification_campaign(
        collection,
        all_concur,
        endpoint_base=BASE,
        identity_binding_digests=IDENTITIES,
        generated_by_task_id="campaign-planner",
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
    )
    original_forward = next(
        item for item in original.actions if item.action_id == "verify-api-graphql-candidate"
    )
    changed_forward = next(
        item for item in changed.actions if item.action_id == "verify-api-graphql-candidate"
    )
    assert original_forward.action_digest != changed_forward.action_digest


def test_campaign_requires_exact_reviews_and_same_fixture_origin() -> None:
    results = _branch_results()
    collection = _collection(results)
    reviews = _reviews(collection)
    incomplete = reviews.model_copy(update={"reviews": reviews.reviews[:-1]})
    with pytest.raises(CampaignV3Error, match="every canonical candidate"):
        build_verification_campaign(
            collection,
            incomplete,
            endpoint_base=BASE,
            identity_binding_digests=IDENTITIES,
            generated_by_task_id="campaign-planner",
            created_at=NOW,
            expires_at=NOW + timedelta(minutes=10),
        )
    with pytest.raises(CampaignV3Error, match="fixture origin"):
        build_verification_campaign(
            collection,
            reviews,
            endpoint_base="http://localhost:9090/",
            identity_binding_digests=IDENTITIES,
            generated_by_task_id="campaign-planner",
            created_at=NOW,
            expires_at=NOW + timedelta(minutes=10),
        )


def test_action_ledger_summary_is_conservative_and_rejects_orphans() -> None:
    results = _branch_results()
    collection = _collection(results)
    reviews = _reviews(collection)
    campaign = build_verification_campaign(
        collection,
        reviews,
        endpoint_base=BASE,
        identity_binding_digests=IDENTITIES,
        generated_by_task_id="campaign-planner",
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
    )
    first, second = campaign.actions[:2]
    entries = (
        ActionLedgerEntry(
            run_id=RUN,
            scope_digest=SCOPE,
            generated_by_task_id="verifier-web",
            ledger_entry_id="entry-1",
            sequence=1,
            action_id=first.action_id,
            action_digest=first.action_digest,
            action_fingerprint=_digest("1"),
            candidate_consumers=first.candidate_consumers,
            state="evidence_committed",
            evidence=_evidence(10),
            occurred_at=NOW,
        ),
        ActionLedgerEntry(
            run_id=RUN,
            scope_digest=SCOPE,
            generated_by_task_id="verifier-web",
            ledger_entry_id="entry-2",
            sequence=2,
            previous_entry_digest=_digest("2"),
            action_id=second.action_id,
            action_digest=second.action_digest,
            action_fingerprint=_digest("2"),
            candidate_consumers=second.candidate_consumers,
            state="failed_after_transport",
            occurred_at=NOW,
        ),
    )
    summary = summarize_action_ledger(campaign, entries)
    assert (
        summary.actions_executed,
        summary.actions_blocked,
        summary.actions_skipped,
    ) == (1, 1, 12)
    assert summary.requests_used == 2
    assert "action:verify-web-xcto-negative-control:failed_after_transport" in summary.gaps

    orphan = entries[0].model_copy(update={"action_id": "outside-campaign"})
    with pytest.raises(CampaignV3Error, match="outside the campaign"):
        summarize_action_ledger(campaign, (orphan,))


def test_coverage_full_and_api_failure_gap_are_derived() -> None:
    full_results = _branch_results()
    full_collection = _collection(full_results)
    full_reviews = _reviews(full_collection)
    full_campaign = build_verification_campaign(
        full_collection,
        full_reviews,
        endpoint_base=BASE,
        identity_binding_digests=IDENTITIES,
        generated_by_task_id="campaign-planner",
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
    )
    full_outcomes, full_findings = _outcomes_and_findings(
        full_collection, full_reviews, full_campaign.digest
    )
    full = build_coverage_report(
        collection=full_collection,
        reviews=full_reviews,
        campaign=full_campaign,
        branch_results=full_results,
        outcomes=full_outcomes,
        findings=full_findings,
        action_ledger=ActionLedgerSummary(14, 14, 0, 0, 14),
        budget=BudgetCoverageSummary(16, 16, 4_000_000),
        active_elapsed_ms=1_000,
        generated_by_task_id="coverage-builder",
    )
    assert full.completion == "completed"
    assert (full.requests_planned, full.requests_used) == (15, 15)
    assert (full.raw_candidates, full.canonical_candidates, full.duplicate_candidates) == (5, 4, 1)

    failed_results = _branch_results(api_status="failed")
    partial_collection = _collection(failed_results, include_api=False)
    partial_reviews = _reviews(partial_collection)
    partial_campaign = build_verification_campaign(
        partial_collection,
        partial_reviews,
        endpoint_base=BASE,
        identity_binding_digests=IDENTITIES,
        generated_by_task_id="campaign-planner",
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
    )
    partial_outcomes, partial_findings = _outcomes_and_findings(
        partial_collection, partial_reviews, partial_campaign.digest
    )
    partial = build_coverage_report(
        collection=partial_collection,
        reviews=partial_reviews,
        campaign=partial_campaign,
        branch_results=failed_results,
        outcomes=partial_outcomes,
        findings=partial_findings,
        action_ledger=ActionLedgerSummary(9, 9, 0, 0, 9),
        budget=BudgetCoverageSummary(14, 14, 3_500_000),
        active_elapsed_ms=1_000,
        generated_by_task_id="coverage-builder",
    )
    assert partial.completion == "completed_with_gaps"
    assert (partial.requests_planned, partial.requests_used) == (10, 10)
    assert partial.candidates_validated == 3
    assert "branch:api:failed:isolated provider failure" in partial.gaps


@pytest.mark.parametrize(
    ("rejected_group", "selected_candidates", "executed", "skipped", "requests"),
    (
        (
            "mutation",
            {"web-xcto", "infra-debug"},
            4,
            10,
            5,
        ),
        (
            "readonly",
            {"api-graphql", "authz-escalation"},
            10,
            4,
            11,
        ),
    ),
)
def test_rejected_risk_group_keeps_only_other_group_with_exact_request_budget(
    rejected_group: str,
    selected_candidates: set[str],
    executed: int,
    skipped: int,
    requests: int,
) -> None:
    """A partial approval cannot silently count rejected actions as tested."""

    results = _branch_results()
    collection = _collection(results)
    reviews = _reviews(collection)
    campaign = build_verification_campaign(
        collection,
        reviews,
        endpoint_base=BASE,
        identity_binding_digests=IDENTITIES,
        generated_by_task_id="campaign-planner",
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
    )
    outcomes, findings = _outcomes_and_findings(
        collection,
        reviews,
        campaign.digest,
        selected_candidate_ids=selected_candidates,
    )
    coverage = build_coverage_report(
        collection=collection,
        reviews=reviews,
        campaign=campaign,
        branch_results=results,
        outcomes=outcomes,
        findings=findings,
        action_ledger=ActionLedgerSummary(
            actions_planned=14,
            actions_executed=executed,
            actions_blocked=0,
            actions_skipped=skipped,
            requests_used=executed,
            gaps=(f"approval:{rejected_group}:rejected",),
        ),
        budget=BudgetCoverageSummary(14, 14, 3_500_000),
        active_elapsed_ms=1_000,
        generated_by_task_id="coverage-builder",
        cleanup_receipt_digest=findings.cleanup_receipt_digest,
    )

    assert coverage.completion == "completed_with_gaps"
    assert coverage.requests_used == requests
    assert coverage.actions_executed == executed
    assert coverage.actions_skipped == skipped
    assert coverage.candidates_validated == 2
    assert len(findings.findings) == 2
    assert f"approval:{rejected_group}:rejected" in coverage.gaps


def test_coverage_rejects_branch_or_finding_digest_discontinuity() -> None:
    results = _branch_results()
    collection = _collection(results)
    reviews = _reviews(collection)
    campaign = build_verification_campaign(
        collection,
        reviews,
        endpoint_base=BASE,
        identity_binding_digests=IDENTITIES,
        generated_by_task_id="campaign-planner",
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
    )
    outcomes, findings = _outcomes_and_findings(collection, reviews, campaign.digest)
    with pytest.raises(CampaignV3Error, match="canonical order"):
        build_coverage_report(
            collection=collection,
            reviews=reviews,
            campaign=campaign,
            branch_results=tuple(reversed(results)),
            outcomes=outcomes,
            findings=findings,
            action_ledger=ActionLedgerSummary(14, 14, 0, 0, 14),
            budget=BudgetCoverageSummary(16, 16, 4_000_000),
            active_elapsed_ms=1_000,
            generated_by_task_id="coverage-builder",
        )
    tampered = findings.model_copy(update={"cross_review_set_digest": _digest("0")})
    with pytest.raises(CampaignV3Error, match="finding digest chain"):
        build_coverage_report(
            collection=collection,
            reviews=reviews,
            campaign=campaign,
            branch_results=results,
            outcomes=outcomes,
            findings=tampered,
            action_ledger=ActionLedgerSummary(14, 14, 0, 0, 14),
            budget=BudgetCoverageSummary(16, 16, 4_000_000),
            active_elapsed_ms=1_000,
            generated_by_task_id="coverage-builder",
        )
