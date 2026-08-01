from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes.cli_v3 import (
    V3ManagementError,
    create_cleanup_challenge_v3,
    emit_v3_payload,
    load_v3_state,
    sign_decision_v3,
    sign_review_v3,
)
from hermes.domain_contracts_v3 import (
    CoverageReportV3,
    FindingSet,
    RunPlanV3,
    VerificationActionV3,
    VerificationCampaignPlan,
)
from hermes.runtime import RunContext
from hermes.security import (
    KeyUsage,
    TrustedKey,
    TrustStoreV2,
    encode_base64,
    generate_ed25519_private_key,
    public_key_bytes,
)
from hermes.security_v3 import approval_actions_v3, verify_approval_batch_v3
from hermes.vertical_v3 import (
    ROLE_ORDER_V3,
    ExecutionStateV3,
    NetworkStateV3,
    VerticalStateV3,
)


def digest(character: str) -> str:
    return "sha256:" + character * 64


def trust(
    private: Ed25519PrivateKey,
    key_id: str,
    usage: KeyUsage,
    now: datetime,
) -> TrustStoreV2:
    return TrustStoreV2(
        keys=(
            TrustedKey(
                key_id=key_id,
                public_key=encode_base64(public_key_bytes(private)),
                usages=frozenset({usage}),
                valid_from=now - timedelta(hours=1),
                valid_until=now + timedelta(hours=1),
            ),
        )
    )


def make_run(tmp_path: Path, state: ExecutionStateV3) -> tuple[RunContext, datetime]:
    now = datetime.now(UTC)
    context = RunContext(tmp_path / "runs", {"fixture": "phase4"}, run_id="run-v3")
    plan = RunPlanV3(
        run_id=context.run_id,
        target="http://localhost:8080/candidate",
        scope_digest=context.scope_digest,
        provider_id="restricted-acp",
        model_id="fixture-model",
        prompt_registry_digest=digest("1"),
        role_manifest_set_digest=digest("2"),
        roles=ROLE_ORDER_V3,
        created_at=now,
    )
    context.write_json("plan/run-v3.json", plan.model_dump(mode="json"), immutable=True)
    write_state(context, state)
    return context, now


def write_state(context: RunContext, state: ExecutionStateV3) -> None:
    context.write_json(
        "state.json",
        VerticalStateV3(
            run_id=context.run_id,
            execution_state=state,
            network_state=NetworkStateV3.USED,
            requests_planned=5,
            requests_used=1,
            requests_blocked=0,
        ).model_dump(mode="json"),
    )


def action(
    context: RunContext,
    candidate_id: str,
    suffix: str,
    purpose: Literal["candidate", "negative_control"],
) -> VerificationActionV3:
    return VerificationActionV3(
        action_id=f"{candidate_id}-{suffix}",
        candidate_id=candidate_id,
        candidate_consumers=(candidate_id,),
        purpose=purpose,
        risk_group="readonly",
        action_kind="validation_http_get",
        method="GET",
        target_url=f"http://localhost:8080/{candidate_id}/{suffix}",
        action_digest=digest(suffix),
    )


def make_campaign(context: RunContext, now: datetime) -> VerificationCampaignPlan:
    result = VerificationCampaignPlan(
        run_id=context.run_id,
        scope_digest=context.scope_digest,
        generated_by_task_id="campaign-planner",
        campaign_id="phase4-campaign",
        candidate_collection_digest=digest("3"),
        cross_review_set_digest=digest("4"),
        actions=(
            action(context, "web-xcto", "a", "candidate"),
            action(context, "web-xcto", "b", "negative_control"),
            action(context, "infra-debug", "c", "candidate"),
            action(context, "infra-debug", "d", "negative_control"),
        ),
        request_budget=4,
        created_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(minutes=15),
    )
    context.write_json(
        "verification_v3/campaign.json", result.model_dump(mode="json"), immutable=True
    )
    context.write_json(
        "approvals_v3/challenge-readonly.json",
        {
            "version": "3",
            "challenge_id": "phase4-readonly",
            "run_id": context.run_id,
            "scope_digest": context.scope_digest,
            "campaign_digest": result.digest,
            "risk_group": "readonly",
            "candidate_ids": ["infra-debug", "web-xcto"],
            "action_digests": [item.action_digest for item in result.actions],
            "expires_at": result.expires_at.isoformat(),
        },
        immutable=True,
    )
    return result


@pytest.mark.parametrize(
    ("selected", "expected_actions"),
    [
        (("web-xcto", "infra-debug"), 4),
        (("web-xcto",), 2),
    ],
)
def test_sign_decision_binds_full_or_selected_candidate_graph(
    tmp_path: Path, selected: tuple[str, ...], expected_actions: int
) -> None:
    context, now = make_run(tmp_path, ExecutionStateV3.AWAITING_READONLY_APPROVAL)
    campaign = make_campaign(context, now)
    private = generate_ed25519_private_key()
    store = trust(private, "approver", KeyUsage.APPROVAL, now)

    signed = sign_decision_v3(
        context,
        campaign,
        "readonly",
        selected,
        "approved",
        private,
        store,
        "operator-v3",
        "Approve the complete selected candidate graph.",
        signed_at=now,
    )

    assert signed.candidate_ids == tuple(sorted(selected))
    assert len(signed.action_digests) == expected_actions
    assert context.artifact_path("approvals_v3/readonly.json").is_file()
    assert not context.artifact_path("approvals_v3/consumptions").exists()
    with pytest.raises(V3ManagementError, match="immutable"):
        sign_decision_v3(
            context,
            campaign,
            "readonly",
            selected,
            "approved",
            private,
            store,
            "operator-v3",
            "A second decision must not overwrite the first.",
            signed_at=now,
        )


def test_rejection_creates_no_consumption_and_tampered_challenge_is_refused(
    tmp_path: Path,
) -> None:
    context, now = make_run(tmp_path, ExecutionStateV3.AWAITING_READONLY_APPROVAL)
    campaign = make_campaign(context, now)
    private = generate_ed25519_private_key()
    store = trust(private, "approver", KeyUsage.APPROVAL, now)
    challenge = context.artifact_path("approvals_v3/challenge-readonly.json")
    original = challenge.read_text(encoding="utf-8")
    value = original.replace("phase4-readonly", "altered")
    challenge.write_text(value, encoding="utf-8")

    with pytest.raises(V3ManagementError, match="altered"):
        sign_decision_v3(
            context,
            campaign,
            "readonly",
            ("web-xcto",),
            "rejected",
            private,
            store,
            "operator-v3",
            "Reject this candidate graph.",
            signed_at=now,
        )
    assert not context.artifact_path("approvals_v3/readonly.json").exists()
    assert not context.artifact_path("approvals_v3/consumptions").exists()

    challenge.write_text(original, encoding="utf-8")
    signed = sign_decision_v3(
        context,
        campaign,
        "readonly",
        ("web-xcto",),
        "rejected",
        private,
        store,
        "operator-v3",
        "Reject this complete candidate graph.",
        signed_at=now,
    )
    assert signed.verdict == "rejected"
    assert context.artifact_path("approvals_v3/readonly.json").is_file()
    assert not context.artifact_path("approvals_v3/consumptions").exists()


def test_cleanup_only_decision_excludes_forward_and_survives_expired_campaign(
    tmp_path: Path,
) -> None:
    context, now = make_run(tmp_path, ExecutionStateV3.CLEANUP_REQUIRED)
    identity = digest("9")
    forward = VerificationActionV3(
        action_id="api-forward",
        candidate_id="api-graphql",
        candidate_consumers=("api-graphql",),
        purpose="candidate",
        risk_group="mutation",
        action_kind="validation_http_request",
        method="POST",
        target_url="http://localhost:8080/graphql/mutate",
        body_sha256=digest("a"),
        identity_binding_digest=identity,
        action_digest=digest("1"),
    )
    cleanup = VerificationActionV3(
        action_id="api-cleanup",
        candidate_id="api-graphql",
        candidate_consumers=("api-graphql",),
        purpose="cleanup",
        risk_group="mutation",
        action_kind="validation_http_request",
        method="POST",
        target_url="http://localhost:8080/graphql/cleanup",
        body_sha256=digest("b"),
        identity_binding_digest=identity,
        action_digest=digest("2"),
        depends_on=(forward.action_id,),
        cleanup_of=forward.action_id,
    )
    check = VerificationActionV3(
        action_id="api-cleanup-check",
        candidate_id="api-graphql",
        candidate_consumers=("api-graphql",),
        purpose="cleanup_check",
        risk_group="mutation",
        action_kind="validation_http_get",
        method="GET",
        target_url="http://localhost:8080/graphql",
        identity_binding_digest=identity,
        action_digest=digest("3"),
        depends_on=(cleanup.action_id,),
    )
    campaign = VerificationCampaignPlan(
        run_id=context.run_id,
        scope_digest=context.scope_digest,
        generated_by_task_id="campaign-planner",
        campaign_id="expired-campaign",
        candidate_collection_digest=digest("4"),
        cross_review_set_digest=digest("5"),
        actions=(forward, cleanup, check),
        request_budget=3,
        created_at=now - timedelta(minutes=20),
        expires_at=now - timedelta(minutes=5),
    )
    context.write_json(
        "verification_v3/campaign.json", campaign.model_dump(mode="json"), immutable=True
    )
    challenge = create_cleanup_challenge_v3(context, campaign, issued_at=now)
    assert challenge["action_digests"] == [cleanup.action_digest, check.action_digest]
    assert forward.action_digest not in challenge["action_digests"]
    assert approval_actions_v3(campaign, "cleanup") == (cleanup, check)

    private = generate_ed25519_private_key()
    store = trust(private, "approver", KeyUsage.APPROVAL, now)
    signed = sign_decision_v3(
        context,
        campaign,
        "cleanup",
        ("api-graphql",),
        "approved",
        private,
        store,
        "cleanup-operator",
        "Authorize only the predeclared compensation graph.",
        signed_at=now,
    )
    assert signed.risk_group == "cleanup"
    assert signed.action_digests == tuple(sorted((cleanup.action_digest, check.action_digest)))
    verify_approval_batch_v3(signed, campaign, store, at=now)


def finding_and_coverage(
    context: RunContext, campaign: VerificationCampaignPlan
) -> tuple[FindingSet, CoverageReportV3]:
    findings = FindingSet(
        run_id=context.run_id,
        scope_digest=context.scope_digest,
        generated_by_task_id="promotion-v3",
        finding_set_id="findings-v3",
        candidate_collection_digest=campaign.candidate_collection_digest,
        cross_review_set_digest=campaign.cross_review_set_digest,
        verification_outcome_set_digest=digest("5"),
        findings=(),
    )
    coverage = CoverageReportV3(
        run_id=context.run_id,
        scope_digest=context.scope_digest,
        generated_by_task_id="coverage-v3",
        report_id="coverage-v3",
        route_decision_digest=digest("6"),
        candidate_collection_digest=campaign.candidate_collection_digest,
        cross_review_set_digest=campaign.cross_review_set_digest,
        campaign_digest=campaign.digest,
        outcome_set_digest=digest("5"),
        finding_set_digest=findings.digest,
        branches_routed=2,
        branches_succeeded=1,
        branches_failed=1,
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
        model_attempts_reserved=16,
        model_attempts_used=16,
        estimated_cost_microusd=4_000_000,
        active_elapsed_ms=100,
        completion="completed_with_gaps",
        gaps=("api assessment failed",),
    )
    context.write_json(
        "report/finding-set-v3.json", findings.model_dump(mode="json"), immutable=True
    )
    context.write_json("report/coverage-v3.json", coverage.model_dump(mode="json"), immutable=True)
    context.write_text("report/draft-v3.md", "# Phase 4 bounded draft\n", immutable=True)
    return findings, coverage


def test_sign_review_requires_exact_gap_verdict_and_distinct_key(tmp_path: Path) -> None:
    context, now = make_run(tmp_path, ExecutionStateV3.AWAITING_READONLY_APPROVAL)
    campaign = make_campaign(context, now)
    approver = generate_ed25519_private_key()
    approval_store = trust(approver, "approver", KeyUsage.APPROVAL, now)
    sign_decision_v3(
        context,
        campaign,
        "readonly",
        ("web-xcto",),
        "approved",
        approver,
        approval_store,
        "operator-v3",
        "Approve the complete Web graph.",
        signed_at=now,
    )
    finding_and_coverage(context, campaign)
    write_state(context, ExecutionStateV3.AWAITING_REVIEW)
    reviewer = generate_ed25519_private_key()
    review_store = trust(reviewer, "reviewer", KeyUsage.HUMAN_REVIEW, now)

    with pytest.raises(V3ManagementError, match="requires review verdict"):
        sign_review_v3(
            context,
            "accepted",
            reviewer,
            review_store,
            "Reviewed every preserved coverage gap.",
            approval_store=approval_store,
            reviewed_at=now,
        )

    signed = sign_review_v3(
        context,
        "accepted_with_gaps",
        reviewer,
        review_store,
        "Reviewed every preserved coverage gap.",
        approval_store=approval_store,
        reviewed_at=now,
    )
    assert signed.gap_digests
    assert context.artifact_path("reviews/signed-v3.json").is_file()


def test_load_state_and_management_reject_v2_run(tmp_path: Path) -> None:
    context = RunContext(tmp_path / "runs", {"fixture": "phase2"}, run_id="run-v2")
    context.write_json("plan/run-plan.json", {"version": "2"}, immutable=True)

    with pytest.raises(V3ManagementError, match="Phase 4 V3"):
        load_v3_state(context)
    with pytest.raises(V3ManagementError, match="Phase 4 V3"):
        sign_review_v3(
            context,
            "rejected",
            generate_ed25519_private_key(),
            TrustStoreV2(
                keys=(
                    TrustedKey(
                        key_id="placeholder",
                        public_key=encode_base64(b"x" * 32),
                        usages=frozenset({KeyUsage.HUMAN_REVIEW}),
                        valid_from=datetime.now(UTC) - timedelta(minutes=1),
                    ),
                )
            ),
            "V2 must never enter the V3 review path.",
        )


def test_emit_payload_is_machine_readable(tmp_path: Path) -> None:
    context, _ = make_run(tmp_path, ExecutionStateV3.AWAITING_READONLY_APPROVAL)
    state = load_v3_state(context)
    assert emit_v3_payload(state)["execution_state"] == "awaiting_readonly_approval"
    assert emit_v3_payload(state)["run_id"] == context.run_id
